import os
import time
from datetime import datetime

import pytest

from peat import Elastic, config
from peat.es_mappings import PEAT_INDICES


def test_init():
    assert Elastic()


def test_ecs_version():
    assert Elastic.ECS_VERSION == "9.5.0"


@pytest.mark.parametrize(
    ("index", "mapping_name"),
    [
        ("ot-device-relationships-2026.10.30", "ot-device-relationships"),
        ("ot-device-relationships", "ot-device-relationships"),
        ("ot-device-baseline-findings-2026.10.30", "ot-device-baseline-findings"),
        ("ot-device-hosts-timeseries-2026.10.30", "ot-device-hosts-timeseries"),
        ("uefi-hashes-2026.10.30", "uefi-hashes"),
    ],
)
def test_create_index_uses_peat_mappings(mocker, index, mapping_name):
    mocker.patch.dict(config["CONFIG"], {"ELASTIC_DIR": None})
    es = Elastic()
    client = mocker.MagicMock()
    client.indices.exists.return_value = False
    es.es = client

    assert es.create_index(index)
    body = client.indices.create.call_args.kwargs["body"]
    assert body["mappings"] is PEAT_INDICES[mapping_name]
    assert body["settings"]["index.mapping.total_fields.limit"] == 20000


def test_create_index_custom_index_names(mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "ELASTIC_DIR": None,
            "ELASTIC_RELATIONSHIPS_INDEX": "custom-relationships",
            "ELASTIC_BASELINE_FINDINGS_INDEX": "custom-findings",
        },
    )
    for index, mapping_name in (
        ("custom-relationships-2026.10.30", "ot-device-relationships"),
        ("custom-findings-2026.10.30", "ot-device-baseline-findings"),
    ):
        es = Elastic()
        client = mocker.MagicMock()
        client.indices.exists.return_value = False
        es.es = client
        assert es.create_index(index)
        body = client.indices.create.call_args.kwargs["body"]
        assert body["mappings"] is PEAT_INDICES[mapping_name]


@pytest.mark.parametrize("disabled", ["ELASTIC_RELATIONSHIPS_INDEX", "ELASTIC_EVENTS_INDEX"])
def test_push_elastic_dir_ignores_disabled_index_names(mocker, tmp_path, disabled):
    """An empty (disabled) index name must not stop ELASTIC_DIR saving."""
    mocker.patch.dict(
        config["CONFIG"],
        {"ELASTIC_DIR": tmp_path, disabled: "", "ELASTIC_DISABLE_DATED_INDICES": True},
    )
    es = Elastic()
    es.es = mocker.MagicMock()
    mocker.patch.object(es, "create_index", return_value=True)

    assert es.push("peat-scan-summaries", {"a": 1}, doc_id="x")
    assert list(es._docs_written) == ["peat-scan-summaries"]
    assert es.push(config.ELASTIC_LOG_INDEX, {"a": 1}, doc_id="y")
    assert config.ELASTIC_LOG_INDEX not in es._docs_written
    # high volume relationship documents are also not kept (they are in JSONL files)
    if config.ELASTIC_RELATIONSHIPS_INDEX:
        assert es.push(config.ELASTIC_RELATIONSHIPS_INDEX, {"a": 1}, doc_id="z")
    assert list(es._docs_written) == ["peat-scan-summaries"]


def test_url():
    unsafe_url = "http://elastic:changeme@localhost:9200"
    safe_url = "http://localhost:9200/"
    es = Elastic(unsafe_url)
    assert es.unsafe_url == f"{unsafe_url}/"
    assert es.safe_url == safe_url
    assert es.host == "localhost:9200"
    assert Elastic(safe_url).safe_url == safe_url


def test_bencode():
    assert Elastic.bencode(b"") == ""
    assert Elastic.bencode(b"1234") == "MTIzNA=="


def test_convert_tstamp():
    exp = "2019-02-25T17:39:11.507Z"
    assert Elastic.convert_tstamp(datetime(2019, 2, 25, 17, 39, 11, 507318)) == exp
    assert Elastic.convert_tstamp("2019-02-25T17:39:11.507318") == exp


def test_gen_id(mocker):
    mocker.patch("peat.consts.RUN_ID", "123456789")
    assert "123456789" in Elastic.gen_id()
    assert "peat" in Elastic.gen_id()


def test_str():
    assert str(Elastic()) == Elastic().host


def test_repr():
    assert isinstance(eval(repr(Elastic())), Elastic)


@pytest.mark.gitlab_ci_only
def test_elastic_live_ci(mocker, tmp_path):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "DEBUG": 1,
            "ELASTIC_DIR": tmp_path,
            "LOG_DIR": tmp_path,
        },
    )

    es = Elastic(os.environ["ES_URL"])

    assert es.ping()
    assert es.info()

    assert not es.index_exists("test-index-that-does-not-exist")
    assert not es.doc_exists("test-index-that-does-not-exist", "test_doc_id")
    assert es.push(
        index="alerts",
        content={"action": "threshold-exceeded"},
        doc_id="test_doc_id",
        no_date=True,
    )
    time.sleep(2)  # the search will fail if query happens too soon after push
    assert len(es.search("alerts")) == 1
    assert not es.doc_exists("alerts", "invalid_doc_id")
    assert es.doc_exists("alerts", "test_doc_id")

    assert es.push("alerts", {"action": "threshold-exceeded-yet-again"})
    time.sleep(2)  # the search will fail if query happens too soon after push
    assert len(es.search("alerts-*")) == 1
    assert len(es.search("alerts*")) == 2
    es.disconnect()
