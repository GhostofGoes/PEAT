import os
import time
from datetime import datetime

import pytest

from peat import Elastic, config


def test_init():
    assert Elastic()


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


def test_dated_index(mocker):
    es = Elastic()
    mocker.patch("peat.utils.utc_now", return_value=datetime(2021, 2, 25, 1, 2, 3))
    assert es._dated_index("peat-configs") == "peat-configs-2021.02.25"
    es.index_date = datetime(2019, 12, 31)
    assert es._dated_index("peat-configs") == "peat-configs-2019.12.31"


def test_attribute_to_run():
    es = Elastic()
    other = Elastic()
    orig_agent = es.base_info["agent"]
    orig_id = orig_agent["id"]
    orig_start = es.start_time
    start = datetime.fromisoformat("2026-10-31T07:31:49+00:00")

    with es.attribute_to_run("179343190989", start):
        assert es.base_info["agent"]["id"] == "179343190989"
        assert es.index_date == start
        assert es.start_time == "2026-10-31T07:31:49.000Z"
        assert Elastic.time_now() == "2026-10-31T07:31:49.000Z"
        assert es.gen_body({})["@timestamp"] == "2026-10-31T07:31:49.000Z"
        # event.ingested from time_now() is the actual time, other values are kept
        content = {"event": {"ingested": Elastic.time_now(), "kind": "event"}}
        body = es.gen_body(content)
        assert body["event"]["ingested"] != "2026-10-31T07:31:49.000Z"
        assert body["event"]["kind"] == "event"
        assert content["event"]["ingested"] == "2026-10-31T07:31:49.000Z"  # Not modified
        ingested = "2020-01-02T03:04:05.000Z"
        assert es.gen_body({"event": {"ingested": ingested}})["event"]["ingested"] == ingested
        # Other instances (e.g. the logging sink) keep their own index dates
        assert other.index_date is None
    assert es.base_info["agent"] is orig_agent
    assert orig_agent["id"] == orig_id  # Not modified in place
    assert es.start_time == orig_start
    assert es.index_date is None
    assert Elastic._time_override is None
    assert Elastic.time_now() != "2026-10-31T07:31:49.000Z"

    # None values keep the current values, and values are restored on errors
    with pytest.raises(ValueError), es.attribute_to_run(None, None):
        assert es.base_info["agent"]["id"] == orig_id
        assert es.index_date is None
        raise ValueError
    assert Elastic._time_override is None
