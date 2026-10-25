import inspect
import json

import pytest
from pydantic import BaseModel, Field

from peat import es_mappings
from peat.data import models
from peat.es_mappings import (
    FLATTENED,
    KEYWORD_AND_TEXT,
    model_mapping,
    peat_index_mappings,
    to_opensearch,
)


def test_model_mapping_inferred_types():
    mapping = model_mapping(models.Interface)
    assert mapping["name"] == {"type": "keyword"}  # constr
    assert mapping["duplex"] == {"type": "keyword"}  # Literal
    assert mapping["enabled"] == {"type": "boolean"}
    assert mapping["uptime"] == {"type": "long"}  # timedelta
    assert mapping["description"]["properties"]["vendor"] == {
        "properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}
    }
    # list of models
    assert mapping["services"]["properties"]["port"] == {"type": "long"}

    file_mapping = model_mapping(models.File)
    assert file_mapping["created"] == {"type": "date"}
    assert file_mapping["original"] == {"type": "binary"}
    assert file_mapping["path"] == {"type": "keyword"}  # PurePath
    assert file_mapping["size"] == {"type": "long"}


def test_model_mapping_elastic_type():
    mapping = model_mapping(models.Interface)
    assert mapping["ip"] == {"type": "ip"}
    assert mapping["mtu"] == {"type": "integer"}
    assert mapping["mac_vendor"] == KEYWORD_AND_TEXT
    assert mapping["extra"] == FLATTENED

    # elastic_type overrides the nested model
    assert model_mapping(models.Geo)["location"] == {"type": "geo_point"}


def test_model_mapping_self_reference_one_level():
    mapping = model_mapping(models.DeviceData)
    assert "module" in mapping
    assert "module" not in mapping["module"]["properties"]
    assert mapping["module"]["properties"]["ip"] == {"type": "ip"}


def test_model_mapping_include():
    mapping = model_mapping(models.DeviceData, include=models.BASE_HOST_FIELD_NAMES)
    assert set(mapping) == set(models.BASE_HOST_FIELD_NAMES)


def test_model_mapping_uninferable_type():
    class DictModel(BaseModel):
        values: dict[str, int] = {}

    with pytest.raises(TypeError, match="elastic_type"):
        model_mapping(DictModel)

    class FlatDictModel(BaseModel):
        values: dict[str, int] = Field(default={}, elastic_type="flattened")

    assert model_mapping(FlatDictModel) == {"values": FLATTENED}

    class ModelDictModel(BaseModel):
        values: dict[str, models.Vendor] = {}

    with pytest.raises(TypeError, match="elastic_type"):
        model_mapping(ModelDictModel)

    class UnionModel(BaseModel):
        value: int | str = ""

    with pytest.raises(TypeError, match="elastic_type"):
        model_mapping(UnionModel)


@pytest.mark.parametrize(
    "model",
    [
        obj
        for _, obj in inspect.getmembers(models, inspect.isclass)
        if issubclass(obj, models.BaseModel) and obj.__module__ == models.__name__
    ],
)
def test_model_mapping_all_models(model):
    assert model_mapping(model)


def test_peat_index_mappings_returns_copy():
    indices = peat_index_mappings()
    indices["peat-logs"]["properties"]["tags"]["type"] = "text"
    del indices["ot-device-files"]
    assert es_mappings.KEYWORD == {"type": "keyword"}
    assert peat_index_mappings()["peat-logs"]["properties"]["tags"] == {"type": "keyword"}
    assert "ot-device-files" in peat_index_mappings()


@pytest.mark.parametrize("opensearch", [False, True])
def test_peat_index_mappings(opensearch):
    indices = peat_index_mappings(opensearch=opensearch)
    assert "ot-device-hosts-timeseries" in indices
    assert "peat-logs" in indices

    hosts = indices["ot-device-hosts-timeseries"]["properties"]
    assert hosts["@timestamp"] == {"type": "date"}
    assert hosts["host"]["properties"]["ip"] == {"type": "ip"}
    assert hosts["host"]["properties"]["event"]["properties"]["severity"] == {"type": "keyword"}

    logs = indices["peat-logs"]["properties"]
    assert logs["event"]["properties"]["severity"] == {"type": "long"}

    files = indices["ot-device-files"]["properties"]
    assert files["file"]["properties"]["hash"]["properties"]["md5"] == {"type": "keyword"}
    assert set(files["host"]["properties"]) == set(models.BASE_HOST_FIELD_NAMES)

    assert indices["ot-device-memory"]["properties"]["memory"]["properties"]["value"] == {
        "type": "keyword",
        "ignore_above": 4096,
    }

    serialized = json.dumps(indices)
    if opensearch:
        assert '"flattened"' not in serialized
        assert hosts["host"]["properties"]["extra"] == {"type": "flat_object"}
    else:
        assert '"flat_object"' not in serialized
        assert hosts["host"]["properties"]["extra"] == FLATTENED


def test_to_opensearch_does_not_mutate():
    mapping = {"a": {"properties": {"extra": FLATTENED}}}
    assert to_opensearch(mapping) == {"a": {"properties": {"extra": {"type": "flat_object"}}}}
    assert mapping == {"a": {"properties": {"extra": FLATTENED}}}
    assert es_mappings.FLATTENED == {"type": "flattened", "ignore_above": 4096}
