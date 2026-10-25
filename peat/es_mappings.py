"""
Mappings (the Elastic "schema") for the various PEAT Elasticsearch indices.

These encode the types defined in the Elastic schemas for
integration of third-party tools and other Sandia capabilities.
Schema reference: :ref:`database-schema`

.. note::
   Type is only required for individual fields, NOT documents

Mappings for the PEAT data models (e.g. :class:`~peat.data.models.DeviceData`)
are generated from the models by :func:`model_mapping`, so the models are the
single source of truth for those types. The type of a field is inferred from
its type annotation (``str`` is ``keyword``, ``int`` is ``long``, ``datetime``
is ``date``, nested models become ``properties``, etc.). Set ``elastic_type``
on the field to override the inferred type, either with the name of a type
(e.g. ``Field(default="", elastic_type="ip")``) or a full mapping
(e.g. ``Field(default="", elastic_type=KEYWORD_AND_TEXT)``).

Fields that aren't part of a data model, such as the ECS ``agent`` and
``observer`` fields or the summary fields, are defined in this module.

Data structure of :func:`peat_index_mappings`

- Key: Name of the index (e.g. ``ot-device-hosts-timeseries``).
- Value: The field mapping for the index, including field types
    and other field configurations, such as tokenizers or filters.

Official Elasticsearch documentation and references

- `Mapping <https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping.html>`__
- `Data types <https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html>`__
- `Nesting <https://www.elastic.co/guide/en/elasticsearch/reference/current/properties.html>`__
- `Create Index <https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-create-index.html>`__
- `Put Mapping <https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-put-mapping.html>`__

"""

from __future__ import annotations

import copy
import datetime
from collections.abc import Collection
from functools import cache
from pathlib import PurePath
from typing import Any, Final, Literal, get_origin

from pydantic import BaseModel
from pydantic.fields import MAPPING_LIKE_SHAPES, ModelField

EsTypeType = dict[str, str | int]
MappingType = dict[str, EsTypeType]
NestedMappingType = dict[str, str | dict]

# -- Elasticsearch types --
BOOL: Final[EsTypeType] = {"type": "boolean"}
BINARY: Final[EsTypeType] = {"type": "binary"}
BYTE: Final[EsTypeType] = {"type": "byte"}
KEYWORD: Final[EsTypeType] = {"type": "keyword"}
IP: Final[EsTypeType] = {"type": "ip"}
# IP_RANGE: Final[EsTypeType] = {"type": "ip_range"}
INTEGER: Final[EsTypeType] = {"type": "integer"}
DATE: Final[EsTypeType] = {"type": "date"}
TEXT: Final[EsTypeType] = {"type": "text"}
LONG: Final[EsTypeType] = {"type": "long"}
DOUBLE: Final[EsTypeType] = {"type": "double"}
NESTED: Final[EsTypeType] = {"type": "nested"}

FLATTENED: Final[EsTypeType] = {
    "type": "flattened",
    "ignore_above": 4096,
}

# *.field and *.field.text
KEYWORD_AND_TEXT: Final[NestedMappingType] = {
    "type": "keyword",
    "fields": {"text": TEXT},
}


# Named types that can be used as "elastic_type" on a model field and
# have a mapping with more than just the type, e.g. "ignore_above".
NAMED_TYPES: Final[dict[str, EsTypeType]] = {
    "flattened": FLATTENED,
}


# -- Mapping generation from the data models --
def _type_mapping(field: ModelField) -> EsTypeType:
    """Infer the Elasticsearch type of a model field from its type annotation."""
    field_type = field.type_

    if field.shape in MAPPING_LIKE_SHAPES or field_type is dict:
        raise TypeError(
            f"Field '{field.name}' is a dict, which has no inferable Elasticsearch "
            f"type. Set 'elastic_type' on the field (e.g. elastic_type=\"flattened\")."
        )

    if get_origin(field_type) is Literal:
        return KEYWORD

    if isinstance(field_type, type):
        # NOTE: bool is a subclass of int, so it must be checked first
        if issubclass(field_type, bool):
            return BOOL
        if issubclass(field_type, int):
            return LONG
        if issubclass(field_type, float):
            return DOUBLE
        if issubclass(field_type, (str, PurePath)):
            return KEYWORD
        if issubclass(field_type, bytes):
            return BINARY
        if issubclass(field_type, datetime.datetime):
            return DATE
        # timedelta is exported as the total number of seconds
        if issubclass(field_type, datetime.timedelta):
            return LONG

    raise TypeError(
        f"Unable to infer the Elasticsearch type of field '{field.name}' "
        f"with type '{field_type}'. Set 'elastic_type' on the field."
    )


def model_mapping(
    model: type[BaseModel],
    include: Collection[str] | None = None,
    _parents: tuple[type[BaseModel], ...] = (),
) -> NestedMappingType:
    """
    Generate the Elasticsearch field mapping for a data model.

    Fields with a nested model (e.g. ``File.hash``) or list of models
    (e.g. ``DeviceData.interface``) are mapped as ``properties`` with the
    mapping of that model. A model that contains itself (e.g. ``DeviceData.module``)
    is expanded one level deep.

    Args:
        model: The model class to generate the mapping for,
            e.g. :class:`~peat.data.models.File`
        include: Names of the fields to include in the mapping.
            If :obj:`None`, all fields are included.

    Returns:
        The field mapping, which can be used as the value of ``properties``

    Raises:
        TypeError: The type of a field can't be inferred and the field
            does not have ``elastic_type`` set.
    """
    mapping = {}

    for name, field in model.__fields__.items():
        if include is not None and name not in include:
            continue

        elastic_type = field.field_info.extra.get("elastic_type")
        if isinstance(elastic_type, str):
            mapping[name] = NAMED_TYPES.get(elastic_type, {"type": elastic_type})
        elif elastic_type is not None:
            mapping[name] = elastic_type
        elif (
            field.shape not in MAPPING_LIKE_SHAPES
            and isinstance(field.type_, type)
            and issubclass(field.type_, BaseModel)
        ):
            if field.type_ in _parents:
                continue
            mapping[name] = {"properties": model_mapping(field.type_, _parents=(*_parents, model))}
        else:
            mapping[name] = _type_mapping(field)

    return mapping


def to_opensearch(mapping: Any) -> Any:
    """
    Convert a mapping to be compatible with OpenSearch.

    OpenSearch uses ``flat_object`` instead of ``flattened``,
    and doesn't support ``ignore_above`` on it.
    """
    if not isinstance(mapping, dict):
        return mapping
    if mapping.get("type") == "flattened":
        return {"type": "flat_object"}
    return {key: to_opensearch(value) for key, value in mapping.items()}


# -- Mapping definitions for fields that aren't in the data models, based on ECS --
AGENT_FIELDS: Final[MappingType] = {
    "id": KEYWORD,
    "type": KEYWORD,
    "version": KEYWORD,
}

ECS_FIELDS: Final[MappingType] = {"version": KEYWORD}

ERROR_FIELDS: Final[MappingType] = {
    "code": KEYWORD,
    "id": KEYWORD,
    "message": TEXT,
    "stack_trace": TEXT,
    "type": KEYWORD,
}

PROCESS_FIELDS: Final[NestedMappingType] = {
    "args": KEYWORD,
    "args_count": LONG,
    "command_line": KEYWORD_AND_TEXT,
    "executable": KEYWORD_AND_TEXT,
    "name": KEYWORD_AND_TEXT,
    "parent": {"properties": {"pid": LONG}},
    "pgid": LONG,
    "pid": LONG,
    "start": DATE,
    "thread": {"properties": {"id": LONG, "name": KEYWORD}},
    "title": KEYWORD_AND_TEXT,
    "working_directory": KEYWORD_AND_TEXT,
}


# -- PEAT index mappings --
def peat_index_mappings(opensearch: bool = False) -> dict[str, dict]:
    """
    Generate the mappings for the PEAT Elasticsearch indices.

    Args:
        opensearch: If the mappings are for OpenSearch instead of Elasticsearch

    Returns:
        Mapping of index names to the mapping for the index. This is a copy,
        so it can be modified without affecting other callers.
    """
    return copy.deepcopy(_peat_index_mappings(opensearch))


@cache
def _peat_index_mappings(opensearch: bool) -> dict[str, dict]:
    # Imported here since the models import this module
    from peat.data import models

    observer_fields = {
        "geo": {"properties": model_mapping(models.Geo)},
        "hostname": KEYWORD,
        "interface": {
            "properties": {"name": KEYWORD, "egress": {"properties": {"name": KEYWORD}}}
        },
        "ip": IP,
        "mac": KEYWORD,
        "os": {"properties": model_mapping(models.OS)},
        "user": {"properties": model_mapping(models.User)},
    }

    base_fields = {
        "@timestamp": DATE,
        "agent": {"properties": AGENT_FIELDS},
        "ecs": {"properties": ECS_FIELDS},
        "message": TEXT,
        "observer": {"properties": observer_fields},
        "tags": KEYWORD,
    }

    event_fields = model_mapping(models.Event)
    host_fields = model_mapping(models.DeviceData)
    basic_host_fields = model_mapping(models.DeviceData, include=models.BASE_HOST_FIELD_NAMES)

    parse_result = {
        "properties": {
            "name": KEYWORD,
            "path": KEYWORD,
            "module": KEYWORD,
            "results": {"properties": host_fields},
        }
    }

    indices = {
        "peat-logs": {
            "properties": {
                **base_fields,
                "error": {"properties": ERROR_FIELDS},
                # PEAT log events use the numeric log level as the severity
                "event": {"properties": {**event_fields, "severity": LONG}},
                "log": {
                    "properties": {
                        "level": KEYWORD,
                        "logger": KEYWORD,
                        "original": KEYWORD,
                        "origin": {
                            "properties": {
                                "function": KEYWORD,
                                "file": {"properties": {"line": LONG, "name": KEYWORD}},
                            }
                        },
                    }
                },
                "peat": {
                    "properties": {
                        "containerized": BOOL,
                        "debug_level": LONG,
                        "entrypoint": KEYWORD,
                        "podman": BOOL,
                        "python_version": KEYWORD,
                    }
                },
                "process": {"properties": PROCESS_FIELDS},
            }
        },
        "peat-scan-summaries": {
            "properties": {
                **base_fields,
                "peat_version": KEYWORD,
                "peat_run_id": KEYWORD,
                "scan_duration": DOUBLE,
                "scan_modules": KEYWORD,
                "scan_type": KEYWORD,
                # Targets could be IPs, IP ranges, serial ports, MACs, etc.
                # Therefore, we just use a plain ole' "keyword" type.
                "scan_targets": KEYWORD,
                "scan_original_targets": KEYWORD,
                "num_hosts_active": LONG,
                "num_hosts_online": LONG,
                "num_hosts_verified": LONG,
                "hosts_online": KEYWORD,
                "hosts_verified": FLATTENED,
            }
        },
        "peat-pull-summaries": {
            "properties": {
                **base_fields,
                "peat_version": KEYWORD,
                "peat_run_id": KEYWORD,
                "pull_duration": DOUBLE,
                "pull_modules": KEYWORD,
                # Targets could be IPs, IP ranges, serial ports, MACs, etc.
                # Therefore, we just use a plain ole' "keyword" type.
                "pull_targets": KEYWORD,
                "pull_original_targets": KEYWORD,
                "pull_devices": KEYWORD,
                "pull_comm_type": KEYWORD,
                "num_pull_results": LONG,
                "pull_results": FLATTENED,
            }
        },
        "peat-parse-summaries": {
            "properties": {
                **base_fields,
                "peat_version": KEYWORD,
                "peat_run_id": KEYWORD,
                "parse_duration": DOUBLE,
                "parse_modules": KEYWORD,
                "input_paths": KEYWORD,
                "files_parsed": KEYWORD,
                "num_files_parsed": LONG,
                "num_parse_successes": LONG,
                "num_parse_failures": LONG,
                "parse_failures": parse_result,
                "parse_results": parse_result,
            }
        },
        "peat-configs": {
            "properties": {
                **base_fields,
            }
        },
        "peat-state": {
            "properties": {
                **base_fields,
            }
        },
        "ot-device-hosts-timeseries": {
            "properties": {
                **base_fields,
                "host": {"properties": host_fields},
            }
        },
    }

    # Indices for models that are pushed to their own index,
    # e.g. "ot-device-files" with the File in "file"
    for index_name, key, model in [
        ("ot-device-events", "", None),
        ("ot-device-files", "file", models.File),
        ("ot-device-registers", "register", models.Register),
        ("ot-device-tags", "tag", models.Tag),
        ("ot-device-io", "io", models.IO),
        ("ot-device-memory", "memory", models.Memory),
        ("uefi-files", "uefi", models.UEFIFile),
        ("uefi-hashes", "uefi", models.UEFIHash),
    ]:
        properties = {
            **base_fields,
            "event": {"properties": event_fields},
            "host": {"properties": basic_host_fields},
        }
        if model is not None:
            properties[key] = {"properties": model_mapping(model)}
        indices[index_name] = {"properties": properties}

    if opensearch:
        indices = to_opensearch(indices)

    return indices
