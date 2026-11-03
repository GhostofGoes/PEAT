from __future__ import annotations

import base64
from datetime import timedelta
from ipaddress import IPv4Interface, IPv6Interface
from pathlib import Path, PurePath

from pydantic import BaseModel as PydanticBaseModel
from pydantic import PrivateAttr


def bytes_to_base64(value: bytes) -> str:
    """
    Attempt to decode bytes as UTF-8, and fallback to Base64 encoding
    if decode fails.
    """
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return base64.b64encode(value).decode("utf-8")


def clean_set(value: set) -> list:
    """
    Remove empty strings and Nones from the set, sort, and convert to list.
    """
    for empty_val in ["", None]:
        if empty_val in value:
            value.remove(empty_val)
    return sorted(value)  # Sort sets for determinism


JSON_ENCODERS = {
    bytes: bytes_to_base64,
    bytearray: bytes_to_base64,
    memoryview: bytes_to_base64,
    Path: lambda v: v.as_posix(),
    PurePath: lambda v: v.as_posix(),
    timedelta: lambda v: v.total_seconds(),
    set: clean_set,
    IPv4Interface: lambda v: str(v.ip),
    IPv6Interface: lambda v: str(v.ip),
}


# https://pydantic-docs.helpmanual.io/usage/model_config/#change-behaviour-globally
# Defining __eq__ sets __hash__ to None: models are mutable and stay unhashable,
# like pydantic models ("__hash__ = None" here would be a pydantic private attribute)
class BaseModel(PydanticBaseModel):  # noqa: PLW1641
    _cache: dict = PrivateAttr(default={})
    """
    Cache for internal usage by device modules. Can include data such as
    Python sockets, protocol classes (e.g. :class:`~peat.protocols.ftp.FTP`)
    or other objects or state.
    """

    _elastic_doc_id: str = PrivateAttr(default="")
    """
    Elasticsearch document ID of this model.

    This is set to ``agent.id`` (``consts.RUN_ID``) + a randomly generated value.
    """

    _es_index_varname: str = PrivateAttr(default="")
    """Name of PEAT variable for this model's Elasticsearch index."""

    _sort_by_fields: tuple[str] = PrivateAttr(default=())
    """Field names and order to use when sorting lists of this model."""

    _dedupe_key: tuple[str] = PrivateAttr(default=())
    """
    Fields that identify a model inside a list. Items whose values for ALL these
    fields are equal (and not all empty) are merged by ``dedupe_model_list()``,
    and ``DeviceData.store()`` uses them as the default lookup.
    """

    _newest_wins_field: str = PrivateAttr(default="")
    """
    Name of a datetime field. When two models are merged and the source's value
    is newer, the source's non-default values overwrite the destination's
    (``NetworkStatistics`` is replaced wholesale, see ``merge_models()``).
    """

    def __repr_args__(self) -> list[tuple]:
        return [
            (a, v) for a, v in super().__repr_args__() if v is not None and not self.is_default(a)
        ]

    def __eq__(self, other) -> bool:
        # Same class: compare the field values directly (nested models recurse
        # through this method). pydantic v1 converts BOTH models to dicts on every
        # comparison, which exclude_defaults/is_default() do for every sub-model field.
        # This equals pydantic's result: no model excludes or includes fields, and
        # private attributes are not in __dict__.
        if type(other) is type(self):
            return self.__dict__ == other.__dict__
        return super().__eq__(other)

    def annotate(self, dev=None) -> None:
        """Populate and cleanup fields on a model."""
        pass

    def is_default(self, field_key: str) -> bool:
        """Check if a field's current value is the default value."""
        model_field = self.__fields__.get(field_key)
        if getattr(model_field, "default", None) == getattr(self, field_key):
            return True
        return False

    def gen_elastic_content(self, dev=None) -> dict:
        """
        Generates the data structure that will be pushed to Elasticsearch.

        This is overridden by child classes.

        Args:
            dev: DeviceData object to use as source for host data for the event

        Returns:
            Complete document structure that can be pushed to Elasticsearch
        """
        pass

    # Config docs: https://pydantic-docs.helpmanual.io/usage/model_config/
    class Config:
        # Allows PurePath types to be used
        # https://github.com/samuelcolvin/pydantic/issues/2089
        arbitrary_types_allowed = True

        # Setting attributes that aren't defined is an error
        extra = "forbid"

        # Enables validation on assignment, e.g. logic.file.extension = "txt"
        validate_assignment = True

        # Convert data types when serializing JSON
        json_encoders = JSON_ENCODERS

        # Make anything starting with an underscore PrivateAttr
        underscore_attrs_are_private = True

        copy_on_model_validation = "deep"


__all__ = ["BaseModel"]
