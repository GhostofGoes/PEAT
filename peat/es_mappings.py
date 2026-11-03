"""
Mappings (the Elastic "schema") for the various PEAT Elasticsearch indices.

These encode the types defined in the Elastic schemas for
integration of third-party tools and other Sandia capabilities.
Schema reference: :ref:`database-schema`

.. note::
   Type is only required for individual fields, NOT documents

Data structure

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

from typing import Final

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

# NOTE: flattened is not "Final" due to a hack in elastic.py
FLATTENED: EsTypeType = {
    "type": "flattened",
    "ignore_above": 4096,
}

# *.field and *.field.text
KEYWORD_AND_TEXT: Final[NestedMappingType] = {
    "type": "keyword",
    "fields": {"text": TEXT},
}

# Long keyword values (e.g. JSON-encoded expected/actual values of baseline findings)
LONG_KEYWORD: Final[EsTypeType] = {"type": "keyword", "ignore_above": 4096}

# Free text of fields added for ECS 9.5.0 / issue #48: keyword limited to 1024
# characters like ECS keywords (a single value over 32766 bytes would otherwise
# reject the whole document), full text searchable through the ".text" multi-field.
FREE_TEXT: Final[NestedMappingType] = {
    "type": "keyword",
    "ignore_above": 1024,
    "fields": {"text": TEXT},
}


# -- Reusable mapping definitions based on ECS --
VENDOR_FIELDS: Final[MappingType] = {
    "name": KEYWORD,
    "id": KEYWORD,
}

DESCRIPTION_FIELDS: Final[NestedMappingType] = {
    "brand": KEYWORD,
    "contact_info": KEYWORD_AND_TEXT,
    "description": KEYWORD_AND_TEXT,
    "full": KEYWORD_AND_TEXT,
    "model": KEYWORD,
    "product": KEYWORD_AND_TEXT,
    "vendor": {"properties": VENDOR_FIELDS},
}

HARDWARE_FIELDS: Final[NestedMappingType] = {
    "cpu": {"properties": DESCRIPTION_FIELDS},
    "id": KEYWORD,
    "storage_available": LONG,
    "storage_usage": LONG,
    "storage_total": LONG,
    "storage_type": KEYWORD,
    "memory_available": LONG,
    "memory_usage": LONG,
    "memory_total": LONG,
    "memory_type": KEYWORD,
    "revision": KEYWORD,
    "version": KEYWORD,
}

HASH_FIELDS: Final[MappingType] = {
    "md5": KEYWORD,
    "sha1": KEYWORD,
    "sha256": KEYWORD,
    "sha512": KEYWORD,
}

USER_FIELDS: Final[NestedMappingType] = {
    "description": KEYWORD_AND_TEXT,
    "domain": KEYWORD,
    "email": KEYWORD,
    "full_name": KEYWORD_AND_TEXT,
    "id": KEYWORD,
    "name": KEYWORD_AND_TEXT,
    "permissions": KEYWORD,
    "roles": KEYWORD,
    "uid": KEYWORD,
    "gid": KEYWORD,
    "extra": FLATTENED,
}

RELATED_FIELDS: Final[MappingType] = {
    "emails": KEYWORD,
    "files": KEYWORD,
    "hash": KEYWORD,
    "hosts": KEYWORD,
    "ip": IP,
    "mac": KEYWORD,
    "ports": LONG,
    "protocols": KEYWORD,
    "process": KEYWORD,
    "roles": KEYWORD,
    "urls": KEYWORD,
    "user": KEYWORD,
    "vlans": KEYWORD,
}

FILE_FIELDS: Final[NestedMappingType] = {
    "created": DATE,
    "description": KEYWORD_AND_TEXT,
    "device": KEYWORD,
    "directory": KEYWORD,
    "extension": KEYWORD,
    "hash": {"properties": HASH_FIELDS},
    "local_path": KEYWORD,
    "path": KEYWORD,
    "peat_module": KEYWORD,
    "gid": KEYWORD,
    "group": KEYWORD,
    "mime_type": KEYWORD,
    "mode": KEYWORD,
    "mtime": DATE,
    "name": KEYWORD,
    "original": BINARY,
    "owner": KEYWORD,
    "size": LONG,
    "target_path": KEYWORD,
    "type": KEYWORD,
    "category": KEYWORD,
    "uid": KEYWORD,
    "extra": FLATTENED,
}

VLAN_FIELDS: Final[MappingType] = {
    "id": KEYWORD,
    "name": KEYWORD,
    "priority": BYTE,
    "tagged": BOOL,
}

NETWORK_TRAFFIC_FIELDS: Final[MappingType] = {
    "bytes": LONG,
    "packets": LONG,
    "unicast_packets": LONG,
    "multicast_packets": LONG,
    "broadcast_packets": LONG,
    "messages": LONG,
    "errors": LONG,
    "dropped": LONG,
    "crc_errors": LONG,
    "unknown_protocols": LONG,
}

CONNECTION_STATISTICS_FIELDS: Final[MappingType] = {
    "active": LONG,
    "max": LONG,
    "listening": LONG,
    "total": LONG,
    "failed": LONG,
    "closed": LONG,
    "resets": LONG,
    "timeouts": LONG,
    "authentication_successes": LONG,
    "authentication_failures": LONG,
}

NETWORK_STATISTICS_FIELDS: Final[NestedMappingType] = {
    "timestamp": DATE,
    "since": DATE,
    "interface": KEYWORD,
    "type": KEYWORD,
    "transport": KEYWORD,
    "protocol": KEYWORD,
    "ingress": {"properties": NETWORK_TRAFFIC_FIELDS},
    "egress": {"properties": NETWORK_TRAFFIC_FIELDS},
    "connections": {"properties": CONNECTION_STATISTICS_FIELDS},
    "collisions": LONG,
    "link_down_count": LONG,
    "extra": FLATTENED,
}

SERVICE_SECURITY_FIELDS: Final[MappingType] = {
    "authentication_required": BOOL,
    "anonymous_access": BOOL,
    "default_credentials": BOOL,
    "encrypted": BOOL,
    "security_mode": KEYWORD,
    "authentication_methods": KEYWORD,
    "tls_version": KEYWORD,
    "extra": FLATTENED,
}

REDUNDANCY_FIELDS: Final[MappingType] = {
    "protocol": KEYWORD,
    "mode": KEYWORD,
    "role": KEYWORD,
    "state": KEYWORD,
    "lan": KEYWORD,
    "members": KEYWORD,
    "partner": KEYWORD,
    "extra": FLATTENED,
}

LOGIC_TASK_FIELDS: Final[NestedMappingType] = {
    "name": KEYWORD,
    "type": KEYWORD,
    "interval": DOUBLE,  # timedelta -> seconds (float)
    "priority": LONG,
    "watchdog": DOUBLE,
    "programs": KEYWORD,
    "enabled": BOOL,
    "scan_count": LONG,
    "scan_time_min": DOUBLE,
    "scan_time_max": DOUBLE,
    "scan_time_avg": DOUBLE,
    "scan_time_last": DOUBLE,
    "overruns": LONG,
    "cpu_percent": DOUBLE,
    "description": FREE_TEXT,
    "extra": FLATTENED,
}

FIRMWARE_FIELDS: Final[NestedMappingType] = {
    "checksum": KEYWORD,
    "extra": FLATTENED,
    "file": {"properties": FILE_FIELDS},
    "hash": {"properties": HASH_FIELDS},
    "id": KEYWORD,
    "last_updated": DATE,
    "original": BINARY,
    "revision": KEYWORD,
    "release_date": DATE,
    "timestamp": DATE,
    "version": KEYWORD,
}

LOGIC_FIELDS: Final[NestedMappingType] = {
    "author": KEYWORD_AND_TEXT,
    "created": DATE,
    "description": KEYWORD_AND_TEXT,
    "file": {"properties": FILE_FIELDS},
    "formats": NESTED,
    "hash": {"properties": HASH_FIELDS},
    "id": KEYWORD,
    "last_updated": DATE,
    "name": KEYWORD_AND_TEXT,
    "original": TEXT,
    "parsed": TEXT,
    "tasks": {"properties": LOGIC_TASK_FIELDS},
}

CERTENTITY_FIELDS: Final[MappingType] = {
    "common_name": KEYWORD,
    "country": KEYWORD,
    "distinguished_name": KEYWORD,
    "locality": KEYWORD,
    "organization": KEYWORD,
    "organizational_unit": KEYWORD,
    "state_or_province": KEYWORD,
}

X509_FIELDS: Final[NestedMappingType] = {
    "alternative_names": KEYWORD,
    "hash": {"properties": HASH_FIELDS},
    "issuer": {"properties": CERTENTITY_FIELDS},
    "not_after": DATE,
    "not_before": DATE,
    "original": KEYWORD,
    "public_key_algorithm": KEYWORD,
    "public_key_curve": KEYWORD,
    "public_key_exponent": LONG,
    "public_key_size": LONG,
    "serial_number": KEYWORD,
    "signature_algorithm": KEYWORD,
    "subject": {"properties": CERTENTITY_FIELDS},
    "version_number": KEYWORD,
}

SERVICE_FIELDS: Final[NestedMappingType] = {
    "configured_port": LONG,
    "enabled": BOOL,
    "extra": FLATTENED,
    "listen_address": IP,
    "listen_interface": KEYWORD,
    "process_name": KEYWORD,
    "process_pid": LONG,
    "port": LONG,
    "protocol": KEYWORD,
    "protocol_id": KEYWORD,
    "role": KEYWORD,
    "security": {"properties": SERVICE_SECURITY_FIELDS},
    "statistics": {"properties": NETWORK_STATISTICS_FIELDS},
    "status": KEYWORD,
    "transport": KEYWORD,
}

INTERFACE_FIELDS: Final[NestedMappingType] = {
    "alias": KEYWORD,
    "application": KEYWORD,
    "connected": BOOL,
    "description": {"properties": DESCRIPTION_FIELDS},
    "duplex": KEYWORD,
    "enabled": BOOL,
    "extra": FLATTENED,
    "name": KEYWORD,
    "parent": KEYWORD,
    "vlan": {"properties": VLAN_FIELDS},
    "vlans": {"properties": VLAN_FIELDS},
    "redundancy": {"properties": REDUNDANCY_FIELDS},
    "type": KEYWORD,
    "hostname": KEYWORD,
    "mac": KEYWORD,
    "mac_vendor": KEYWORD_AND_TEXT,
    "mtu": INTEGER,
    "physical": BOOL,
    "promiscuous_mode": BOOL,
    "speed": INTEGER,
    "uptime": LONG,
    "statistics": {"properties": NETWORK_STATISTICS_FIELDS},
    "hardware_mac": KEYWORD,
    "id": KEYWORD,
    "ip": IP,
    "subnet_mask": IP,
    "gateway": IP,
    "serial_port": KEYWORD,
    "baudrate": INTEGER,
    "data_bits": BYTE,
    "parity": KEYWORD,
    "stop_bits": BYTE,
    "flow_control": KEYWORD,
    "services": {"properties": SERVICE_FIELDS},
    "version": KEYWORD,
}

REGISTER_FIELDS: Final[MappingType] = {
    "address": KEYWORD,
    "data_type": KEYWORD,
    "description": TEXT,
    "enabled": BOOL,
    "extra": FLATTENED,
    "group": KEYWORD,
    "io": KEYWORD,
    "measurement_type": KEYWORD,
    "name": KEYWORD,
    "protocol": KEYWORD,
    "read_write": KEYWORD,
    "tag": KEYWORD,
}

TAG_FIELDS: Final[MappingType] = {
    "address": KEYWORD,
    "description": TEXT,
    "io": KEYWORD,
    "name": KEYWORD,
    "type": KEYWORD,
}

IO_FIELDS: Final[MappingType] = {
    "address": KEYWORD,
    "description": TEXT,
    "direction": KEYWORD,
    "extra": FLATTENED,
    "id": KEYWORD,
    "name": KEYWORD,
    "type": KEYWORD,
    "slot": KEYWORD,
}

ERROR_FIELDS: Final[MappingType] = {
    "code": KEYWORD,
    "id": KEYWORD,
    "message": TEXT,
    "stack_trace": TEXT,
    "type": KEYWORD,
}

GEO_FIELDS: Final[MappingType] = {
    "city_name": KEYWORD,
    "country_name": KEYWORD,
    "location": {"type": "geo_point"},
    "name": KEYWORD,
    "timezone": KEYWORD,
}

ROUTE_FIELDS: Final[NestedMappingType] = {
    "destination": KEYWORD,
    "gateway": IP,
    "interface": KEYWORD,
    "metric": LONG,
    "type": KEYWORD,
    "protocol": KEYWORD,
    "flags": KEYWORD,
    "enabled": BOOL,
    "description": FREE_TEXT,
    "extra": FLATTENED,
}

TIME_SOURCE_FIELDS: Final[MappingType] = {
    "protocol": KEYWORD,
    "address": KEYWORD,
    "port": LONG,
    "priority": LONG,
    "stratum": LONG,
    "state": KEYWORD,
    "enabled": BOOL,
    "selected": BOOL,
    "offset": DOUBLE,
    "last_sync": DATE,
    "extra": FLATTENED,
}

CLOCK_FIELDS: Final[NestedMappingType] = {
    "time": DATE,
    "observed": DATE,
    "offset": DOUBLE,
    "utc_offset": KEYWORD,
    "synchronized": BOOL,
    "source": KEYWORD,
    "last_sync": DATE,
    "sources": {"properties": TIME_SOURCE_FIELDS},
    "extra": FLATTENED,
}

RELATIONSHIP_ENDPOINT_FIELDS: Final[MappingType] = {
    "address": KEYWORD,
    "ip": IP,
    "mac": KEYWORD,
    "port": LONG,
    "hostname": KEYWORD,
    "id": KEYWORD,
    "name": KEYWORD,
    "interface": KEYWORD,
    "serial_port": KEYWORD,
    "protocol_address": KEYWORD,
    "role": KEYWORD,
}

RELATIONSHIP_FIELDS: Final[NestedMappingType] = {
    "id": KEYWORD,
    "type": KEYWORD,
    "protocol": KEYWORD,
    "transport": KEYWORD,
    "medium": KEYWORD,
    "direction": KEYWORD,
    "local": {"properties": RELATIONSHIP_ENDPOINT_FIELDS},
    "remote": {"properties": RELATIONSHIP_ENDPOINT_FIELDS},
    "vlan": {"properties": VLAN_FIELDS},
    "reference": KEYWORD,
    "state": KEYWORD,
    "enabled": BOOL,
    "evidence": KEYWORD,
    "first_seen": DATE,
    "last_seen": DATE,
    "count": LONG,
    "statistics": {"properties": NETWORK_STATISTICS_FIELDS},
    "description": FREE_TEXT,
    "extra": FLATTENED,
}

INDICATOR_FIELDS: Final[NestedMappingType] = {
    "name": KEYWORD,
    "label": FREE_TEXT,
    "type": KEYWORD,
    "category": KEYWORD,
    "state": KEYWORD,
    "color": KEYWORD,
    "blink_rate": DOUBLE,
    "value": FREE_TEXT,
    "description": FREE_TEXT,
    "health": KEYWORD,
    "latched": BOOL,
    "equation": FREE_TEXT,
    "interface": KEYWORD,
    "position": KEYWORD,
    "timestamp": DATE,
    "extra": FLATTENED,
}

# ECS "process.*" leaf names (reuses USER_FIELDS and HASH_FIELDS)
HOST_PROCESS_FIELDS: Final[NestedMappingType] = {
    "pid": LONG,
    "name": FREE_TEXT,
    "title": FREE_TEXT,
    "executable": FREE_TEXT,
    "args": KEYWORD,
    "command_line": FREE_TEXT,
    "working_directory": FREE_TEXT,
    "start": DATE,
    "uptime": LONG,
    "exit_code": LONG,
    "entity_id": KEYWORD,
    "parent": {"properties": {"pid": LONG, "name": KEYWORD}},
    "user": {"properties": USER_FIELDS},
    "hash": {"properties": HASH_FIELDS},
    "type": KEYWORD,
    "state": KEYWORD,
    "priority": LONG,
    "threads_count": LONG,
    "cpu_percent": DOUBLE,
    "memory_bytes": LONG,
    "memory_percent": DOUBLE,
    "extra": FLATTENED,
}

# ECS "package.*" leaf names
PACKAGE_FIELDS: Final[NestedMappingType] = {
    "name": KEYWORD,
    "version": KEYWORD,
    "type": KEYWORD,
    "category": KEYWORD,
    "architecture": KEYWORD,
    "description": FREE_TEXT,
    "installed": DATE,
    "path": KEYWORD,
    "license": KEYWORD,
    "reference": KEYWORD,
    "size": LONG,
    "checksum": KEYWORD,
    "build_version": KEYWORD,
    "vendor": KEYWORD,
    "cpe": KEYWORD,
    "purl": KEYWORD,
    "extra": FLATTENED,
}

ASSET_FIELDS: Final[NestedMappingType] = {
    "id": KEYWORD,
    "criticality": KEYWORD,
    "owner": KEYWORD,
    "business_unit": KEYWORD,
    "site": KEYWORD,
    "location": KEYWORD,
    "zone": KEYWORD,
    "conduits": KEYWORD,
    "purdue_level": KEYWORD,
    "safety": BOOL,
    "tags": KEYWORD,
    "description": FREE_TEXT,
    "extra": FLATTENED,
}

IEC61850_ADDRESS_FIELDS: Final[NestedMappingType] = {
    "mac": KEYWORD,
    "appid": LONG,
    "vlan": {"properties": VLAN_FIELDS},
}

IEC61850_FIELDS: Final[NestedMappingType] = {
    "ied_name": KEYWORD,
    "description": FREE_TEXT,
    "manufacturer": KEYWORD,
    "ied_type": KEYWORD,
    "config_version": KEYWORD,
    "original_scl_version": KEYWORD,
    "scl_file": KEYWORD,
    "header": {
        "properties": {
            "file_type": KEYWORD,
            "scl_version": KEYWORD,
            "id": KEYWORD,
            "version": KEYWORD,
            "revision": KEYWORD,
            "tool_id": KEYWORD,
            "name_structure": KEYWORD,
            "history": {
                "properties": {
                    "version": KEYWORD,
                    "revision": KEYWORD,
                    "when": KEYWORD,
                    "who": KEYWORD,
                    "what": FREE_TEXT,
                    "why": FREE_TEXT,
                }
            },
        }
    },
    "access_points": {
        "properties": {
            "name": KEYWORD,
            "subnetwork": KEYWORD,
            "subnetwork_type": KEYWORD,
            "ip": IP,
            "subnet_mask": IP,
            "gateway": IP,
            "mms_port": LONG,
            "server": BOOL,
            "authentication": KEYWORD,
            "redundancy": KEYWORD,
            "physical_ports": KEYWORD,
            "router": BOOL,
            "clock": BOOL,
            "osi": FLATTENED,
        }
    },
    "logical_devices": {
        "properties": {
            "inst": KEYWORD,
            "name": KEYWORD,
            "description": FREE_TEXT,
            "access_point": KEYWORD,
            "logical_nodes": KEYWORD,
        }
    },
    "publications": {
        "properties": {
            "type": KEYWORD,
            "name": KEYWORD,
            "ld_inst": KEYWORD,
            "reference": KEYWORD,
            "id": KEYWORD,
            "dataset": KEYWORD,
            "dataset_members_count": LONG,
            "conf_rev": LONG,
            "security": KEYWORD,
            "address": {"properties": IEC61850_ADDRESS_FIELDS},
            "min_time": LONG,
            "max_time": LONG,
            "smp_rate": LONG,
            "smp_mod": KEYWORD,
            "nof_asdu": LONG,
            "subscribers": KEYWORD,
            "description": FREE_TEXT,
        }
    },
    "report_controls": {
        "properties": {
            "name": KEYWORD,
            "ld_inst": KEYWORD,
            "ln": KEYWORD,
            "report_id": KEYWORD,
            "dataset": KEYWORD,
            "conf_rev": LONG,
            "buffered": BOOL,
            "buffer_time": LONG,
            "integrity_period": LONG,
            "trigger_options": KEYWORD,
            "max_clients": LONG,
            "clients": KEYWORD,
        }
    },
    "subscriptions": {
        "properties": {
            "service_type": KEYWORD,
            "publisher_ied": KEYWORD,
            "publisher_ld_inst": KEYWORD,
            "control_block": KEYWORD,
            "reference": KEYWORD,
            "address": {"properties": IEC61850_ADDRESS_FIELDS},
            "ext_ref_count": LONG,
        }
    },
    "datasets_count": LONG,
    "setting_groups": LONG,
    "active_setting_group": LONG,
    "capabilities": FLATTENED,
    "functional_locations": KEYWORD,
    "extra": FLATTENED,
}

# ECS "rule.*" subset for baseline findings (rule.version is not emitted)
RULE_FIELDS: Final[MappingType] = {
    "id": KEYWORD,
    "name": KEYWORD,
    "ruleset": KEYWORD,
    "reference": KEYWORD,
    "category": KEYWORD,
}

# Custom root "baseline.*" of the baseline findings index
BASELINE_DOC_FIELDS: Final[NestedMappingType] = {
    "id": KEYWORD,
    "name": KEYWORD,
    "kind": KEYWORD,
    "version": KEYWORD,
    "finding": {
        "properties": {
            "path": KEYWORD,
            "category": KEYWORD,
            "result": KEYWORD,
            "difference": KEYWORD,
            "operator": KEYWORD,
            "expected": LONG_KEYWORD,
            "actual": LONG_KEYWORD,
            "severity": KEYWORD,
            "standards": KEYWORD,
        }
    },
}

EVENT_FIELDS: Final[NestedMappingType] = {
    "action": KEYWORD_AND_TEXT,
    "category": KEYWORD,
    "code": KEYWORD,
    "created": DATE,
    "dataset": KEYWORD,
    "end": DATE,  # relationships index: Relationship.last_seen
    "extra": FLATTENED,
    "hash": {"properties": HASH_FIELDS},
    "id": KEYWORD,
    "ingested": DATE,
    "kind": KEYWORD,
    "message": KEYWORD_AND_TEXT,
    "module": KEYWORD,
    "original": TEXT,
    "outcome": KEYWORD,
    "provider": KEYWORD,
    "reason": FREE_TEXT,
    "sequence": LONG,
    "severity": LONG,
    "start": DATE,  # relationships index: Relationship.first_seen
    "timezone": KEYWORD,
    "type": KEYWORD,
}

# host.event[*] only: Event.log_level is exported as root "log.level" in the
# events index, but as "host.event[*].log_level" in host documents.
HOST_EVENT_FIELDS: Final[NestedMappingType] = {
    **{k: v for k, v in EVENT_FIELDS.items() if k not in ("start", "end")},
    "log_level": KEYWORD,
}

OS_FIELDS: Final[NestedMappingType] = {
    "family": KEYWORD,
    "full": KEYWORD,
    "kernel": KEYWORD,
    "name": KEYWORD,
    "timestamp": DATE,
    "vendor": {"properties": VENDOR_FIELDS},
    "version": KEYWORD,
}

MEMORY_FIELDS: Final[MappingType] = {
    "address": KEYWORD,
    "created": DATE,
    "dataset": KEYWORD,
    "device": KEYWORD,
    "process": KEYWORD,
    "size": LONG,
    "value": {
        "type": "keyword",
        "ignore_above": 4096,  # memory values can be quite large
    },
    "extra": FLATTENED,
}

SSHKEY_FIELDS: Final[NestedMappingType] = {
    "description": KEYWORD_AND_TEXT,
    "file": {"properties": FILE_FIELDS},
    "host": KEYWORD,
    "id": KEYWORD,
    "original": KEYWORD_AND_TEXT,
    "type": KEYWORD,
    "user": KEYWORD,
}

AGENT_FIELDS: Final[MappingType] = {
    "id": KEYWORD,
    "type": KEYWORD,
    "version": KEYWORD,
}

ECS_FIELDS: Final[MappingType] = {"version": KEYWORD}

OBSERVER_FIELDS: Final[NestedMappingType] = {
    "geo": {"properties": GEO_FIELDS},
    "hostname": KEYWORD,
    "interface": {"properties": {"name": KEYWORD, "egress": {"properties": {"name": KEYWORD}}}},
    "ip": IP,
    "mac": KEYWORD,
    "os": {"properties": OS_FIELDS},
    "user": {"properties": USER_FIELDS},
}

BASE_FIELDS: Final[NestedMappingType] = {
    "@timestamp": DATE,
    "agent": {"properties": AGENT_FIELDS},
    "ecs": {"properties": ECS_FIELDS},
    "message": TEXT,
    "observer": {"properties": OBSERVER_FIELDS},
    "tags": KEYWORD,
}
UEFI_FILE_FIELD: Final[MappingType] = {
    # Define all Fields
    "type": KEYWORD,
    "subtype": KEYWORD,
    "base": KEYWORD,
    "size": KEYWORD,
    "crc32": KEYWORD,
    "guid": KEYWORD,
    "name": KEYWORD,
    "path": KEYWORD,
    "created": DATE,
}

UEFI_HASH_FIELD: Final[MappingType] = {
    "file_system": KEYWORD,
    "pathname": KEYWORD,
    "hash": KEYWORD,
}
BASIC_HOST_FIELDS: Final[NestedMappingType] = {
    "description": {"properties": DESCRIPTION_FIELDS},
    "hostname": KEYWORD,
    "id": KEYWORD,
    "ip": IP,
    "mac": KEYWORD,
    "mac_vendor": KEYWORD_AND_TEXT,
    "serial_port": KEYWORD,
    "name": KEYWORD,
    "label": KEYWORD,
    "comment": KEYWORD_AND_TEXT,
    "type": KEYWORD,
    "serial_number": KEYWORD,
    "slot": KEYWORD,
    "geo": {"properties": GEO_FIELDS},
    "asset": {"properties": ASSET_FIELDS},
    "tags": KEYWORD,  # ECS 9.5.0 "host.tags" (= asset.tags)
}

HOST_FIELDS: Final[NestedMappingType] = {
    "architecture": KEYWORD,
    "boot_firmware": {"properties": FIRMWARE_FIELDS},
    "description": {"properties": DESCRIPTION_FIELDS},
    "endian": KEYWORD,
    "firmware": {"properties": FIRMWARE_FIELDS},
    "hardware": {"properties": HARDWARE_FIELDS},
    "hostname": KEYWORD,
    "id": KEYWORD,
    "ip": IP,
    "mac": KEYWORD,
    "mac_vendor": KEYWORD_AND_TEXT,
    "serial_port": KEYWORD,
    "name": KEYWORD,
    "label": KEYWORD,
    "comment": KEYWORD_AND_TEXT,
    "part_number": KEYWORD,
    "type": KEYWORD,
    "serial_number": KEYWORD,
    "manufacturing_date": DATE,
    "run_mode": KEYWORD,
    "slot": KEYWORD,
    "start_time": DATE,
    "status": KEYWORD,
    "health": KEYWORD,
    "key_switch": KEYWORD,
    "uptime": LONG,
    "successful_pulls": FLATTENED,
    "os": {"properties": OS_FIELDS},
    "geo": {"properties": GEO_FIELDS},
    "asset": {"properties": ASSET_FIELDS},
    "clock": {"properties": CLOCK_FIELDS},
    "logic": {"properties": LOGIC_FIELDS},
    "iec61850": {"properties": IEC61850_FIELDS},
    "files": {"properties": FILE_FIELDS},
    "interface": {"properties": INTERFACE_FIELDS},
    "service": {"properties": SERVICE_FIELDS},
    "statistics": {"properties": NETWORK_STATISTICS_FIELDS},
    "protocol_statistics": {"properties": NETWORK_STATISTICS_FIELDS},
    "routes": {"properties": ROUTE_FIELDS},
    "ssh_keys": {"properties": SSHKEY_FIELDS},
    "processes": {"properties": HOST_PROCESS_FIELDS},
    "software": {"properties": PACKAGE_FIELDS},
    "indicators": {"properties": INDICATOR_FIELDS},
    "related": {"properties": RELATED_FIELDS},
    "registers": {"properties": REGISTER_FIELDS},
    "tag": {"properties": TAG_FIELDS},
    "io": {"properties": IO_FIELDS},
    "event": {"properties": HOST_EVENT_FIELDS},
    "memory": {"properties": MEMORY_FIELDS},
    "users": {"properties": USER_FIELDS},
    "x509": {"properties": X509_FIELDS},
    "extra": FLATTENED,
    "uefi_image": {"properties": UEFI_FILE_FIELD},
    "uefi_hashes": {"properties": UEFI_HASH_FIELD},
    # Derived in the host document only (not DeviceData fields).
    # "relationships" and "baseline_findings" have their own indices.
    "tags": KEYWORD,  # ECS 9.5.0 "host.tags" (= asset.tags)
    "indicator_states": FLATTENED,  # {indicator name: live state or value}
}

PROCESS_FIELDS: Final[NestedMappingType] = {
    "args": KEYWORD,
    "args_count": LONG,
    "command_line": KEYWORD_AND_TEXT,
    "executable": KEYWORD_AND_TEXT,
    "name": KEYWORD_AND_TEXT,
    "parent": {"properties": {"pid": LONG}},
    "pid": LONG,
    "start": DATE,
    "thread": {"properties": {"id": LONG, "name": KEYWORD}},
    "title": KEYWORD_AND_TEXT,
    "working_directory": KEYWORD_AND_TEXT,
}

# ECS "source.*" / "destination.*" subset of relationship documents
RELATIONSHIP_DOC_ENDPOINT_FIELDS: Final[MappingType] = {
    "address": KEYWORD,
    "ip": IP,
    "mac": KEYWORD,
    "port": LONG,
    "domain": KEYWORD,
    "bytes": LONG,
    "packets": LONG,
}

PARSE_RESULT: Final[dict[str, NestedMappingType]] = {
    "properties": {
        "name": KEYWORD,
        "path": KEYWORD,
        "module": KEYWORD,
        "results": {"properties": {**HOST_FIELDS, "module": {"properties": HOST_FIELDS}}},
    }
}


# -- PEAT index mappings --
PEAT_INDICES: Final[dict[str, dict]] = {
    "peat-logs": {
        "properties": {
            **BASE_FIELDS,
            "error": {"properties": ERROR_FIELDS},
            "event": {"properties": EVENT_FIELDS},
            "log": {
                "properties": {
                    "level": KEYWORD,
                    "logger": KEYWORD,
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
            **BASE_FIELDS,
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
            **BASE_FIELDS,
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
            **BASE_FIELDS,
            "peat_version": KEYWORD,
            "peat_run_id": KEYWORD,
            "parse_duration": DOUBLE,
            "parse_modules": KEYWORD,
            "input_paths": KEYWORD,
            "files_parsed": KEYWORD,
            "num_files_parsed": LONG,
            "num_parse_successes": LONG,
            "num_parse_failures": LONG,
            "parse_failures": PARSE_RESULT,
            "parse_results": PARSE_RESULT,
        }
    },
    "peat-configs": {
        "properties": {
            **BASE_FIELDS,
        }
    },
    "peat-state": {
        "properties": {
            **BASE_FIELDS,
        }
    },
    "ot-device-hosts-timeseries": {
        "properties": {
            **BASE_FIELDS,
            # Host documents are ECS asset documents ("event.kind: asset")
            "event": {"properties": EVENT_FIELDS},
            "host": {
                "properties": {
                    **HOST_FIELDS,
                    "module": {"properties": HOST_FIELDS},
                }
            },
        }
    },
    "ot-device-files": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
            "file": {"properties": FILE_FIELDS},
        }
    },
    "ot-device-registers": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
            "register": {"properties": REGISTER_FIELDS},
        }
    },
    "ot-device-tags": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
            "tag": {"properties": TAG_FIELDS},
        }
    },
    "ot-device-io": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
            "io": {"properties": IO_FIELDS},
        }
    },
    "ot-device-events": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
            "hash": {"properties": HASH_FIELDS},  # hashes of Event.original
            "log": {"properties": {"level": KEYWORD}},  # Event.log_level
        }
    },
    "ot-device-memory": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
            "memory": {"properties": MEMORY_FIELDS},
        }
    },
    "uefi-files": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
            "uefi": {"properties": UEFI_FILE_FIELD},
        }
    },
    "uefi-hashes": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
            "uefi": {"properties": UEFI_HASH_FIELD},
        }
    },
    "ot-device-relationships": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
            "relationship": {"properties": RELATIONSHIP_FIELDS},
            "network": {
                "properties": {
                    "protocol": KEYWORD,
                    "transport": KEYWORD,
                    "direction": KEYWORD,
                    "bytes": LONG,
                    "packets": LONG,
                    "vlan": {"properties": {"id": KEYWORD, "name": KEYWORD}},
                }
            },
            "source": {"properties": RELATIONSHIP_DOC_ENDPOINT_FIELDS},
            "destination": {"properties": RELATIONSHIP_DOC_ENDPOINT_FIELDS},
            "related": {"properties": RELATED_FIELDS},
        }
    },
    "ot-device-baseline-findings": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
            "rule": {"properties": RULE_FIELDS},
            "baseline": {"properties": BASELINE_DOC_FIELDS},
        }
    },
}
