import inspect
import io
import shutil
from pathlib import Path
from typing import Any, Literal, get_args

import pydantic

from peat import (
    DeviceData,
    DeviceError,
    IPMethod,
    PeatError,
    SerialMethod,
    config,
    consts,
    datastore,
    log,
    utils,
)
from peat.file_signature import FileSignature
from peat.module_protocol import (
    PROTOCOL_OPERATIONS,
    ModuleProtocol,
    normalize_protocol_name,
)


class DeviceModule:
    """
    Base class for all PEAT device modules.

    The methods of this class represent the core PEAT API, and should be
    implemented by all devices that inherit from it. Sub-classes may add
    their own device-specific methods and data structures as needed.
    """

    # This is used to dynamically set the "log" attribute on subclasses
    # to add the sub-class's name as metadata for the logger.
    # https://docs.python.org/3/reference/datamodel.html#object.__init_subclass__
    def __init_subclass__(cls, *args, **kwargs):
        super().__init_subclass__(*args, **kwargs)
        cls.log = log.bind(classname=cls.__name__, peat_module=cls.__name__)

    ip_methods: list[IPMethod] = []
    """
    Methods for identifying devices via IP or Ethernet.
    """

    serial_methods: list[SerialMethod] = []
    """
    Methods for identifying devices via a serial connection.
    """

    protocols: list[ModuleProtocol] = []
    """
    Protocols the module uses to pull from or push to devices.

    Protocols used to identify devices (scan) are derived automatically from
    ``ip_methods`` and ``serial_methods``, and don't need to be listed here.
    List every protocol used by ``_pull()`` and ``_push()``, including
    ones also used for scanning. For example, SELRelay pulls files via FTP,
    but doesn't use FTP to identify relays.

    If a module implements ``_pull()`` or ``_push()`` but doesn't declare any
    protocols for that operation, PEAT assumes the operation uses the module's
    scanning protocols.

    Query these with :meth:`get_protocols`, :meth:`get_ports`,
    and :meth:`get_protocol_details`.
    """

    device_type: str = ""
    """
    Type of device, e.g "PLC", "Relay", "RTU", "RTAC", etc.
    Elasticsearch field: ``host.type``.
    """

    vendor_id: str = ""
    """
    Short-form vendor name.
    Elasticsearch field: ``host.description.vendor.id``.
    """

    vendor_name: str = ""
    """
    Long-form vendor name.
    Elasticsearch field: ``host.description.vendor.name``.
    """

    brand: str = ""
    """
    Device brand.
    Elasticsearch field: ``host.description.brand``.
    """

    model: str = ""
    """
    Device's default model (if not known).
    Elasticsearch field: ``host.description.model``.
    """

    supported_models: list[str] = []
    """
    Device models this module supports or is known to work with.
    These are shown by ``--module-info`` and :meth:`get_capabilities`.
    """

    filename_patterns: list[str] = []
    """
    Patterns of files the module is capable of parsing, if any.
    Patterns are a literal name (``*SET_ALL.TXT``) or a Unix shell glob
    (``*.rdb``), are case-insensitive, and must start with a wildcard
    character (``*``). Globs can be anything accepted by :mod:`glob`.
    """

    file_signatures: list[FileSignature] = []
    """
    Signatures to determine if file data is parsable by this module,
    and what type of file it is, e.g. config vs log vs firmware.

    It uses a :class:`~peat.file_signature.FileSignature` object, which contains
    the expected or targeted filename as well as the associated signatures that
    must ALL match. The signatures can be magic bytes, XML tags, substrings, or
    a custom function (named or lambda) which receives the
    :class:`~typing.BinaryIO` to check and returns a True (matches) or False
    (does not match).
    """

    can_parse_dir: bool = False
    """
    If the module will accept a directory as the source path for parsing.
    If this is True, a Path like ``Path("./some_files/")`` would be a valid
    target for parsing. Any handling of files in the directory will have to
    be handled by the module, not PEAT.
    """

    module_aliases: list[str] = []
    """
    Alternative names for looking up the module, e.g. for the ``-d``
    :term:`CLI` option. Aliases that can be used to refer to the
    device via the PEAT's Module API (:mod:`peat.module_manager`).
    """

    annotate_fields: dict[str, Any] = {}
    """
    Fields that will be annotated (populated) by default for most operations,
    such as scan pull, parse, etc. Examples include known OS versions
    or hardware architecture. These fields will populated ONLY IF they are
    already unset on the device being annotated. Format is the path to the
    field to populate, e.g. ``os.name``, ``os.vendor.id``, etc.
    """

    default_options: dict[str, Any] = {}
    """
    Define module-specific options and/or override global defaults,
    such as default ports for protocols or default credentials.
    """

    @classmethod
    def pull(cls, dev: DeviceData) -> bool:
        """
        Pull artifacts from the device, such as logic, configuration, or firmware.

        This wraps and calls ``_pull()``. PEAT modules implementing the pull interface
        should implement ``_pull()``, instead of this method.

        Args:
            dev: existing :class:`~peat.data.models.DeviceData` object
                representing the device to pull from.

        Returns:
            If the pull was successful, as a bool

        Raises:
            DeviceError: If a critical error occurred
        """
        if not cls.method_implemented("_pull"):
            raise DeviceError(f"_pull() is not implemented by {cls.__name__}")

        if not isinstance(dev, DeviceData):
            raise DeviceError(f"dev has type '{type(dev)}', expected DeviceData")

        cls.log.info(f"Pulling from {dev.get_comm_id()}")

        result = cls._pull(dev)

        if not result:
            cls.log.debug(f"_pull() failed for {dev.get_comm_id()}")
            return False

        cls.log.info(f"Finished pulling from {dev.get_comm_id()}")

        cls.update_dev(dev)
        dev.purge_duplicates(force=True)
        return True

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        """
        Implemented by modules. Subclass :class:`~peat.device.DeviceModule`
        and override this method.
        """
        pass

    @classmethod
    def push(
        cls,
        dev: DeviceData,
        to_push: str | bytes | Path,
        push_type: consts.PushType,
    ) -> bool:
        """
        Upload (push) configuration or firmware to a device.

        This wraps and calls ``_push()``. PEAT modules implementing the push interface
        should implement ``_push()``, instead of this method.

        Args:
            dev: existing :class:`~peat.data.models.DeviceData` object
                representing the device to push to.
            to_push: the information to push, either as a Path object pointing
                to a file or directory with config files to upload, or a raw
                string or bytes of file to upload.
            push_type: What information is being pushed, either 'config' or 'firmware'.
                This comes from the ``-t`` command line argument.

        Returns:
            If the push was successful, as a bool

        Raises:
            DeviceError: If a critical error occurred
        """
        if not cls.method_implemented("_push"):
            raise DeviceError(f"_push() is not implemented by {cls.__name__}")

        if not isinstance(dev, DeviceData):
            raise DeviceError(f"dev has type '{type(dev)}', expected DeviceData")

        if push_type not in get_args(consts.PushType):
            raise DeviceError(
                f"Invalid '{push_type}' (supported types: {get_args(consts.PushType)})"
            )

        # if Path, ensure path exists
        if isinstance(to_push, Path):
            file = utils.check_file(to_push)
            if not file:
                cls.log.error(f"Push failed: '{to_push}' doesn't exist")
                return False
            to_push = file
            cls.log.debug(f"Loading push data from file '{file}'")

        cls.log.info(f"Pushing {push_type} to {dev.get_id()}")

        result = cls._push(dev, to_push, push_type)

        if not result:
            cls.log.error(f"{push_type.capitalize()} push to {dev.get_id()} failed")
            return False

        cls.log.info(f"{push_type.capitalize()} push to {dev.get_id()} was successful")
        return True

    @classmethod
    def _push(
        cls,
        dev: DeviceData,
        to_push: str | bytes | Path,
        push_type: consts.PushType,
    ) -> bool:
        """
        Implemented by modules. Subclass :class:`~peat.device.DeviceModule`
        and override this method.
        """
        pass

    @classmethod
    def parse(
        cls,
        to_parse: str | bytes | Path | io.IOBase,
        dev: DeviceData | None = None,
    ) -> DeviceData | None:
        """
        Parse device information from collected data or file artifacts.

        Args:
            to_parse: Data to be parsed. This can either be the
                :class:`~pathlib.Path` of a file or the raw data to parse.
            dev: existing :class:`~peat.data.models.DeviceData` object to
                use instead of the one created by the module

        Returns:
            Exported version of the parsed data object

        Raises:
            DeviceError: If a critical error occurred
        """
        if not cls.method_implemented("_parse"):
            raise DeviceError(f"_parse() is not implemented by {cls.__name__}")

        if dev is not None and not isinstance(dev, DeviceData):
            raise DeviceError(f"dev has type '{type(dev)}', expected DeviceData")

        if isinstance(to_parse, Path):
            file = to_parse.resolve()

            if not file.exists():
                cls.log.error(f"Parse failed: '{to_parse.as_posix()}' doesn't exist")
                return None

            cls.log.debug(f"Parsing data from {to_parse.as_posix()}")

            # Copy file or directory to temp dir
            if config.TEMP_DIR:
                if file.is_file():
                    utils.copy_file(file, config.TEMP_DIR / file.name)
                elif file.is_dir():
                    # NOTE: we allow directories for things like the SEL or the ION
                    tmp_path = config.TEMP_DIR / file.name
                    if tmp_path.exists():
                        shutil.rmtree(tmp_path)
                    shutil.copytree(file, tmp_path, dirs_exist_ok=True)
        else:
            # Treat file streams as raw data
            if isinstance(to_parse, (io.RawIOBase, io.StringIO)):
                cls.log.debug(f"Parsing data from file stream ({to_parse.__class__.__name__}")
                to_parse = to_parse.read()
            elif isinstance(to_parse, io.TextIOWrapper):  # Regular text file
                cls.log.debug("Parsing data from file buffer (TextIOWrapper)")
                to_parse = to_parse.buffer.read()  # Don't decode, read raw
            else:
                cls.log.debug(f"Parsing raw data with type '{to_parse.__class__.__name__}'")

            label = "raw-unparsed-data"
            ext = ""

            # NOTE: Use as initial check for naming
            # - Modules have existing uncovered pattern logic; wildcard names
            # - Modules need more signature data; uniqueness, greater coverage, etc.
            for pat in cls.filename_patterns:
                if label in pat and "." in pat:
                    ext = f".{pat.partition('.')[2]}"
                    break

            if ext and not ext.startswith("."):
                ext = f".{ext}"

            # Attempt to use signatures to label if no prior pattern matches
            # - Defaults to prior behavior if no signature match
            if label == "raw-unparsed-data" and not ext and cls.file_signatures:
                cls.log.debug("Signature checking data")
                for signature in cls.file_signatures:
                    if signature.matches(to_parse):
                        cls.log.debug("File signature match found, updating label.")
                        label = signature.default_filename
                        break

            file = config.TEMP_DIR / consts.sanitize_filename(f"{label}{ext}")

            # NOTE: `utils.write_file()` handles filename conflict type issues
            if not utils.write_file(data=to_parse, file=file):
                cls.log.error("Parse failed due to an error during file writing")
                return None

        # TODO: improve handling of empty files
        #   Example: if you pass a 0-byte apx file to M340._parse(),
        #   it will generate a bunch of boilerplate and say it's a M340,
        #   TC6 XML, etc. when really there's nothing there. In these cases,
        #   we really should just generate file metadata and return a device
        #   based on file name instead of passing it to the module for parsing.
        if file.is_file() and file.stat().st_size == 0:
            cls.log.warning(f"Input file '{file.name}' is empty, PEAT may behave strangely")
        # Check if directory is empty
        elif file.is_dir() and not list(file.iterdir()):
            raise DeviceError(f"Input directory is empty: {file}")

        # TODO: flesh out a single-device result and single file parse
        #  ION: parse multiple files to get one result
        #  ION, Sage, etc: multiple devices potentially present in one file
        parse_dev = cls._parse(file=file, dev=dev)

        if parse_dev is None:
            cls.log.debug("device.parse() failed, dev from _parse() is None")
            return None

        if not isinstance(parse_dev, DeviceData):
            raise DeviceError(
                f"_parse() returned object of invalid type '{type(parse_dev)}', "
                f"expected DeviceData. This is either a bug in the device module "
                f"or a bug in PEAT."
            )

        if parse_dev not in datastore.objects:
            cls.log.debug(f"Parsed device {parse_dev.get_id()} not in datastore, adding it now...")
            datastore.objects.append(parse_dev)

        cls.update_dev(parse_dev)

        # Ensure duplicates get purged since this is a fresh parse
        parse_dev.purge_duplicates(force=True)

        if config.DEVICE_DIR:
            parse_dev.export_to_files()

            if file.is_file():
                utils.move_file(config.TEMP_DIR / file.name, parse_dev.get_out_dir() / file.name)
            elif file.is_dir():
                # NOTE: we allow directories for things like the SEL or the ION
                shutil.move(
                    str(config.TEMP_DIR / file.name),
                    str(parse_dev.get_out_dir() / file.name),
                )

        return parse_dev

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:
        """
        Implemented by modules. Subclass :class:`~peat.device.DeviceModule`
        and override this method.
        """
        pass

    @classmethod
    def update_dev(cls, dev: DeviceData) -> None:
        """
        Update the device's data with metadata, inferences, and lookups.

        .. note::
           Data values are only changed if they're *unset*. In other words,
           existing values will NOT be overwritten.

        What's populated:

        - Basic Module attributes, e.g. ``cls.vendor_name => dev.description.vendor.name``.
        - Any Module-defined fields in ``cls.annotate_fields``, if present.
        - Calls :meth:`~peat.data.models.DeviceData.populate_fields`,
          which populates fields such as adding description values, network
          interfaces, and other values. This call will also implicitly lookup
          MAC addresses, IP addresses, and/or hostnames, unless
          disabled with the appropriate PEAT global configuration options.

        Args:
            dev: DeviceData instance to annotate.
        """
        # Annotate with the standard class fields (vendor info, etc.)
        if not dev.description.vendor.name:
            dev.description.vendor.name = cls.vendor_name
        if not dev.description.vendor.id:
            dev.description.vendor.id = cls.vendor_id
        if not dev.description.brand:
            dev.description.brand = cls.brand
        if not dev.description.model:
            dev.description.model = cls.model
        if not dev.type:
            dev.type = cls.device_type

        # Set the module
        if not dev._module:
            dev._module = cls
        elif dev._module != cls:
            cls.log.warning(f"Existing module {dev._module} != update_dev() module {cls}")

        # Add any module-defined fields
        if cls.annotate_fields:
            for field, value in cls.annotate_fields.items():
                # If the field isn't populated, then set it to the module's preferred value
                if not utils.rgetattr(dev, field):
                    utils.rsetattr(dev, field, value)

        # Fill in fields (inferences) and add common fields, like description.product
        dev.populate_fields()

    @classmethod
    def get_operations(cls) -> list[consts.OperationType]:
        """
        Operations PEAT can perform with this module.

        This uses the same checks as the scan, pull, push, and parse APIs:

        - ``scan``: the module has ``ip_methods`` or ``serial_methods``
        - ``pull``: it can scan, and ``_pull()`` is implemented
        - ``push``: it can scan, and ``_push()`` is implemented
        - ``parse``: ``_parse()`` is implemented, and the module has
          ``filename_patterns``, ``file_signatures``, or ``can_parse_dir``

        Returns:
            Supported operations, in the order scan, pull, push, parse
        """
        can_identify = bool(cls.ip_methods or cls.serial_methods)
        ops: list[consts.OperationType] = []

        if can_identify:
            ops.append("scan")
        if can_identify and cls.method_implemented("_pull"):
            ops.append("pull")
        if can_identify and cls.method_implemented("_push"):
            ops.append("push")
        if cls.method_implemented("_parse") and (
            cls.filename_patterns or cls.file_signatures or cls.can_parse_dir
        ):
            ops.append("parse")

        return ops

    @classmethod
    def supports(cls, operation: consts.OperationType) -> bool:
        """
        If the module supports an operation (``scan``, ``pull``, ``push``, or ``parse``).
        """
        return operation in cls.get_operations()

    @classmethod
    def get_comm_types(cls) -> list[consts.AllowedCommTypes]:
        """
        Communication types the module can use to identify devices.

        Returns:
            ``unicast_ip``, ``broadcast_ip``, and/or ``serial``, in that order
        """
        types = {m.type for m in cls.ip_methods}
        if cls.serial_methods:
            types.add("serial")
        return [t for t in get_args(consts.AllowedCommTypes) if t in types]

    @classmethod
    def get_method_names(cls, comm_type: consts.AllowedCommTypes | None = None) -> list[str]:
        """
        Names of the module's identification methods (``ip_methods`` and ``serial_methods``).

        Args:
            comm_type: Only include methods for this communication type
                (``unicast_ip``, ``broadcast_ip``, or ``serial``)

        Returns:
            Method names, in the order they're defined
        """
        names = [m.name for m in cls.ip_methods if comm_type in (None, m.type)]
        if comm_type in (None, "serial"):
            names.extend(m.name for m in cls.serial_methods)
        return names

    @classmethod
    def get_protocol_details(
        cls,
        operation: consts.ProtocolOperationType | None = None,
        comm_type: consts.AllowedCommTypes | None = None,
    ) -> list[ModuleProtocol]:
        """
        All protocols used by the module.

        Protocols from ``ip_methods`` and ``serial_methods`` (used for scanning)
        are merged with the declared :attr:`protocols`, resulting in one entry per
        protocol name and transport. If the module implements pull or push but
        doesn't declare protocols for it, the scanning protocols are assumed
        to be used for that operation. Names of protocols from ``ip_methods``
        and ``serial_methods`` are normalized with
        :func:`~peat.module_protocol.normalize_protocol_name`.

        Args:
            operation: Only include protocols used for this operation
                (``scan``, ``pull``, or ``push``)
            comm_type: Only include protocols used with this communication type
                (``unicast_ip``, ``broadcast_ip``, or ``serial``). For scanning,
                only the ``ip_methods`` of that type (or the ``serial_methods``)
                are used, e.g. a broadcast scan only uses ``broadcast_ip`` methods.
                For pull and push, ``serial`` only includes serial protocols,
                and ``unicast_ip`` and ``broadcast_ip`` only include
                network (non-serial) protocols.

        Returns:
            New :class:`~peat.module_protocol.ModuleProtocol` objects,
            sorted by name, then transport

        Raises:
            ValueError: If ``operation`` or ``comm_type`` is invalid
            PeatError: If the module's :attr:`protocols` are invalid
        """
        if operation is not None and operation not in PROTOCOL_OPERATIONS:
            raise ValueError(
                f"invalid operation '{operation}' (expected one of {PROTOCOL_OPERATIONS})"
            )
        if comm_type is not None and comm_type not in get_args(consts.AllowedCommTypes):
            raise ValueError(f"invalid comm_type '{comm_type}'")

        merged: dict[tuple[str, str], ModuleProtocol] = {}

        def _merge(proto: ModuleProtocol) -> None:
            key = (proto.name, proto.transport)
            if key not in merged:
                merged[key] = proto.copy(deep=True)  # Don't modify class attributes
                return
            existing = merged[key]
            # NOTE: validators sort and deduplicate ports and operations on assignment
            existing.ports = [*existing.ports, *proto.ports]
            existing.operations = [*existing.operations, *proto.operations]
            existing.description = existing.description or proto.description
            existing.options_key = existing.options_key or proto.options_key

        declared = cls._declared_protocols()

        # Modules (e.g. third-party modules) that implement pull or push
        # without declaring protocols for it are assumed to use the scan protocols.
        declared_ops = {op for p in declared for op in p.operations}
        inferred = [op for op in ("pull", "push") if op not in declared_ops and cls.supports(op)]

        if comm_type != "serial":
            for ip_meth in cls.ip_methods:
                # Methods of another IP comm type aren't used for this kind of
                # scan, but pull and push may still be assumed to use them.
                ops = ["scan"] if comm_type in (None, ip_meth.type) else []
                if ops or inferred:
                    _merge(
                        ModuleProtocol(
                            name=normalize_protocol_name(ip_meth.protocol),
                            transport=ip_meth.transport,
                            ports=[ip_meth.default_port],
                            operations=[*ops, *inferred],
                        )
                    )

        if comm_type in (None, "serial"):
            for serial_meth in cls.serial_methods:
                _merge(
                    ModuleProtocol(
                        name=normalize_protocol_name(serial_meth.protocol),
                        transport="serial",
                        operations=["scan", *inferred],
                    )
                )

        for proto in declared:
            if comm_type is not None and (proto.transport == "serial") != (comm_type == "serial"):
                continue
            if inferred and "scan" in proto.operations:
                proto = ModuleProtocol(
                    **{**proto.dict(), "operations": [*proto.operations, *inferred]}
                )
            _merge(proto)

        results = sorted(merged.values(), key=lambda p: (p.name, p.transport))
        if operation is not None:
            results = [p for p in results if operation in p.operations]

        return results

    @classmethod
    def _declared_protocols(cls) -> list[ModuleProtocol]:
        """
        The module's :attr:`protocols`, validated.

        Third-party modules may set :attr:`protocols` to dicts instead of
        :class:`~peat.module_protocol.ModuleProtocol` objects.

        Raises:
            PeatError: If a protocol is invalid
        """
        results = []
        for proto in cls.protocols:
            if isinstance(proto, ModuleProtocol):
                results.append(proto)
                continue
            try:
                results.append(ModuleProtocol.parse_obj(proto))
            except (pydantic.ValidationError, TypeError) as ex:
                raise PeatError(f"Invalid protocol in {cls.__name__}.protocols: {ex}") from None
        return results

    @classmethod
    def get_protocols(
        cls,
        operation: consts.ProtocolOperationType | None = None,
        comm_type: consts.AllowedCommTypes | None = None,
    ) -> list[str]:
        """
        Names of the protocols used by the module, e.g. ``["ftp", "http", "telnet"]``.

        Args:
            operation: Only include protocols used for this operation
                (``scan``, ``pull``, or ``push``)
            comm_type: Only include protocols used with this communication type
                (refer to :meth:`get_protocol_details`)

        Returns:
            Sorted unique protocol names
        """
        return sorted({p.name for p in cls.get_protocol_details(operation, comm_type)})

    @classmethod
    def get_ports(
        cls,
        operation: consts.ProtocolOperationType | None = None,
        transport: Literal["tcp", "udp"] | None = None,
    ) -> list[int]:
        """
        Default network ports used by the module.

        Args:
            operation: Only include ports used for this operation
                (``scan``, ``pull``, or ``push``)
            transport: Only include ports for this transport (``tcp`` or ``udp``).
                Protocols with a transport of ``both`` are included for either.

        Returns:
            Sorted unique port numbers
        """
        return sorted(
            {
                port
                for proto in cls.get_protocol_details(operation)
                if transport is None or transport in proto.transports
                for port in proto.ports
            }
        )

    @classmethod
    def get_capabilities(cls) -> dict[str, Any]:
        """
        Summary of the module's metadata and capabilities.

        This is used by ``--list-modules --json`` and ``--module-info``.
        Keys will only be added in the future, not changed or removed.

        Returns:
            JSON-serializable :class:`dict` with the module's capabilities
        """
        # NOTE: inspect.getdoc() would return the DeviceModule docstring
        # if the module doesn't have a docstring.
        doc = inspect.cleandoc(cls.__doc__) if cls.__doc__ else ""

        return {
            "name": cls.__name__,
            "description": doc.splitlines()[0] if doc else "",
            "python_module": cls.__module__,
            "device_type": cls.device_type,
            "vendor_id": cls.vendor_id,
            "vendor_name": cls.vendor_name,
            "brand": cls.brand,
            "model": cls.model,
            "supported_models": list(cls.supported_models),
            "module_aliases": list(cls.module_aliases),
            "operations": cls.get_operations(),
            "comm_types": cls.get_comm_types(),
            "protocols": [p.dict() for p in cls.get_protocol_details()],
            "ports": cls.get_ports(),
            "identify_methods": [
                *(
                    {
                        "name": m.name,
                        "type": m.type,
                        "protocol": m.protocol,
                        "transport": m.transport,
                        "default_port": m.default_port,
                        "reliability": m.reliability,
                    }
                    for m in cls.ip_methods
                ),
                *(
                    {
                        "name": m.name,
                        "type": "serial",
                        "protocol": m.protocol,
                        "transport": "serial",
                        "default_port": None,
                        "reliability": m.reliability,
                    }
                    for m in cls.serial_methods
                ),
            ],
            "parse": {
                "filename_patterns": list(cls.filename_patterns),
                "file_signatures": [s.default_filename for s in cls.file_signatures],
                "can_parse_dir": cls.can_parse_dir,
            },
        }

    @classmethod
    def method_implemented(cls, method_name: str) -> bool:
        """
        Checks if a method of a subclass of :class:`~peat.device.DeviceModule`
        is implemented and overrides the method in
        :class:`~peat.device.DeviceModule`).
        """
        return (
            getattr(cls, method_name).__code__ is not getattr(DeviceModule, method_name).__code__
        )


__all__ = ["DeviceModule"]
