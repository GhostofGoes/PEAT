import ipaddress
from typing import Any

from peat import log

from .data_utils import DeepChainMap, merge_models
from .models import DeviceData


class Datastore:
    """
    `Registry <https://martinfowler.com/eaaCatalog/registry.html>`__
    of :class:`~peat.data.models.DeviceData` instances.
    """

    objects: list[DeviceData] = None
    """:class:`~peat.data.models.DeviceData` instances in this datastore."""

    global_options: dict[str, Any] = None
    """
    Options that will be applied and used by all devices in this datastore.
    Changes to the values in this :class:`dict` will be reflected in the
    options of all devices in this datastore.
    """

    def __init__(self) -> None:
        self.objects = []
        self.global_options = {}
        self._data_obj: DeviceData | None = None

    def create(self, ident: str, ident_type: str) -> DeviceData:
        """
        Create a new :class:`~peat.data.models.DeviceData`
        instance, add it to the datastore, and return it.
        """
        dev_data = DeviceData(**{ident_type: ident})
        self.objects.append(dev_data)
        return dev_data

    def get(self, ident: str, ident_type: str = "ip") -> DeviceData:
        """
        Get a :class:`~peat.data.models.DeviceData` instance from the datastore.

        .. warning::
           If you want to search for an existing device and fail if one isn't found,
           then use :meth:`~peat.data.store.Datastore.search` instead.

        .. code-block:: python
           :caption: Examples of ``datastore.get()``

           >>> from pprint import pprint
           >>> from peat import SCEPTRE, datastore

           >>> device = datastore.get("192.0.2.20")
           >>> device.ip
           '192.0.2.20'

           >>> device = datastore.get("192.0.2.123")  # doctest: +SKIP
           >>> SCEPTRE.pull(device)  # doctest: +SKIP
           >>> pprint(device.export())  # doctest: +SKIP
           >>> parsed_name = "relay_1"  # Name extracted from the pulled config
           >>> device = datastore.get(parsed_name, "name")  # doctest: +SKIP
           >>> device.data.name == parsed_name  # doctest: +SKIP
           True

        Args:
            ident: Identifier to search for, such as ``192.168.0.1``
            ident_type: What ``ident`` is, e.g. ``"serial_port"`` or ``"ip"``

        Returns:
            The :class:`~peat.data.models.DeviceData` object found or a new
            object if there wasn't a device found that matched the arguments.
        """
        dev = self.search(ident, ident_type)

        if dev:
            return dev

        return self.create(ident, ident_type)

    def search(self, ident: str, ident_type: str) -> DeviceData | None:
        """
        Search for the device with a given identifier.

        Example: During passive scanning a device was initialized with a MAC
        which gets resolved to a IP. Later during active scanning, we want
        to add information to the device. We can look it up by it's IP,
        even if it was originally added to the datastore using it's MAC.

        Args:
            ident: Identifier to search for, such as ``192.168.0.1``
            ident_type: What ``ident`` is, e.g. ``"serial_port"`` or ``"ip"``

        Returns:
            The :class:`~peat.data.models.DeviceData` found or
            :obj:`None` if the search failed
        """
        for obj in self.objects:
            if getattr(obj, ident_type, None) == ident:
                return obj

        return None

    def remove(self, to_remove: DeviceData) -> bool:
        """
        Remove a device from the datastore.

        Args:
            to_remove: :class:`~peat.data.models.DeviceData` instance to remove

        Returns:
            If the device was successfully found and removed
        """
        for i in range(len(self.objects)):
            if self.objects[i] is to_remove:
                del self.objects[i]
                return True

        return False

    def prune_inactive(self) -> None:
        """Remove inactive devices from the datastore (``dev._is_active == False``)."""
        if not self.objects:
            return

        inactive_devs = [x for x in self.objects if not x._is_active]

        for dev in inactive_devs:
            self.remove(dev)

        log.debug(f"Pruned {len(inactive_devs)} inactive devices from datastore")

    def deduplicate(self, prune_inactive: bool = True) -> None:
        """
        Cleanup duplicate devices in the datastore.

        Duplicates are only merged if they have the same IP, MAC or serial port,
        or if they're communication modules in the same ControlLogix chassis
        (same CPU serial number).

        If the duplicates have different IPs (multiple communication modules
        on one device), then the one with the lowest IP address is used as the
        primary, and each module's IP, MAC, interfaces, and services are
        stored in the matching entry in ``module``. Otherwise, the first
        duplicate in the datastore is used as the primary.

        Any duplicates found are merged into a single
        :class:`~peat.data.models.DeviceData` object,
        and the additional copies are removed from the list of objects.

        Args:
            prune_inactive: If inactive devices should be removed before
              beginning deduplication
        """
        if not self.objects:
            return

        if prune_inactive:
            self.prune_inactive()

        # Only log at INFO level if there are enough objects to possibly make it lag
        msg = f"Searching for duplicates in {len(self.objects)} objects..."
        if len(self.objects) > 2:
            log.info(msg)
        else:
            log.debug(msg)

        for obj in self.objects:
            obj.purge_duplicates()

        deduped = []  # type: list[DeviceData]
        grouped = set()  # type: set[int]
        num_removed = 0

        for obj in self.objects:
            # Object was already merged into another object
            if id(obj) in grouped:
                continue

            group = self._find_duplicates(obj, grouped)
            if len(group) == 1:
                deduped.append(obj)
                continue

            # When the duplicates have different IPs, they're different
            # communication modules on the same device (e.g. a ControlLogix
            # with a EWEB and a EN2TR). The order of objects depends on the
            # order devices responded, so sort to make the result deterministic.
            multi_module = len({d.ip for d in group if d.ip}) > 1
            if multi_module:
                group = sorted(group, key=_primary_sort_key)
            primary = group[0]

            for comp in group[1:]:
                log.info(f"Merging duplicate {comp.get_id()} into {primary.get_id()}")

                if multi_module:
                    self._merge_comm_module(primary, comp)

                # TODO: copy/merge stuff other than the data, e.g. options?
                # TODO: delete duplicate timeseries document from Elasticsearch
                # Merge in data from the duplicate
                merge_models(primary, comp)
                primary._is_deduplicated = False

                # Purge any new duplicates from the now-merged object
                primary.purge_duplicates()
                num_removed += 1

            deduped.append(primary)

        self.objects = deduped  # Replace objects list with de-duped objects

        log.debug(
            f"Finished deduplicating objects, {num_removed} duplicates were merged and removed"
        )

    def _find_duplicates(self, obj: DeviceData, grouped: set[int]) -> list[DeviceData]:
        """
        Find all objects that are duplicates of ``obj``, including duplicates
        of those duplicates (e.g. a match by IP, then another match by MAC).

        Returns:
            ``obj`` and its duplicates, in datastore order. The IDs of all
            objects in the group are added to ``grouped``.
        """
        group = [obj]
        grouped.add(id(obj))

        i = 0
        while i < len(group):
            for comp in self.objects:
                if id(comp) not in grouped and group[i].is_duplicate(comp):
                    group.append(comp)
                    grouped.add(id(comp))
            i += 1

        # Keep datastore order, so the first object seen remains the primary
        # when all of the duplicates share the same IP.
        order = {id(o): i for i, o in enumerate(self.objects)}
        group.sort(key=lambda o: order[id(o)])

        return group

    @staticmethod
    def _merge_comm_module(primary: DeviceData, secondary: DeviceData) -> None:
        """
        Prepare to merge data from a device's secondary communication module.

        The network identity of each communication module (IP, MAC, interfaces,
        services, HTTP and FTP data) is added to that module's entry in
        ``module``, and removed from the top level of ``secondary``, so it isn't
        mixed in with the data of the primary communication module.
        """
        primary.annotate_comm_module()
        secondary_mod = secondary.annotate_comm_module()
        if not secondary_mod:
            return

        if secondary.ip:
            primary.related.ip.add(secondary.ip)
        if secondary.mac:
            primary.related.mac.add(secondary.mac)

        for key in list(secondary.extra.keys()):
            if key.startswith(("http_", "ftp_")):
                secondary_mod.extra[key] = secondary.extra.pop(key)
        secondary.extra.pop("comm_module_serial", None)

        secondary.ip = ""
        secondary.mac = ""
        secondary.mac_vendor = ""
        secondary.service = []

    @property
    def verified(self) -> list[DeviceData]:
        """Devices that have been verified (``dev._is_verified == True``)."""
        return [d for d in self.objects if d._is_verified]

    @property
    def device_options(self) -> DeepChainMap:
        """
        Get global options with module defaults and injects applied.

        This is a hack, to be sure, but refactoring will take more time than it's worth.
        """
        if not self._data_obj:
            self._data_obj = DeviceData()

        return self._data_obj._options


def _primary_sort_key(dev: DeviceData) -> tuple:
    """
    Sort key for picking the primary device when merging communication
    modules, which is the one with the lowest IP address.
    """
    if not dev.ip:
        return (2, 0, 0, "")
    try:
        addr = ipaddress.ip_address(dev.ip)
    except ValueError:
        return (1, 0, 0, dev.ip)
    return (0, addr.version, int(addr), dev.ip)


#: Global singleton for managing :class:`~peat.data.models.DeviceData`
#: instances and making them available throughout PEAT.
datastore = Datastore()


__all__ = ["Datastore", "datastore"]
