# Synthetic RTAC export with engineering access

This is NOT a real RTAC project export. It was written by hand for the tests of
the RTAC engineering access discovery (`tests/modules/sel/test_sel_rtac_engineering_access.py`),
because none of the public exports in this directory have an access point router,
a SEL server or a SEL device. All of the names, addresses and ports are made up
(the IP addresses are from the documentation ranges of RFC 5737, and the MAC
addresses from the documentation range of RFC 7042).

The format of the files is the format of the public exports in this directory
(e.g. `Access Points/BansheeUDP_AP.xml` in `ephcc-microgrid-rtac.tar.gz`), and of
the access point routers that `peat.modules.sel.rtac_parse.parse_accesspointrouters`
reads. The setting names and the example values (access points `EA_Transparent`
on SSH port 8001 and `EA_Direct` on Telnet port 9001, the destinations
`Feeder_1_SEL_TAP` and `Feeder_1_SEL_AP`, and a SEL server on port 3254 with
Virtual Port Number 254 and the Termination String `<CTRL-D>`) are from these
public SEL documents:

- SEL HD2014-34, "SEL-3530 RTAC Hands-On Session", Engineering Access Exercise
- SEL LWP0018-01, "Leveraging Security - Using the SEL RTAC's Built-In Security
  Features", Section 5

Things that are guesses and need to be checked against a real export:

- The protocol names of SEL devices and SEL servers (`SELClient`, `SELServer`) and
  the connection types (`Serial`, `Ethernet`, `Ethernet Tunneled Serial`).
- How an access point router names its endpoints. `EA_Transparent_APR` has the
  device, protocol and type of its destination in separate elements
  (`Feeder_1`, `SEL`, `TAP`), `EA_Direct_APR` has the name of the destination
  access point (`Feeder_1_SEL_AP`), and `EA_Raw_APR` has the source and
  destination the other way around (like the router in the tests of the export
  parser).
- Where a serial SEL device has its serial port number.

| File | What it is |
| ---- | ---------- |
| `SEL_RTAC/Advanced Read-in Items/Ethernet Settings.xml` | Two Ethernet interfaces (the RTAC is 192.0.2.10) |
| `SEL_RTAC/Access Points/EA_Transparent.xml` | Access point, SSH, port 8001 |
| `SEL_RTAC/Access Points/EA_Direct.xml` | Access point, Telnet, port 9001 |
| `SEL_RTAC/Access Points/EA_Raw.xml` | Access point, Raw TCP, port 9002 |
| `SEL_RTAC/Access Points/Logic_UDP.xml` | Access point, UDP Incoming, port 7300, no router |
| `SEL_RTAC/Access Point Routers/EA_Transparent_APR.xml` | `EA_Transparent` to `Feeder_1` (transparent, interleaved) |
| `SEL_RTAC/Access Point Routers/EA_Direct_APR.xml` | `EA_Direct` to `Feeder_1` (direct transparent) |
| `SEL_RTAC/Access Point Routers/EA_Raw_APR.xml` | `EA_Raw` to `Feeder_2` (transparent, interleaved) |
| `SEL_RTAC/Devices/Feeder_1.xml` | Serial SEL device, Virtual Port Number 1 |
| `SEL_RTAC/Devices/Feeder_2.xml` | Ethernet SEL device, Virtual Port Number 63 |
| `SEL_RTAC/Devices/Remote_Access_Server.xml` | SEL server, SSL/TLS, port 3254, with authentication |
| `SEL_RTAC/Devices/SCADA_DNP.xml` | DNP3 server over TLS (not engineering access) |
