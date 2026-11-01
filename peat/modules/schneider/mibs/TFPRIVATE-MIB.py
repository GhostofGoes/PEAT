# SNMP MIB module (TFPRIVATE-MIB) expressed in pysnmp data model.
#
# This Python module is designed to be imported and executed by the
# pysnmp library.
#
# See https://www.pysnmp.com/pysnmp for further information.
#
# Notes
# -----
# ASN.1 source: Schneider Electric "SchneiderTFE_V03.01.mib" (ASN.1 module
#   TFPRIVATE-MIB, "Schneider Transparent Ready PRIVATE MIB Release 03.01",
#   Symphony document 31005306_K14000 version 09), from the archive
#   "MIB Files_08705.zip" (se.com document reference "MIB_Modicon_Switch").
#   sha256(SchneiderTFE_V03.01.mib) =
#     c1f89c133b9eccb4a0204d2301a039bfbb4ed8fa84405ab53eddf4b9e3f65782
#   sha256(MIB Files_08705.zip) =
#     9cfbae4d729bed173a15a3b2ac4e1f509575f0003671c47d4a2be547ae3bca53
# Produced by pysmi-1.4.3 (pysmi-lextudio) WITHOUT MIB texts (no
#   --generate-mib-texts), so only object names, OIDs, types and enumerations
#   are included. The .mib source file is intentionally not committed to PEAT.
# Do not hand-edit: regenerate using the instructions in the
#   "Using vendor SNMP MIBs" section of docs/module_developer_guide.rst.

if 'mibBuilder' not in globals():
    import sys

    sys.stderr.write(__doc__)
    sys.exit(1)

# Import base ASN.1 objects even if this MIB does not use it

(Integer,
 OctetString,
 ObjectIdentifier) = mibBuilder.importSymbols(
    "ASN1",
    "Integer",
    "OctetString",
    "ObjectIdentifier")

(NamedValues,) = mibBuilder.importSymbols(
    "ASN1-ENUMERATION",
    "NamedValues")
(ConstraintsIntersection,
 SingleValueConstraint,
 ValueRangeConstraint,
 ValueSizeConstraint,
 ConstraintsUnion) = mibBuilder.importSymbols(
    "ASN1-REFINEMENT",
    "ConstraintsIntersection",
    "SingleValueConstraint",
    "ValueRangeConstraint",
    "ValueSizeConstraint",
    "ConstraintsUnion")

# Import SMI symbols from the MIBs this MIB depends on

(NotificationGroup,
 ModuleCompliance) = mibBuilder.importSymbols(
    "SNMPv2-CONF",
    "NotificationGroup",
    "ModuleCompliance")

(enterprises,
 Counter32,
 Counter64,
 MibIdentifier,
 NotificationType,
 Integer32,
 Gauge32,
 IpAddress,
 iso,
 Bits,
 ModuleIdentity,
 Unsigned32,
 MibScalar,
 MibTable,
 MibTableRow,
 MibTableColumn,
 TimeTicks,
 ObjectIdentity) = mibBuilder.importSymbols(
    "SNMPv2-SMI",
    "enterprises",
    "Counter32",
    "Counter64",
    "MibIdentifier",
    "NotificationType",
    "Integer32",
    "Gauge32",
    "IpAddress",
    "iso",
    "Bits",
    "ModuleIdentity",
    "Unsigned32",
    "MibScalar",
    "MibTable",
    "MibTableRow",
    "MibTableColumn",
    "TimeTicks",
    "ObjectIdentity")

(PhysAddress,
 DisplayString,
 TextualConvention) = mibBuilder.importSymbols(
    "SNMPv2-TC",
    "PhysAddress",
    "DisplayString",
    "TextualConvention")


# MODULE-IDENTITY

transparentFactoryEthernet = ModuleIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1)
)
transparentFactoryEthernet.setRevisions(
        ("2010-09-29 12:00",)
)


# Types definitions


# TEXTUAL-CONVENTIONS



# MIB Managed Objects in the order of their OIDs

_Schneiderelectric_ObjectIdentity = ObjectIdentity
schneiderelectric = _Schneiderelectric_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833)
)
_Port502Messaging_ObjectIdentity = ObjectIdentity
port502Messaging = _Port502Messaging_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2)
)
_Port502MessagingV2_ObjectIdentity = ObjectIdentity
port502MessagingV2 = _Port502MessagingV2_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 0)
)
if mibBuilder.loadTexts:
    port502MessagingV2.setStatus("current")


class _Port502Status_Type(Integer32):
    """Custom type port502Status based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("idle", 1),
          ("operationnal", 2))
    )


_Port502Status_Type.__name__ = "Integer32"
_Port502Status_Object = MibScalar
port502Status = _Port502Status_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 1),
    _Port502Status_Type()
)
port502Status.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502Status.setStatus("current")


class _Port502SupportedProtocol_Type(Integer32):
    """Custom type port502SupportedProtocol based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2,
              4,
              5,
              6)
        )
    )
    namedValues = NamedValues(
        *(("modbusDirect", 2),
          ("modbusDirectAndUnite", 6),
          ("modbusThroughGateway", 1),
          ("modbusThroughGatewayAndUnite", 5),
          ("unite", 4))
    )


_Port502SupportedProtocol_Type.__name__ = "Integer32"
_Port502SupportedProtocol_Object = MibScalar
port502SupportedProtocol = _Port502SupportedProtocol_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 2),
    _Port502SupportedProtocol_Type()
)
port502SupportedProtocol.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502SupportedProtocol.setStatus("current")


class _Port502IpSecurity_Type(Integer32):
    """Custom type port502IpSecurity based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("disabled", 1),
          ("enabled", 2))
    )


_Port502IpSecurity_Type.__name__ = "Integer32"
_Port502IpSecurity_Object = MibScalar
port502IpSecurity = _Port502IpSecurity_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 3),
    _Port502IpSecurity_Type()
)
port502IpSecurity.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502IpSecurity.setStatus("current")


class _Port502MaxConn_Type(Integer32):
    """Custom type port502MaxConn based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 63),
    )


_Port502MaxConn_Type.__name__ = "Integer32"
_Port502MaxConn_Object = MibScalar
port502MaxConn = _Port502MaxConn_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 4),
    _Port502MaxConn_Type()
)
port502MaxConn.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502MaxConn.setStatus("current")


class _Port502LocalConn_Type(Integer32):
    """Custom type port502LocalConn based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 63),
    )


_Port502LocalConn_Type.__name__ = "Integer32"
_Port502LocalConn_Object = MibScalar
port502LocalConn = _Port502LocalConn_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 5),
    _Port502LocalConn_Type()
)
port502LocalConn.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502LocalConn.setStatus("current")


class _Port502RemConn_Type(Integer32):
    """Custom type port502RemConn based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 63),
    )


_Port502RemConn_Type.__name__ = "Integer32"
_Port502RemConn_Object = MibScalar
port502RemConn = _Port502RemConn_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 6),
    _Port502RemConn_Type()
)
port502RemConn.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502RemConn.setStatus("current")
_Port502IpSecurityTable_Object = MibTable
port502IpSecurityTable = _Port502IpSecurityTable_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 7)
)
if mibBuilder.loadTexts:
    port502IpSecurityTable.setStatus("current")
_Port502IpSecurityEntry_Object = MibTableRow
port502IpSecurityEntry = _Port502IpSecurityEntry_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 7, 1)
)
port502IpSecurityEntry.setIndexNames(
    (0, "TFPRIVATE-MIB", "ipSourceAddress"),
)
if mibBuilder.loadTexts:
    port502IpSecurityEntry.setStatus("current")
_AttemptFails_Type = Counter32
_AttemptFails_Object = MibTableColumn
attemptFails = _AttemptFails_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 7, 1, 1),
    _AttemptFails_Type()
)
attemptFails.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    attemptFails.setStatus("current")
_IpSourceAddress_Type = IpAddress
_IpSourceAddress_Object = MibTableColumn
ipSourceAddress = _IpSourceAddress_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 7, 1, 2),
    _IpSourceAddress_Type()
)
ipSourceAddress.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipSourceAddress.setStatus("current")
_Port502ConnTable_Object = MibTable
port502ConnTable = _Port502ConnTable_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 8)
)
if mibBuilder.loadTexts:
    port502ConnTable.setStatus("current")
_Port502ConnEntry_Object = MibTableRow
port502ConnEntry = _Port502ConnEntry_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 8, 1)
)
port502ConnEntry.setIndexNames(
    (0, "TFPRIVATE-MIB", "port502ConnLocalPort"),
    (0, "TFPRIVATE-MIB", "port502ConnRemAddress"),
    (0, "TFPRIVATE-MIB", "port502ConnRemPort"),
    (0, "TFPRIVATE-MIB", "port502XwayNet"),
    (0, "TFPRIVATE-MIB", "port502XwayStation"),
)
if mibBuilder.loadTexts:
    port502ConnEntry.setStatus("current")


class _Port502ConnLocalPort_Type(Integer32):
    """Custom type port502ConnLocalPort based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(512, 3071),
    )


_Port502ConnLocalPort_Type.__name__ = "Integer32"
_Port502ConnLocalPort_Object = MibTableColumn
port502ConnLocalPort = _Port502ConnLocalPort_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 8, 1, 1),
    _Port502ConnLocalPort_Type()
)
port502ConnLocalPort.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502ConnLocalPort.setStatus("current")
_Port502ConnRemAddress_Type = IpAddress
_Port502ConnRemAddress_Object = MibTableColumn
port502ConnRemAddress = _Port502ConnRemAddress_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 8, 1, 2),
    _Port502ConnRemAddress_Type()
)
port502ConnRemAddress.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502ConnRemAddress.setStatus("current")


class _Port502ConnRemPort_Type(Integer32):
    """Custom type port502ConnRemPort based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 65535),
    )


_Port502ConnRemPort_Type.__name__ = "Integer32"
_Port502ConnRemPort_Object = MibTableColumn
port502ConnRemPort = _Port502ConnRemPort_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 8, 1, 3),
    _Port502ConnRemPort_Type()
)
port502ConnRemPort.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502ConnRemPort.setStatus("current")


class _Port502ConnType_Type(Integer32):
    """Custom type port502ConnType based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("local", 1),
          ("remote", 2))
    )


_Port502ConnType_Type.__name__ = "Integer32"
_Port502ConnType_Object = MibTableColumn
port502ConnType = _Port502ConnType_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 8, 1, 4),
    _Port502ConnType_Type()
)
port502ConnType.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502ConnType.setStatus("current")
_Port502ConnMsgIn_Type = Counter32
_Port502ConnMsgIn_Object = MibTableColumn
port502ConnMsgIn = _Port502ConnMsgIn_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 8, 1, 5),
    _Port502ConnMsgIn_Type()
)
port502ConnMsgIn.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502ConnMsgIn.setStatus("current")
_Port502ConnMsgOut_Type = Counter32
_Port502ConnMsgOut_Object = MibTableColumn
port502ConnMsgOut = _Port502ConnMsgOut_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 8, 1, 6),
    _Port502ConnMsgOut_Type()
)
port502ConnMsgOut.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502ConnMsgOut.setStatus("current")
_Port502ConnMsgErr_Type = Counter32
_Port502ConnMsgErr_Object = MibTableColumn
port502ConnMsgErr = _Port502ConnMsgErr_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 8, 1, 7),
    _Port502ConnMsgErr_Type()
)
port502ConnMsgErr.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502ConnMsgErr.setStatus("current")


class _Port502XwayNet_Type(Integer32):
    """Custom type port502XwayNet based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 127),
    )


_Port502XwayNet_Type.__name__ = "Integer32"
_Port502XwayNet_Object = MibTableColumn
port502XwayNet = _Port502XwayNet_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 8, 1, 8),
    _Port502XwayNet_Type()
)
port502XwayNet.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502XwayNet.setStatus("current")


class _Port502XwayStation_Type(Integer32):
    """Custom type port502XwayStation based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 63),
    )


_Port502XwayStation_Type.__name__ = "Integer32"
_Port502XwayStation_Object = MibTableColumn
port502XwayStation = _Port502XwayStation_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 8, 1, 9),
    _Port502XwayStation_Type()
)
port502XwayStation.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502XwayStation.setStatus("current")
_Port502MsgIn_Type = Counter32
_Port502MsgIn_Object = MibScalar
port502MsgIn = _Port502MsgIn_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 9),
    _Port502MsgIn_Type()
)
port502MsgIn.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502MsgIn.setStatus("current")
_Port502MsgOut_Type = Counter32
_Port502MsgOut_Object = MibScalar
port502MsgOut = _Port502MsgOut_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 10),
    _Port502MsgOut_Type()
)
port502MsgOut.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502MsgOut.setStatus("current")
_Port502MsgOutErr_Type = Counter32
_Port502MsgOutErr_Object = MibScalar
port502MsgOutErr = _Port502MsgOutErr_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 11),
    _Port502MsgOutErr_Type()
)
port502MsgOutErr.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502MsgOutErr.setStatus("current")


class _Port502AddStackStat_Type(Integer32):
    """Custom type port502AddStackStat based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("disabled", 1),
          ("enabled", 2))
    )


_Port502AddStackStat_Type.__name__ = "Integer32"
_Port502AddStackStat_Object = MibScalar
port502AddStackStat = _Port502AddStackStat_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 12),
    _Port502AddStackStat_Type()
)
port502AddStackStat.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502AddStackStat.setStatus("current")
_Port502AddStackStatTable_Object = MibTable
port502AddStackStatTable = _Port502AddStackStatTable_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 13)
)
if mibBuilder.loadTexts:
    port502AddStackStatTable.setStatus("current")
_Port502AddStackStatEntry_Object = MibTableRow
port502AddStackStatEntry = _Port502AddStackStatEntry_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 13, 1)
)
port502AddStackStatEntry.setIndexNames(
    (0, "TFPRIVATE-MIB", "port502AddStackStatIndex"),
)
if mibBuilder.loadTexts:
    port502AddStackStatEntry.setStatus("current")


class _Port502AddStackStatIndex_Type(Integer32):
    """Custom type port502AddStackStatIndex based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 0),
    )


_Port502AddStackStatIndex_Type.__name__ = "Integer32"
_Port502AddStackStatIndex_Object = MibTableColumn
port502AddStackStatIndex = _Port502AddStackStatIndex_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 13, 1, 1),
    _Port502AddStackStatIndex_Type()
)
port502AddStackStatIndex.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502AddStackStatIndex.setStatus("current")


class _Port502PeaKTcpRetransSegs_Type(Integer32):
    """Custom type port502PeaKTcpRetransSegs based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 2147483647),
    )


_Port502PeaKTcpRetransSegs_Type.__name__ = "Integer32"
_Port502PeaKTcpRetransSegs_Object = MibTableColumn
port502PeaKTcpRetransSegs = _Port502PeaKTcpRetransSegs_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 13, 1, 2),
    _Port502PeaKTcpRetransSegs_Type()
)
port502PeaKTcpRetransSegs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502PeaKTcpRetransSegs.setStatus("current")
_IoScanning_ObjectIdentity = ObjectIdentity
ioScanning = _IoScanning_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 3)
)
_IoScanningV2_ObjectIdentity = ObjectIdentity
ioScanningV2 = _IoScanningV2_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 3, 0)
)
if mibBuilder.loadTexts:
    ioScanningV2.setStatus("current")


class _IoScanStatus_Type(Integer32):
    """Custom type ioScanStatus based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2,
              3)
        )
    )
    namedValues = NamedValues(
        *(("idle", 1),
          ("operationnal", 2),
          ("stopped", 3))
    )


_IoScanStatus_Type.__name__ = "Integer32"
_IoScanStatus_Object = MibScalar
ioScanStatus = _IoScanStatus_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 3, 1),
    _IoScanStatus_Type()
)
ioScanStatus.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ioScanStatus.setStatus("current")


class _IoScanMaxDevice_Type(Integer32):
    """Custom type ioScanMaxDevice based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 63),
    )


_IoScanMaxDevice_Type.__name__ = "Integer32"
_IoScanMaxDevice_Object = MibScalar
ioScanMaxDevice = _IoScanMaxDevice_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 3, 2),
    _IoScanMaxDevice_Type()
)
ioScanMaxDevice.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ioScanMaxDevice.setStatus("current")


class _IoScanPolledDevice_Type(Integer32):
    """Custom type ioScanPolledDevice based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 63),
    )


_IoScanPolledDevice_Type.__name__ = "Integer32"
_IoScanPolledDevice_Object = MibScalar
ioScanPolledDevice = _IoScanPolledDevice_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 3, 3),
    _IoScanPolledDevice_Type()
)
ioScanPolledDevice.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ioScanPolledDevice.setStatus("current")
_IoScanTransSend_Type = Counter32
_IoScanTransSend_Object = MibScalar
ioScanTransSend = _IoScanTransSend_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 3, 4),
    _IoScanTransSend_Type()
)
ioScanTransSend.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ioScanTransSend.setStatus("current")


class _IoScanGlbHealth_Type(Integer32):
    """Custom type ioScanGlbHealth based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(2,
              4)
        )
    )
    namedValues = NamedValues(
        *(("ok", 2),
          ("warning", 4))
    )


_IoScanGlbHealth_Type.__name__ = "Integer32"
_IoScanGlbHealth_Object = MibScalar
ioScanGlbHealth = _IoScanGlbHealth_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 3, 5),
    _IoScanGlbHealth_Type()
)
ioScanGlbHealth.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ioScanGlbHealth.setStatus("current")
_IoScanDeviceTable_Object = MibTable
ioScanDeviceTable = _IoScanDeviceTable_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 3, 6)
)
if mibBuilder.loadTexts:
    ioScanDeviceTable.setStatus("current")
_IoScanDeviceEntry_Object = MibTableRow
ioScanDeviceEntry = _IoScanDeviceEntry_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 3, 6, 1)
)
ioScanDeviceEntry.setIndexNames(
    (0, "TFPRIVATE-MIB", "ioScanDeviceRemAddress"),
)
if mibBuilder.loadTexts:
    ioScanDeviceEntry.setStatus("current")
_IoScanDeviceRemAddress_Type = IpAddress
_IoScanDeviceRemAddress_Object = MibTableColumn
ioScanDeviceRemAddress = _IoScanDeviceRemAddress_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 3, 6, 1, 1),
    _IoScanDeviceRemAddress_Type()
)
ioScanDeviceRemAddress.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ioScanDeviceRemAddress.setStatus("current")


class _IoScanDeviceHealth_Type(Integer32):
    """Custom type ioScanDeviceHealth based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("nok", 1),
          ("ok", 2))
    )


_IoScanDeviceHealth_Type.__name__ = "Integer32"
_IoScanDeviceHealth_Object = MibTableColumn
ioScanDeviceHealth = _IoScanDeviceHealth_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 3, 6, 1, 2),
    _IoScanDeviceHealth_Type()
)
ioScanDeviceHealth.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ioScanDeviceHealth.setStatus("current")
_IoScanDeviceRate_Type = Integer32
_IoScanDeviceRate_Object = MibTableColumn
ioScanDeviceRate = _IoScanDeviceRate_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 3, 6, 1, 3),
    _IoScanDeviceRate_Type()
)
ioScanDeviceRate.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ioScanDeviceRate.setStatus("current")
_IoScanInputLocalAddress_Type = Integer32
_IoScanInputLocalAddress_Object = MibTableColumn
ioScanInputLocalAddress = _IoScanInputLocalAddress_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 3, 6, 1, 4),
    _IoScanInputLocalAddress_Type()
)
ioScanInputLocalAddress.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ioScanInputLocalAddress.setStatus("current")
_IoScanOutputLocalAddress_Type = Integer32
_IoScanOutputLocalAddress_Object = MibTableColumn
ioScanOutputLocalAddress = _IoScanOutputLocalAddress_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 3, 6, 1, 5),
    _IoScanOutputLocalAddress_Type()
)
ioScanOutputLocalAddress.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ioScanOutputLocalAddress.setStatus("current")
_GlobalData_ObjectIdentity = ObjectIdentity
globalData = _GlobalData_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4)
)
_GlobalDataV2_ObjectIdentity = ObjectIdentity
globalDataV2 = _GlobalDataV2_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 0)
)
if mibBuilder.loadTexts:
    globalDataV2.setStatus("current")


class _GlbDataStatus_Type(Integer32):
    """Custom type glbDataStatus based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2,
              3)
        )
    )
    namedValues = NamedValues(
        *(("idle", 1),
          ("operationnal", 2),
          ("stopped", 3))
    )


_GlbDataStatus_Type.__name__ = "Integer32"
_GlbDataStatus_Object = MibScalar
glbDataStatus = _GlbDataStatus_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 1),
    _GlbDataStatus_Type()
)
glbDataStatus.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataStatus.setStatus("current")


class _GlbDataMaxPub_Type(Integer32):
    """Custom type glbDataMaxPub based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 127),
    )


_GlbDataMaxPub_Type.__name__ = "Integer32"
_GlbDataMaxPub_Object = MibScalar
glbDataMaxPub = _GlbDataMaxPub_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 2),
    _GlbDataMaxPub_Type()
)
glbDataMaxPub.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataMaxPub.setStatus("current")


class _GlbDataMaxSub_Type(Integer32):
    """Custom type glbDataMaxSub based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 127),
    )


_GlbDataMaxSub_Type.__name__ = "Integer32"
_GlbDataMaxSub_Object = MibScalar
glbDataMaxSub = _GlbDataMaxSub_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 3),
    _GlbDataMaxSub_Type()
)
glbDataMaxSub.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataMaxSub.setStatus("current")
_GlbDataPub_Type = Counter32
_GlbDataPub_Object = MibScalar
glbDataPub = _GlbDataPub_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 4),
    _GlbDataPub_Type()
)
glbDataPub.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataPub.setStatus("current")
_GlbDataSub_Type = Counter32
_GlbDataSub_Object = MibScalar
glbDataSub = _GlbDataSub_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 5),
    _GlbDataSub_Type()
)
glbDataSub.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataSub.setStatus("current")
_GlbDataPubErr_Type = Counter32
_GlbDataPubErr_Object = MibScalar
glbDataPubErr = _GlbDataPubErr_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 6),
    _GlbDataPubErr_Type()
)
glbDataPubErr.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataPubErr.setStatus("current")
_GlbDataSubErr_Type = Counter32
_GlbDataSubErr_Object = MibScalar
glbDataSubErr = _GlbDataSubErr_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 7),
    _GlbDataSubErr_Type()
)
glbDataSubErr.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataSubErr.setStatus("current")


class _GlbDataGlbSubHealth_Type(Integer32):
    """Custom type glbDataGlbSubHealth based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(2,
              4)
        )
    )
    namedValues = NamedValues(
        *(("ok", 2),
          ("warning", 4))
    )


_GlbDataGlbSubHealth_Type.__name__ = "Integer32"
_GlbDataGlbSubHealth_Object = MibScalar
glbDataGlbSubHealth = _GlbDataGlbSubHealth_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 8),
    _GlbDataGlbSubHealth_Type()
)
glbDataGlbSubHealth.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataGlbSubHealth.setStatus("current")
_GlbDataPubTable_Object = MibTable
glbDataPubTable = _GlbDataPubTable_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 9)
)
if mibBuilder.loadTexts:
    glbDataPubTable.setStatus("current")
_GlbDataPubEntry_Object = MibTableRow
glbDataPubEntry = _GlbDataPubEntry_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 9, 1)
)
glbDataPubEntry.setIndexNames(
    (0, "TFPRIVATE-MIB", "glbDataPubGroupId"),
    (0, "TFPRIVATE-MIB", "glbDataPubNetId"),
)
if mibBuilder.loadTexts:
    glbDataPubEntry.setStatus("current")
_GlbDataPubSourceAddress_Type = IpAddress
_GlbDataPubSourceAddress_Object = MibTableColumn
glbDataPubSourceAddress = _GlbDataPubSourceAddress_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 9, 1, 1),
    _GlbDataPubSourceAddress_Type()
)
glbDataPubSourceAddress.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataPubSourceAddress.setStatus("current")


class _GlbDataPubHostId_Type(Integer32):
    """Custom type glbDataPubHostId based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 63),
    )


_GlbDataPubHostId_Type.__name__ = "Integer32"
_GlbDataPubHostId_Object = MibTableColumn
glbDataPubHostId = _GlbDataPubHostId_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 9, 1, 2),
    _GlbDataPubHostId_Type()
)
glbDataPubHostId.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataPubHostId.setStatus("current")


class _GlbDataPubNetId_Type(DisplayString):
    """Custom type glbDataPubNetId based on DisplayString"""
    subtypeSpec = DisplayString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(0, 31),
    )


_GlbDataPubNetId_Type.__name__ = "DisplayString"
_GlbDataPubNetId_Object = MibTableColumn
glbDataPubNetId = _GlbDataPubNetId_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 9, 1, 3),
    _GlbDataPubNetId_Type()
)
glbDataPubNetId.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataPubNetId.setStatus("current")
_GlbDataPubGroupId_Type = IpAddress
_GlbDataPubGroupId_Object = MibTableColumn
glbDataPubGroupId = _GlbDataPubGroupId_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 9, 1, 4),
    _GlbDataPubGroupId_Type()
)
glbDataPubGroupId.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataPubGroupId.setStatus("current")
_GlbDataPubCnt_Type = Counter32
_GlbDataPubCnt_Object = MibTableColumn
glbDataPubCnt = _GlbDataPubCnt_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 9, 1, 5),
    _GlbDataPubCnt_Type()
)
glbDataPubCnt.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataPubCnt.setStatus("current")
_GlbDataPubErrCnt_Type = Counter32
_GlbDataPubErrCnt_Object = MibTableColumn
glbDataPubErrCnt = _GlbDataPubErrCnt_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 9, 1, 6),
    _GlbDataPubErrCnt_Type()
)
glbDataPubErrCnt.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataPubErrCnt.setStatus("current")
_GlbDataPubDistribRate_Type = Integer32
_GlbDataPubDistribRate_Object = MibTableColumn
glbDataPubDistribRate = _GlbDataPubDistribRate_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 9, 1, 7),
    _GlbDataPubDistribRate_Type()
)
glbDataPubDistribRate.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataPubDistribRate.setStatus("current")


class _GlbDataPubDuplicateErr_Type(Integer32):
    """Custom type glbDataPubDuplicateErr based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("off", 2),
          ("on", 1))
    )


_GlbDataPubDuplicateErr_Type.__name__ = "Integer32"
_GlbDataPubDuplicateErr_Object = MibTableColumn
glbDataPubDuplicateErr = _GlbDataPubDuplicateErr_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 9, 1, 8),
    _GlbDataPubDuplicateErr_Type()
)
glbDataPubDuplicateErr.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataPubDuplicateErr.setStatus("current")
_GlbDataSubTable_Object = MibTable
glbDataSubTable = _GlbDataSubTable_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 10)
)
if mibBuilder.loadTexts:
    glbDataSubTable.setStatus("current")
_GlbDataSubEntry_Object = MibTableRow
glbDataSubEntry = _GlbDataSubEntry_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 10, 1)
)
glbDataSubEntry.setIndexNames(
    (0, "TFPRIVATE-MIB", "glbDataSubGroupId"),
    (0, "TFPRIVATE-MIB", "glbDataSubNetId"),
)
if mibBuilder.loadTexts:
    glbDataSubEntry.setStatus("current")
_GlbDataSubSourceAddress_Type = IpAddress
_GlbDataSubSourceAddress_Object = MibTableColumn
glbDataSubSourceAddress = _GlbDataSubSourceAddress_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 10, 1, 1),
    _GlbDataSubSourceAddress_Type()
)
glbDataSubSourceAddress.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataSubSourceAddress.setStatus("current")


class _GlbDataSubHostId_Type(Integer32):
    """Custom type glbDataSubHostId based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 63),
    )


_GlbDataSubHostId_Type.__name__ = "Integer32"
_GlbDataSubHostId_Object = MibTableColumn
glbDataSubHostId = _GlbDataSubHostId_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 10, 1, 2),
    _GlbDataSubHostId_Type()
)
glbDataSubHostId.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataSubHostId.setStatus("current")


class _GlbDataSubNetId_Type(DisplayString):
    """Custom type glbDataSubNetId based on DisplayString"""
    subtypeSpec = DisplayString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(0, 31),
    )


_GlbDataSubNetId_Type.__name__ = "DisplayString"
_GlbDataSubNetId_Object = MibTableColumn
glbDataSubNetId = _GlbDataSubNetId_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 10, 1, 3),
    _GlbDataSubNetId_Type()
)
glbDataSubNetId.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataSubNetId.setStatus("current")
_GlbDataSubGroupId_Type = IpAddress
_GlbDataSubGroupId_Object = MibTableColumn
glbDataSubGroupId = _GlbDataSubGroupId_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 10, 1, 4),
    _GlbDataSubGroupId_Type()
)
glbDataSubGroupId.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataSubGroupId.setStatus("current")
_GlbDataSubCnt_Type = Counter32
_GlbDataSubCnt_Object = MibTableColumn
glbDataSubCnt = _GlbDataSubCnt_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 10, 1, 5),
    _GlbDataSubCnt_Type()
)
glbDataSubCnt.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataSubCnt.setStatus("current")
_GlbDataSubErrCnt_Type = Counter32
_GlbDataSubErrCnt_Object = MibTableColumn
glbDataSubErrCnt = _GlbDataSubErrCnt_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 10, 1, 6),
    _GlbDataSubErrCnt_Type()
)
glbDataSubErrCnt.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataSubErrCnt.setStatus("current")
_GlbDataMinimumSeparation_Type = Integer32
_GlbDataMinimumSeparation_Object = MibTableColumn
glbDataMinimumSeparation = _GlbDataMinimumSeparation_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 10, 1, 7),
    _GlbDataMinimumSeparation_Type()
)
glbDataMinimumSeparation.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataMinimumSeparation.setStatus("current")


class _GlbDataHealth_Type(Integer32):
    """Custom type glbDataHealth based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("nok", 1),
          ("ok", 2))
    )


_GlbDataHealth_Type.__name__ = "Integer32"
_GlbDataHealth_Object = MibTableColumn
glbDataHealth = _GlbDataHealth_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 10, 1, 8),
    _GlbDataHealth_Type()
)
glbDataHealth.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataHealth.setStatus("current")
_GlbDataHealthTimeOut_Type = Integer32
_GlbDataHealthTimeOut_Object = MibTableColumn
glbDataHealthTimeOut = _GlbDataHealthTimeOut_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 10, 1, 9),
    _GlbDataHealthTimeOut_Type()
)
glbDataHealthTimeOut.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataHealthTimeOut.setStatus("current")


class _GlbDataLastRecErr_Type(Integer32):
    """Custom type glbDataLastRecErr based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2,
              3,
              4,
              255)
        )
    )
    namedValues = NamedValues(
        *(("deserialization-error", 4),
          ("never-received-data", 1),
          ("no-new-data", 2),
          ("undefined", 255),
          ("update-old-data", 3))
    )


_GlbDataLastRecErr_Type.__name__ = "Integer32"
_GlbDataLastRecErr_Object = MibTableColumn
glbDataLastRecErr = _GlbDataLastRecErr_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 10, 1, 10),
    _GlbDataLastRecErr_Type()
)
glbDataLastRecErr.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    glbDataLastRecErr.setStatus("current")
_Web_ObjectIdentity = ObjectIdentity
web = _Web_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 5)
)
_WebV2_ObjectIdentity = ObjectIdentity
webV2 = _WebV2_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 5, 0)
)
if mibBuilder.loadTexts:
    webV2.setStatus("current")


class _WebStatus_Type(Integer32):
    """Custom type webStatus based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("idle", 1),
          ("operationnal", 2))
    )


_WebStatus_Type.__name__ = "Integer32"
_WebStatus_Object = MibScalar
webStatus = _WebStatus_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 5, 1),
    _WebStatus_Type()
)
webStatus.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    webStatus.setStatus("current")


class _WebPassword_Type(Integer32):
    """Custom type webPassword based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("disabled", 1),
          ("enabled", 2))
    )


_WebPassword_Type.__name__ = "Integer32"
_WebPassword_Object = MibScalar
webPassword = _WebPassword_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 5, 2),
    _WebPassword_Type()
)
webPassword.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    webPassword.setStatus("current")
_WebSuccessfullAccess_Type = Counter32
_WebSuccessfullAccess_Object = MibScalar
webSuccessfullAccess = _WebSuccessfullAccess_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 5, 3),
    _WebSuccessfullAccess_Type()
)
webSuccessfullAccess.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    webSuccessfullAccess.setStatus("current")
_WebFailedAttempts_Type = Counter32
_WebFailedAttempts_Object = MibScalar
webFailedAttempts = _WebFailedAttempts_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 5, 4),
    _WebFailedAttempts_Type()
)
webFailedAttempts.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    webFailedAttempts.setStatus("current")
_AddressServer_ObjectIdentity = ObjectIdentity
addressServer = _AddressServer_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 6)
)
_AddressServerV2_ObjectIdentity = ObjectIdentity
addressServerV2 = _AddressServerV2_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 6, 0)
)
if mibBuilder.loadTexts:
    addressServerV2.setStatus("current")


class _AddressServerStatus_Type(Integer32):
    """Custom type addressServerStatus based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("idle", 1),
          ("operationnal", 2))
    )


_AddressServerStatus_Type.__name__ = "Integer32"
_AddressServerStatus_Object = MibScalar
addressServerStatus = _AddressServerStatus_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 6, 1),
    _AddressServerStatus_Type()
)
addressServerStatus.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    addressServerStatus.setStatus("current")
_EquipmentProfile_ObjectIdentity = ObjectIdentity
equipmentProfile = _EquipmentProfile_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7)
)
_EquipmentProfileV2_ObjectIdentity = ObjectIdentity
equipmentProfileV2 = _EquipmentProfileV2_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 0)
)
if mibBuilder.loadTexts:
    equipmentProfileV2.setStatus("current")


class _ProfileProductName_Type(DisplayString):
    """Custom type profileProductName based on DisplayString"""
    subtypeSpec = DisplayString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(0, 255),
    )


_ProfileProductName_Type.__name__ = "DisplayString"
_ProfileProductName_Object = MibScalar
profileProductName = _ProfileProductName_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 1),
    _ProfileProductName_Type()
)
profileProductName.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    profileProductName.setStatus("current")


class _ProfileVersion_Type(DisplayString):
    """Custom type profileVersion based on DisplayString"""
    subtypeSpec = DisplayString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(0, 255),
    )


_ProfileVersion_Type.__name__ = "DisplayString"
_ProfileVersion_Object = MibScalar
profileVersion = _ProfileVersion_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 2),
    _ProfileVersion_Type()
)
profileVersion.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    profileVersion.setStatus("current")
_ProfileCommunicationServices_Type = Integer32
_ProfileCommunicationServices_Object = MibScalar
profileCommunicationServices = _ProfileCommunicationServices_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 3),
    _ProfileCommunicationServices_Type()
)
profileCommunicationServices.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    profileCommunicationServices.setStatus("current")


class _ProfileGlobalStatus_Type(Integer32):
    """Custom type profileGlobalStatus based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("nok", 1),
          ("ok", 2))
    )


_ProfileGlobalStatus_Type.__name__ = "Integer32"
_ProfileGlobalStatus_Object = MibScalar
profileGlobalStatus = _ProfileGlobalStatus_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 4),
    _ProfileGlobalStatus_Type()
)
profileGlobalStatus.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    profileGlobalStatus.setStatus("current")


class _ProfileIpConfigMode_Type(Integer32):
    """Custom type profileIpConfigMode based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("dhcpServed", 2),
          ("local", 1))
    )


_ProfileIpConfigMode_Type.__name__ = "Integer32"
_ProfileIpConfigMode_Object = MibScalar
profileIpConfigMode = _ProfileIpConfigMode_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 5),
    _ProfileIpConfigMode_Type()
)
profileIpConfigMode.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    profileIpConfigMode.setStatus("current")


class _ProfileRoleName_Type(DisplayString):
    """Custom type profileRoleName based on DisplayString"""
    subtypeSpec = DisplayString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(1, 16),
    )


_ProfileRoleName_Type.__name__ = "DisplayString"
_ProfileRoleName_Object = MibScalar
profileRoleName = _ProfileRoleName_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 6),
    _ProfileRoleName_Type()
)
profileRoleName.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    profileRoleName.setStatus("current")


class _ProfileBandwidthMgt_Type(Integer32):
    """Custom type profileBandwidthMgt based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("disabled", 1),
          ("enabled", 2))
    )


_ProfileBandwidthMgt_Type.__name__ = "Integer32"
_ProfileBandwidthMgt_Object = MibScalar
profileBandwidthMgt = _ProfileBandwidthMgt_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 7),
    _ProfileBandwidthMgt_Type()
)
profileBandwidthMgt.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    profileBandwidthMgt.setStatus("current")
_ProfileBandwidthDistTable_Object = MibTable
profileBandwidthDistTable = _ProfileBandwidthDistTable_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 8)
)
if mibBuilder.loadTexts:
    profileBandwidthDistTable.setStatus("current")
_ProfileBandwidthDistEntry_Object = MibTableRow
profileBandwidthDistEntry = _ProfileBandwidthDistEntry_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 8, 1)
)
profileBandwidthDistEntry.setIndexNames(
    (0, "TFPRIVATE-MIB", "bandwidthDistributionIndex"),
)
if mibBuilder.loadTexts:
    profileBandwidthDistEntry.setStatus("current")


class _BandwidthDistributionIndex_Type(Integer32):
    """Custom type bandwidthDistributionIndex based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 0),
    )


_BandwidthDistributionIndex_Type.__name__ = "Integer32"
_BandwidthDistributionIndex_Object = MibTableColumn
bandwidthDistributionIndex = _BandwidthDistributionIndex_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 8, 1, 1),
    _BandwidthDistributionIndex_Type()
)
bandwidthDistributionIndex.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    bandwidthDistributionIndex.setStatus("current")
_Port502Bandwidth_Type = Integer32
_Port502Bandwidth_Object = MibTableColumn
port502Bandwidth = _Port502Bandwidth_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 8, 1, 2),
    _Port502Bandwidth_Type()
)
port502Bandwidth.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    port502Bandwidth.setStatus("current")
_IoScanningBandwidth_Type = Integer32
_IoScanningBandwidth_Object = MibTableColumn
ioScanningBandwidth = _IoScanningBandwidth_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 8, 1, 3),
    _IoScanningBandwidth_Type()
)
ioScanningBandwidth.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ioScanningBandwidth.setStatus("current")
_GlobalDataBandwidth_Type = Integer32
_GlobalDataBandwidth_Object = MibTableColumn
globalDataBandwidth = _GlobalDataBandwidth_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 8, 1, 4),
    _GlobalDataBandwidth_Type()
)
globalDataBandwidth.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    globalDataBandwidth.setStatus("current")
_OtherBandwidth_Type = Integer32
_OtherBandwidth_Object = MibTableColumn
otherBandwidth = _OtherBandwidth_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 8, 1, 5),
    _OtherBandwidth_Type()
)
otherBandwidth.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    otherBandwidth.setStatus("current")
_ProfileLedDisplayTable_Object = MibTable
profileLedDisplayTable = _ProfileLedDisplayTable_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 9)
)
if mibBuilder.loadTexts:
    profileLedDisplayTable.setStatus("current")
_ProfileLedDisplayEntry_Object = MibTableRow
profileLedDisplayEntry = _ProfileLedDisplayEntry_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 9, 1)
)
profileLedDisplayEntry.setIndexNames(
    (0, "TFPRIVATE-MIB", "ledIndex"),
)
if mibBuilder.loadTexts:
    profileLedDisplayEntry.setStatus("current")


class _LedIndex_Type(Integer32):
    """Custom type ledIndex based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 15),
    )


_LedIndex_Type.__name__ = "Integer32"
_LedIndex_Object = MibTableColumn
ledIndex = _LedIndex_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 9, 1, 1),
    _LedIndex_Type()
)
ledIndex.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ledIndex.setStatus("current")


class _LedName_Type(DisplayString):
    """Custom type ledName based on DisplayString"""
    subtypeSpec = DisplayString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(0, 255),
    )


_LedName_Type.__name__ = "DisplayString"
_LedName_Object = MibTableColumn
ledName = _LedName_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 9, 1, 2),
    _LedName_Type()
)
ledName.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ledName.setStatus("current")


class _LedDescr_Type(DisplayString):
    """Custom type ledDescr based on DisplayString"""
    subtypeSpec = DisplayString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(0, 64),
    )


_LedDescr_Type.__name__ = "DisplayString"
_LedDescr_Object = MibTableColumn
ledDescr = _LedDescr_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 9, 1, 3),
    _LedDescr_Type()
)
ledDescr.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ledDescr.setStatus("current")


class _LedState_Type(Integer32):
    """Custom type ledState based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2,
              3)
        )
    )
    namedValues = NamedValues(
        *(("blinking", 3),
          ("off", 2),
          ("on", 1))
    )


_LedState_Type.__name__ = "Integer32"
_LedState_Object = MibTableColumn
ledState = _LedState_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 9, 1, 4),
    _LedState_Type()
)
ledState.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ledState.setStatus("current")
_ProfileSlot_Type = Integer32
_ProfileSlot_Object = MibScalar
profileSlot = _ProfileSlot_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 10),
    _ProfileSlot_Type()
)
profileSlot.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    profileSlot.setStatus("current")


class _ProfileCPUType_Type(DisplayString):
    """Custom type profileCPUType based on DisplayString"""
    subtypeSpec = DisplayString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(0, 255),
    )


_ProfileCPUType_Type.__name__ = "DisplayString"
_ProfileCPUType_Object = MibScalar
profileCPUType = _ProfileCPUType_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 11),
    _ProfileCPUType_Type()
)
profileCPUType.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    profileCPUType.setStatus("current")


class _ProfileTrapTableEntriesMax_Type(Integer32):
    """Custom type profileTrapTableEntriesMax based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(1, 2),
    )


_ProfileTrapTableEntriesMax_Type.__name__ = "Integer32"
_ProfileTrapTableEntriesMax_Object = MibScalar
profileTrapTableEntriesMax = _ProfileTrapTableEntriesMax_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 12),
    _ProfileTrapTableEntriesMax_Type()
)
profileTrapTableEntriesMax.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    profileTrapTableEntriesMax.setStatus("current")
_ProfileTrapTable_Object = MibTable
profileTrapTable = _ProfileTrapTable_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 13)
)
if mibBuilder.loadTexts:
    profileTrapTable.setStatus("current")
_ProfileTrapEntry_Object = MibTableRow
profileTrapEntry = _ProfileTrapEntry_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 13, 1)
)
profileTrapEntry.setIndexNames(
    (0, "TFPRIVATE-MIB", "remoteIpAddress"),
)
if mibBuilder.loadTexts:
    profileTrapEntry.setStatus("current")


class _TrapCommunityName_Type(DisplayString):
    """Custom type trapCommunityName based on DisplayString"""
    subtypeSpec = DisplayString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(1, 16),
    )


_TrapCommunityName_Type.__name__ = "DisplayString"
_TrapCommunityName_Object = MibTableColumn
trapCommunityName = _TrapCommunityName_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 13, 1, 1),
    _TrapCommunityName_Type()
)
trapCommunityName.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    trapCommunityName.setStatus("current")
_RemoteIpAddress_Type = IpAddress
_RemoteIpAddress_Object = MibTableColumn
remoteIpAddress = _RemoteIpAddress_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 13, 1, 2),
    _RemoteIpAddress_Type()
)
remoteIpAddress.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    remoteIpAddress.setStatus("current")


class _AuthenticationTrap_Type(Integer32):
    """Custom type authenticationTrap based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("disable", 1),
          ("enable", 2))
    )


_AuthenticationTrap_Type.__name__ = "Integer32"
_AuthenticationTrap_Object = MibTableColumn
authenticationTrap = _AuthenticationTrap_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 13, 1, 3),
    _AuthenticationTrap_Type()
)
authenticationTrap.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    authenticationTrap.setStatus("current")


class _Port502Trap_Type(Integer32):
    """Custom type port502Trap based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("disable", 1),
          ("enable", 2))
    )


_Port502Trap_Type.__name__ = "Integer32"
_Port502Trap_Object = MibTableColumn
port502Trap = _Port502Trap_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 13, 1, 4),
    _Port502Trap_Type()
)
port502Trap.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    port502Trap.setStatus("current")


class _IoScanningTrap_Type(Integer32):
    """Custom type ioScanningTrap based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("disable", 1),
          ("enable", 2))
    )


_IoScanningTrap_Type.__name__ = "Integer32"
_IoScanningTrap_Object = MibTableColumn
ioScanningTrap = _IoScanningTrap_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 13, 1, 5),
    _IoScanningTrap_Type()
)
ioScanningTrap.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ioScanningTrap.setStatus("current")


class _GlobalDataTrap_Type(Integer32):
    """Custom type globalDataTrap based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("disable", 1),
          ("enable", 2))
    )


_GlobalDataTrap_Type.__name__ = "Integer32"
_GlobalDataTrap_Object = MibTableColumn
globalDataTrap = _GlobalDataTrap_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 13, 1, 6),
    _GlobalDataTrap_Type()
)
globalDataTrap.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    globalDataTrap.setStatus("current")


class _WebTrap_Type(Integer32):
    """Custom type webTrap based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("disable", 1),
          ("enable", 2))
    )


_WebTrap_Type.__name__ = "Integer32"
_WebTrap_Object = MibTableColumn
webTrap = _WebTrap_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 13, 1, 7),
    _WebTrap_Type()
)
webTrap.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    webTrap.setStatus("current")


class _AddressServerTrap_Type(Integer32):
    """Custom type addressServerTrap based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("disable", 1),
          ("enable", 2))
    )


_AddressServerTrap_Type.__name__ = "Integer32"
_AddressServerTrap_Object = MibTableColumn
addressServerTrap = _AddressServerTrap_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 13, 1, 8),
    _AddressServerTrap_Type()
)
addressServerTrap.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    addressServerTrap.setStatus("current")


class _ProfileTrap_Type(Integer32):
    """Custom type profileTrap based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("disable", 1),
          ("enable", 2))
    )


_ProfileTrap_Type.__name__ = "Integer32"
_ProfileTrap_Object = MibTableColumn
profileTrap = _ProfileTrap_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 13, 1, 9),
    _ProfileTrap_Type()
)
profileTrap.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    profileTrap.setStatus("current")


class _TimeManagementTrap_Type(Integer32):
    """Custom type timeManagementTrap based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("disable", 1),
          ("enable", 2))
    )


_TimeManagementTrap_Type.__name__ = "Integer32"
_TimeManagementTrap_Object = MibTableColumn
timeManagementTrap = _TimeManagementTrap_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 13, 1, 10),
    _TimeManagementTrap_Type()
)
timeManagementTrap.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    timeManagementTrap.setStatus("current")


class _EmailTrap_Type(Integer32):
    """Custom type emailTrap based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("disable", 1),
          ("enable", 2))
    )


_EmailTrap_Type.__name__ = "Integer32"
_EmailTrap_Object = MibTableColumn
emailTrap = _EmailTrap_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 13, 1, 11),
    _EmailTrap_Type()
)
emailTrap.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    emailTrap.setStatus("current")
_ProfileSpecificId_Type = ObjectIdentifier
_ProfileSpecificId_Object = MibScalar
profileSpecificId = _ProfileSpecificId_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 14),
    _ProfileSpecificId_Type()
)
profileSpecificId.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    profileSpecificId.setStatus("current")
_ProfileIpAddress_Type = IpAddress
_ProfileIpAddress_Object = MibScalar
profileIpAddress = _ProfileIpAddress_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 15),
    _ProfileIpAddress_Type()
)
profileIpAddress.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    profileIpAddress.setStatus("current")
_ProfileIpNetMask_Type = IpAddress
_ProfileIpNetMask_Object = MibScalar
profileIpNetMask = _ProfileIpNetMask_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 16),
    _ProfileIpNetMask_Type()
)
profileIpNetMask.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    profileIpNetMask.setStatus("current")
_ProfileIpGateway_Type = IpAddress
_ProfileIpGateway_Object = MibScalar
profileIpGateway = _ProfileIpGateway_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 17),
    _ProfileIpGateway_Type()
)
profileIpGateway.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    profileIpGateway.setStatus("current")
_ProfileMacAddress_Type = PhysAddress
_ProfileMacAddress_Object = MibScalar
profileMacAddress = _ProfileMacAddress_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 18),
    _ProfileMacAddress_Type()
)
profileMacAddress.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    profileMacAddress.setStatus("current")


class _ProfileImplementationClass_Type(DisplayString):
    """Custom type profileImplementationClass based on DisplayString"""
    subtypeSpec = DisplayString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(1, 16),
    )


_ProfileImplementationClass_Type.__name__ = "DisplayString"
_ProfileImplementationClass_Object = MibScalar
profileImplementationClass = _ProfileImplementationClass_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 19),
    _ProfileImplementationClass_Type()
)
profileImplementationClass.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    profileImplementationClass.setStatus("current")
_PremiumProfile_ObjectIdentity = ObjectIdentity
premiumProfile = _PremiumProfile_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 100)
)
_QuantumProfile_ObjectIdentity = ObjectIdentity
quantumProfile = _QuantumProfile_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 101)
)
_Qnoe_ObjectIdentity = ObjectIdentity
qnoe = _Qnoe_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 101, 100)
)


class _QNoeCommand_Type(Integer32):
    """Custom type qNoeCommand based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("noCmd", 1),
          ("reset", 2))
    )


_QNoeCommand_Type.__name__ = "Integer32"
_QNoeCommand_Object = MibScalar
qNoeCommand = _QNoeCommand_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 101, 100, 1),
    _QNoeCommand_Type()
)
qNoeCommand.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    qNoeCommand.setStatus("current")
_MicroProfile_ObjectIdentity = ObjectIdentity
microProfile = _MicroProfile_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 102)
)
_MEtz_ObjectIdentity = ObjectIdentity
mEtz = _MEtz_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 102, 100)
)
_EtzIpMgtStatus_Type = Integer32
_EtzIpMgtStatus_Object = MibScalar
etzIpMgtStatus = _EtzIpMgtStatus_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 102, 100, 1),
    _EtzIpMgtStatus_Type()
)
etzIpMgtStatus.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    etzIpMgtStatus.setStatus("current")
_EtzIpMgtDhcpTries_Type = Counter32
_EtzIpMgtDhcpTries_Object = MibScalar
etzIpMgtDhcpTries = _EtzIpMgtDhcpTries_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 102, 100, 2),
    _EtzIpMgtDhcpTries_Type()
)
etzIpMgtDhcpTries.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    etzIpMgtDhcpTries.setStatus("current")
_EtzIpMgtDhcpMode_Type = Integer32
_EtzIpMgtDhcpMode_Object = MibScalar
etzIpMgtDhcpMode = _EtzIpMgtDhcpMode_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 102, 100, 3),
    _EtzIpMgtDhcpMode_Type()
)
etzIpMgtDhcpMode.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    etzIpMgtDhcpMode.setStatus("current")
_EtzRepUserBkups_Type = Counter32
_EtzRepUserBkups_Object = MibScalar
etzRepUserBkups = _EtzRepUserBkups_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 102, 100, 4),
    _EtzRepUserBkups_Type()
)
etzRepUserBkups.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    etzRepUserBkups.setStatus("current")
_EtzRepAutoBkups_Type = Counter32
_EtzRepAutoBkups_Object = MibScalar
etzRepAutoBkups = _EtzRepAutoBkups_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 102, 100, 5),
    _EtzRepAutoBkups_Type()
)
etzRepAutoBkups.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    etzRepAutoBkups.setStatus("current")
_EtzRepStatus_Type = Integer32
_EtzRepStatus_Object = MibScalar
etzRepStatus = _EtzRepStatus_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 102, 100, 6),
    _EtzRepStatus_Type()
)
etzRepStatus.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    etzRepStatus.setStatus("current")
_EtzRepFTPcnxErrors_Type = Counter32
_EtzRepFTPcnxErrors_Object = MibScalar
etzRepFTPcnxErrors = _EtzRepFTPcnxErrors_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 102, 100, 7),
    _EtzRepFTPcnxErrors_Type()
)
etzRepFTPcnxErrors.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    etzRepFTPcnxErrors.setStatus("current")
_EtzRepFTPxferErrors_Type = Counter32
_EtzRepFTPxferErrors_Object = MibScalar
etzRepFTPxferErrors = _EtzRepFTPxferErrors_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 102, 100, 8),
    _EtzRepFTPxferErrors_Type()
)
etzRepFTPxferErrors.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    etzRepFTPxferErrors.setStatus("current")
_MomentumIoProfile_ObjectIdentity = ObjectIdentity
momentumIoProfile = _MomentumIoProfile_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103)
)
_MomentumIoBaseType_Type = Integer32
_MomentumIoBaseType_Object = MibScalar
momentumIoBaseType = _MomentumIoBaseType_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 1),
    _MomentumIoBaseType_Type()
)
momentumIoBaseType.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    momentumIoBaseType.setStatus("current")


class _MomentumIoBaseName_Type(DisplayString):
    """Custom type momentumIoBaseName based on DisplayString"""
    subtypeSpec = DisplayString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(1, 255),
    )


_MomentumIoBaseName_Type.__name__ = "DisplayString"
_MomentumIoBaseName_Object = MibScalar
momentumIoBaseName = _MomentumIoBaseName_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 2),
    _MomentumIoBaseName_Type()
)
momentumIoBaseName.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    momentumIoBaseName.setStatus("current")
_MomentumIoMasterIPTable_Object = MibTable
momentumIoMasterIPTable = _MomentumIoMasterIPTable_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 3)
)
if mibBuilder.loadTexts:
    momentumIoMasterIPTable.setStatus("current")
_MomentumIoMasterIPEntry_Object = MibTableRow
momentumIoMasterIPEntry = _MomentumIoMasterIPEntry_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 3, 1)
)
momentumIoMasterIPEntry.setIndexNames(
    (0, "TFPRIVATE-MIB", "momentumIoMasterIPValue"),
)
if mibBuilder.loadTexts:
    momentumIoMasterIPEntry.setStatus("current")
_MomentumIoMasterIPValue_Type = IpAddress
_MomentumIoMasterIPValue_Object = MibTableColumn
momentumIoMasterIPValue = _MomentumIoMasterIPValue_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 3, 1, 1),
    _MomentumIoMasterIPValue_Type()
)
momentumIoMasterIPValue.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    momentumIoMasterIPValue.setStatus("current")


class _MomentumIoModuleTimeOut_Type(Integer32):
    """Custom type momentumIoModuleTimeOut based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 2147483647),
    )


_MomentumIoModuleTimeOut_Type.__name__ = "Integer32"
_MomentumIoModuleTimeOut_Object = MibScalar
momentumIoModuleTimeOut = _MomentumIoModuleTimeOut_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 4),
    _MomentumIoModuleTimeOut_Type()
)
momentumIoModuleTimeOut.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    momentumIoModuleTimeOut.setStatus("current")


class _MomentumIoASCIIModuleHeader_Type(DisplayString):
    """Custom type momentumIoASCIIModuleHeader based on DisplayString"""
    subtypeSpec = DisplayString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(1, 64),
    )


_MomentumIoASCIIModuleHeader_Type.__name__ = "DisplayString"
_MomentumIoASCIIModuleHeader_Object = MibScalar
momentumIoASCIIModuleHeader = _MomentumIoASCIIModuleHeader_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 5),
    _MomentumIoASCIIModuleHeader_Type()
)
momentumIoASCIIModuleHeader.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    momentumIoASCIIModuleHeader.setStatus("current")


class _MomentumIoReservationTime_Type(Integer32):
    """Custom type momentumIoReservationTime based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 2147483647),
    )


_MomentumIoReservationTime_Type.__name__ = "Integer32"
_MomentumIoReservationTime_Object = MibScalar
momentumIoReservationTime = _MomentumIoReservationTime_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 6),
    _MomentumIoReservationTime_Type()
)
momentumIoReservationTime.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    momentumIoReservationTime.setStatus("current")
_MomentumIoInputDataTable_Object = MibTable
momentumIoInputDataTable = _MomentumIoInputDataTable_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 7)
)
if mibBuilder.loadTexts:
    momentumIoInputDataTable.setStatus("current")
_MomentumIoInputDataEntry_Object = MibTableRow
momentumIoInputDataEntry = _MomentumIoInputDataEntry_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 7, 1)
)
momentumIoInputDataEntry.setIndexNames(
    (0, "TFPRIVATE-MIB", "momentumIoInputDataIndex"),
)
if mibBuilder.loadTexts:
    momentumIoInputDataEntry.setStatus("current")


class _MomentumIoInputDataIndex_Type(Integer32):
    """Custom type momentumIoInputDataIndex based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 0),
    )


_MomentumIoInputDataIndex_Type.__name__ = "Integer32"
_MomentumIoInputDataIndex_Object = MibTableColumn
momentumIoInputDataIndex = _MomentumIoInputDataIndex_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 7, 1, 1),
    _MomentumIoInputDataIndex_Type()
)
momentumIoInputDataIndex.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    momentumIoInputDataIndex.setStatus("current")


class _MomentumIoInputDataValues_Type(OctetString):
    """Custom type momentumIoInputDataValues based on OctetString"""
    subtypeSpec = OctetString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(1, 16),
    )


_MomentumIoInputDataValues_Type.__name__ = "OctetString"
_MomentumIoInputDataValues_Object = MibTableColumn
momentumIoInputDataValues = _MomentumIoInputDataValues_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 7, 1, 2),
    _MomentumIoInputDataValues_Type()
)
momentumIoInputDataValues.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    momentumIoInputDataValues.setStatus("current")


class _MomentumIoNumInputWords_Type(Integer32):
    """Custom type momentumIoNumInputWords based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 15),
    )


_MomentumIoNumInputWords_Type.__name__ = "Integer32"
_MomentumIoNumInputWords_Object = MibTableColumn
momentumIoNumInputWords = _MomentumIoNumInputWords_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 7, 1, 3),
    _MomentumIoNumInputWords_Type()
)
momentumIoNumInputWords.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    momentumIoNumInputWords.setStatus("current")


class _MomentumIoNumInputPoints_Type(Integer32):
    """Custom type momentumIoNumInputPoints based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 7),
    )


_MomentumIoNumInputPoints_Type.__name__ = "Integer32"
_MomentumIoNumInputPoints_Object = MibTableColumn
momentumIoNumInputPoints = _MomentumIoNumInputPoints_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 7, 1, 4),
    _MomentumIoNumInputPoints_Type()
)
momentumIoNumInputPoints.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    momentumIoNumInputPoints.setStatus("current")
_MomentumIoOutputDataTable_Object = MibTable
momentumIoOutputDataTable = _MomentumIoOutputDataTable_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 8)
)
if mibBuilder.loadTexts:
    momentumIoOutputDataTable.setStatus("current")
_MomentumIoOutputDataEntry_Object = MibTableRow
momentumIoOutputDataEntry = _MomentumIoOutputDataEntry_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 8, 1)
)
momentumIoOutputDataEntry.setIndexNames(
    (0, "TFPRIVATE-MIB", "momentumIoOutputDataIndex"),
)
if mibBuilder.loadTexts:
    momentumIoOutputDataEntry.setStatus("current")


class _MomentumIoOutputDataIndex_Type(Integer32):
    """Custom type momentumIoOutputDataIndex based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 0),
    )


_MomentumIoOutputDataIndex_Type.__name__ = "Integer32"
_MomentumIoOutputDataIndex_Object = MibTableColumn
momentumIoOutputDataIndex = _MomentumIoOutputDataIndex_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 8, 1, 1),
    _MomentumIoOutputDataIndex_Type()
)
momentumIoOutputDataIndex.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    momentumIoOutputDataIndex.setStatus("current")


class _MomentumIoOutputDataValues_Type(OctetString):
    """Custom type momentumIoOutputDataValues based on OctetString"""
    subtypeSpec = OctetString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(1, 16),
    )


_MomentumIoOutputDataValues_Type.__name__ = "OctetString"
_MomentumIoOutputDataValues_Object = MibTableColumn
momentumIoOutputDataValues = _MomentumIoOutputDataValues_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 8, 1, 2),
    _MomentumIoOutputDataValues_Type()
)
momentumIoOutputDataValues.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    momentumIoOutputDataValues.setStatus("current")


class _MomentumIoNumOutputWords_Type(Integer32):
    """Custom type momentumIoNumOutputWords based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 15),
    )


_MomentumIoNumOutputWords_Type.__name__ = "Integer32"
_MomentumIoNumOutputWords_Object = MibTableColumn
momentumIoNumOutputWords = _MomentumIoNumOutputWords_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 8, 1, 3),
    _MomentumIoNumOutputWords_Type()
)
momentumIoNumOutputWords.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    momentumIoNumOutputWords.setStatus("current")


class _MomentumIoNumOutputPoints_Type(Integer32):
    """Custom type momentumIoNumOutputPoints based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 7),
    )


_MomentumIoNumOutputPoints_Type.__name__ = "Integer32"
_MomentumIoNumOutputPoints_Object = MibTableColumn
momentumIoNumOutputPoints = _MomentumIoNumOutputPoints_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 103, 8, 1, 4),
    _MomentumIoNumOutputPoints_Type()
)
momentumIoNumOutputPoints.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    momentumIoNumOutputPoints.setStatus("current")
_MomentumM1eProfile_ObjectIdentity = ObjectIdentity
momentumM1eProfile = _MomentumM1eProfile_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 104)
)
_AdvantysProfile_ObjectIdentity = ObjectIdentity
advantysProfile = _AdvantysProfile_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 105)
)
_GatewayProfile_ObjectIdentity = ObjectIdentity
gatewayProfile = _GatewayProfile_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 106)
)
_ModiconM340Profile_ObjectIdentity = ObjectIdentity
modiconM340Profile = _ModiconM340Profile_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 107)
)
_TimeManagement_ObjectIdentity = ObjectIdentity
timeManagement = _TimeManagement_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8)
)
_Ntp_ObjectIdentity = ObjectIdentity
ntp = _Ntp_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1)
)
_NtpV2_ObjectIdentity = ObjectIdentity
ntpV2 = _NtpV2_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1, 0)
)
if mibBuilder.loadTexts:
    ntpV2.setStatus("current")


class _NtpStatus_Type(Integer32):
    """Custom type ntpStatus based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("idle", 1),
          ("operationnal", 2))
    )


_NtpStatus_Type.__name__ = "Integer32"
_NtpStatus_Object = MibScalar
ntpStatus = _NtpStatus_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1, 1),
    _NtpStatus_Type()
)
ntpStatus.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ntpStatus.setStatus("current")
_NtpSrvAddr_Type = IpAddress
_NtpSrvAddr_Object = MibScalar
ntpSrvAddr = _NtpSrvAddr_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1, 2),
    _NtpSrvAddr_Type()
)
ntpSrvAddr.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ntpSrvAddr.setStatus("current")


class _NtpLnkSrvStatus_Type(Integer32):
    """Custom type ntpLnkSrvStatus based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("nok", 1),
          ("ok", 2))
    )


_NtpLnkSrvStatus_Type.__name__ = "Integer32"
_NtpLnkSrvStatus_Object = MibScalar
ntpLnkSrvStatus = _NtpLnkSrvStatus_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1, 3),
    _NtpLnkSrvStatus_Type()
)
ntpLnkSrvStatus.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ntpLnkSrvStatus.setStatus("current")
_NtpReqCnt_Type = Counter32
_NtpReqCnt_Object = MibScalar
ntpReqCnt = _NtpReqCnt_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1, 4),
    _NtpReqCnt_Type()
)
ntpReqCnt.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ntpReqCnt.setStatus("current")
_NtpRespCnt_Type = Counter32
_NtpRespCnt_Object = MibScalar
ntpRespCnt = _NtpRespCnt_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1, 5),
    _NtpRespCnt_Type()
)
ntpRespCnt.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ntpRespCnt.setStatus("current")
_NtpErrCnt_Type = Counter32
_NtpErrCnt_Object = MibScalar
ntpErrCnt = _NtpErrCnt_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1, 6),
    _NtpErrCnt_Type()
)
ntpErrCnt.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ntpErrCnt.setStatus("current")


class _NtpDate_Type(DisplayString):
    """Custom type ntpDate based on DisplayString"""
    subtypeSpec = DisplayString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(0, 12),
    )


_NtpDate_Type.__name__ = "DisplayString"
_NtpDate_Object = MibScalar
ntpDate = _NtpDate_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1, 7),
    _NtpDate_Type()
)
ntpDate.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ntpDate.setStatus("current")


class _NtpTime_Type(DisplayString):
    """Custom type ntpTime based on DisplayString"""
    subtypeSpec = DisplayString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(0, 12),
    )


_NtpTime_Type.__name__ = "DisplayString"
_NtpTime_Object = MibScalar
ntpTime = _NtpTime_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1, 8),
    _NtpTime_Type()
)
ntpTime.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ntpTime.setStatus("current")


class _NtpTimeZone_Type(DisplayString):
    """Custom type ntpTimeZone based on DisplayString"""
    subtypeSpec = DisplayString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(0, 100),
    )


_NtpTimeZone_Type.__name__ = "DisplayString"
_NtpTimeZone_Object = MibScalar
ntpTimeZone = _NtpTimeZone_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1, 9),
    _NtpTimeZone_Type()
)
ntpTimeZone.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ntpTimeZone.setStatus("current")


class _NtpDSTStatus_Type(Integer32):
    """Custom type ntpDSTStatus based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("off", 2),
          ("on", 1))
    )


_NtpDSTStatus_Type.__name__ = "Integer32"
_NtpDSTStatus_Object = MibScalar
ntpDSTStatus = _NtpDSTStatus_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1, 10),
    _NtpDSTStatus_Type()
)
ntpDSTStatus.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ntpDSTStatus.setStatus("current")
_NtpLastErr_Type = Integer32
_NtpLastErr_Object = MibScalar
ntpLastErr = _NtpLastErr_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1, 11),
    _NtpLastErr_Type()
)
ntpLastErr.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ntpLastErr.setStatus("current")
_Email_ObjectIdentity = ObjectIdentity
email = _Email_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 9)
)
_Smtp_ObjectIdentity = ObjectIdentity
smtp = _Smtp_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 9, 1)
)
_SmtpV2_ObjectIdentity = ObjectIdentity
smtpV2 = _SmtpV2_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 9, 1, 0)
)
if mibBuilder.loadTexts:
    smtpV2.setStatus("current")
_EmailTable_Object = MibTable
emailTable = _EmailTable_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 9, 1, 1)
)
if mibBuilder.loadTexts:
    emailTable.setStatus("current")
_EmailEntry_Object = MibTableRow
emailEntry = _EmailEntry_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 9, 1, 1, 1)
)
emailEntry.setIndexNames(
    (0, "TFPRIVATE-MIB", "emailIndex"),
)
if mibBuilder.loadTexts:
    emailEntry.setStatus("current")


class _EmailIndex_Type(Integer32):
    """Custom type emailIndex based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 1),
    )


_EmailIndex_Type.__name__ = "Integer32"
_EmailIndex_Object = MibTableColumn
emailIndex = _EmailIndex_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 9, 1, 1, 1, 1),
    _EmailIndex_Type()
)
emailIndex.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    emailIndex.setStatus("current")


class _SmtpStatus_Type(Integer32):
    """Custom type smtpStatus based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2,
              3)
        )
    )
    namedValues = NamedValues(
        *(("idle", 1),
          ("operationnal", 2),
          ("stopped", 3))
    )


_SmtpStatus_Type.__name__ = "Integer32"
_SmtpStatus_Object = MibTableColumn
smtpStatus = _SmtpStatus_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 9, 1, 1, 1, 2),
    _SmtpStatus_Type()
)
smtpStatus.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    smtpStatus.setStatus("current")
_SmtpSrvAddr_Type = IpAddress
_SmtpSrvAddr_Object = MibTableColumn
smtpSrvAddr = _SmtpSrvAddr_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 9, 1, 1, 1, 3),
    _SmtpSrvAddr_Type()
)
smtpSrvAddr.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    smtpSrvAddr.setStatus("current")
_SmtpMailSentCnt_Type = Counter32
_SmtpMailSentCnt_Object = MibTableColumn
smtpMailSentCnt = _SmtpMailSentCnt_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 9, 1, 1, 1, 4),
    _SmtpMailSentCnt_Type()
)
smtpMailSentCnt.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    smtpMailSentCnt.setStatus("current")
_SmtpErrCnt_Type = Counter32
_SmtpErrCnt_Object = MibTableColumn
smtpErrCnt = _SmtpErrCnt_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 9, 1, 1, 1, 5),
    _SmtpErrCnt_Type()
)
smtpErrCnt.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    smtpErrCnt.setStatus("current")
_SmtpLastErr_Type = Integer32
_SmtpLastErr_Object = MibTableColumn
smtpLastErr = _SmtpLastErr_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 9, 1, 1, 1, 6),
    _SmtpLastErr_Type()
)
smtpLastErr.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    smtpLastErr.setStatus("current")
_SmtpLastMailElapsedTime_Type = Counter32
_SmtpLastMailElapsedTime_Object = MibTableColumn
smtpLastMailElapsedTime = _SmtpLastMailElapsedTime_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 9, 1, 1, 1, 7),
    _SmtpLastMailElapsedTime_Type()
)
smtpLastMailElapsedTime.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    smtpLastMailElapsedTime.setStatus("current")


class _SmtpLnkSrvStatus_Type(Integer32):
    """Custom type smtpLnkSrvStatus based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("nok", 1),
          ("ok", 2))
    )


_SmtpLnkSrvStatus_Type.__name__ = "Integer32"
_SmtpLnkSrvStatus_Object = MibTableColumn
smtpLnkSrvStatus = _SmtpLnkSrvStatus_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 9, 1, 1, 1, 8),
    _SmtpLnkSrvStatus_Type()
)
smtpLnkSrvStatus.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    smtpLnkSrvStatus.setStatus("current")
_SmtpSrvChkFailCnt_Type = Counter32
_SmtpSrvChkFailCnt_Object = MibTableColumn
smtpSrvChkFailCnt = _SmtpSrvChkFailCnt_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 9, 1, 1, 1, 9),
    _SmtpSrvChkFailCnt_Type()
)
smtpSrvChkFailCnt.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    smtpSrvChkFailCnt.setStatus("current")
_TfeMibVersion_ObjectIdentity = ObjectIdentity
tfeMibVersion = _TfeMibVersion_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 3833, 1, 255)
)


class _TfeMibVersionNumber_Type(DisplayString):
    """Custom type tfeMibVersionNumber based on DisplayString"""
    subtypeSpec = DisplayString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(0, 15),
    )


_TfeMibVersionNumber_Type.__name__ = "DisplayString"
_TfeMibVersionNumber_Object = MibScalar
tfeMibVersionNumber = _TfeMibVersionNumber_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 255, 1),
    _TfeMibVersionNumber_Type()
)
tfeMibVersionNumber.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tfeMibVersionNumber.setStatus("current")


class _TfeMibVersionDate_Type(DisplayString):
    """Custom type tfeMibVersionDate based on DisplayString"""
    subtypeSpec = DisplayString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(0, 15),
    )


_TfeMibVersionDate_Type.__name__ = "DisplayString"
_TfeMibVersionDate_Object = MibScalar
tfeMibVersionDate = _TfeMibVersionDate_Object(
    (1, 3, 6, 1, 4, 1, 3833, 1, 255, 2),
    _TfeMibVersionDate_Type()
)
tfeMibVersionDate.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tfeMibVersionDate.setStatus("current")

# Managed Objects groups


# Notification objects

port502StatusChange = NotificationType(
    (1, 3, 6, 1, 4, 1, 3833, 1, 2, 0, 2)
)
port502StatusChange.setObjects(
    ("TFPRIVATE-MIB", "port502Status")
)
if mibBuilder.loadTexts:
    port502StatusChange.setStatus(
        "current"
    )

ioScanStatusChange = NotificationType(
    (1, 3, 6, 1, 4, 1, 3833, 1, 3, 0, 3)
)
ioScanStatusChange.setObjects(
      *(("TFPRIVATE-MIB", "ioScanStatus"),
        ("TFPRIVATE-MIB", "ioScanGlbHealth"))
)
if mibBuilder.loadTexts:
    ioScanStatusChange.setStatus(
        "current"
    )

glbDataStatusChange = NotificationType(
    (1, 3, 6, 1, 4, 1, 3833, 1, 4, 0, 4)
)
glbDataStatusChange.setObjects(
      *(("TFPRIVATE-MIB", "glbDataStatus"),
        ("TFPRIVATE-MIB", "glbDataGlbSubHealth"))
)
if mibBuilder.loadTexts:
    glbDataStatusChange.setStatus(
        "current"
    )

webStatusChange = NotificationType(
    (1, 3, 6, 1, 4, 1, 3833, 1, 5, 0, 5)
)
webStatusChange.setObjects(
    ("TFPRIVATE-MIB", "webStatus")
)
if mibBuilder.loadTexts:
    webStatusChange.setStatus(
        "current"
    )

addressServerStatusChange = NotificationType(
    (1, 3, 6, 1, 4, 1, 3833, 1, 6, 0, 6)
)
addressServerStatusChange.setObjects(
    ("TFPRIVATE-MIB", "webStatus")
)
if mibBuilder.loadTexts:
    addressServerStatusChange.setStatus(
        "current"
    )

profileLed = NotificationType(
    (1, 3, 6, 1, 4, 1, 3833, 1, 7, 0, 1)
)
profileLed.setObjects(
    ("TFPRIVATE-MIB", "ledState")
)
if mibBuilder.loadTexts:
    profileLed.setStatus(
        "current"
    )

ntpStatusChange = NotificationType(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1, 0, 7)
)
ntpStatusChange.setObjects(
    ("TFPRIVATE-MIB", "ntpStatus")
)
if mibBuilder.loadTexts:
    ntpStatusChange.setStatus(
        "current"
    )

ntpServerChange = NotificationType(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1, 0, 8)
)
ntpServerChange.setObjects(
      *(("TFPRIVATE-MIB", "ntpLnkSrvStatus"),
        ("TFPRIVATE-MIB", "ntpSrvAddr"))
)
if mibBuilder.loadTexts:
    ntpServerChange.setStatus(
        "current"
    )

ntpLnkSrvStatusChange = NotificationType(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1, 0, 9)
)
ntpLnkSrvStatusChange.setObjects(
    ("TFPRIVATE-MIB", "ntpSrvAddr")
)
if mibBuilder.loadTexts:
    ntpLnkSrvStatusChange.setStatus(
        "current"
    )

ntpLeapSecond = NotificationType(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1, 0, 10)
)
ntpLeapSecond.setObjects(
      *(("TFPRIVATE-MIB", "ntpDate"),
        ("TFPRIVATE-MIB", "ntpTime"))
)
if mibBuilder.loadTexts:
    ntpLeapSecond.setStatus(
        "current"
    )

ntpDSTChange = NotificationType(
    (1, 3, 6, 1, 4, 1, 3833, 1, 8, 1, 0, 11)
)
ntpDSTChange.setObjects(
    ("TFPRIVATE-MIB", "ntpDSTStatus")
)
if mibBuilder.loadTexts:
    ntpDSTChange.setStatus(
        "current"
    )

smtpStatusChange = NotificationType(
    (1, 3, 6, 1, 4, 1, 3833, 1, 9, 1, 0, 12)
)
smtpStatusChange.setObjects(
      *(("TFPRIVATE-MIB", "emailIndex"),
        ("TFPRIVATE-MIB", "smtpStatus"))
)
if mibBuilder.loadTexts:
    smtpStatusChange.setStatus(
        "current"
    )

smtpLnkSrvChange = NotificationType(
    (1, 3, 6, 1, 4, 1, 3833, 1, 9, 1, 0, 13)
)
smtpLnkSrvChange.setObjects(
      *(("TFPRIVATE-MIB", "emailIndex"),
        ("TFPRIVATE-MIB", "smtpLnkSrvStatus"),
        ("TFPRIVATE-MIB", "smtpSrvAddr"))
)
if mibBuilder.loadTexts:
    smtpLnkSrvChange.setStatus(
        "current"
    )


# Notifications groups


# Agent capabilities


# Module compliance


# Export all MIB objects to the MIB builder

mibBuilder.exportSymbols(
    "TFPRIVATE-MIB",
    **{"schneiderelectric": schneiderelectric,
       "transparentFactoryEthernet": transparentFactoryEthernet,
       "port502Messaging": port502Messaging,
       "port502MessagingV2": port502MessagingV2,
       "port502StatusChange": port502StatusChange,
       "port502Status": port502Status,
       "port502SupportedProtocol": port502SupportedProtocol,
       "port502IpSecurity": port502IpSecurity,
       "port502MaxConn": port502MaxConn,
       "port502LocalConn": port502LocalConn,
       "port502RemConn": port502RemConn,
       "port502IpSecurityTable": port502IpSecurityTable,
       "port502IpSecurityEntry": port502IpSecurityEntry,
       "attemptFails": attemptFails,
       "ipSourceAddress": ipSourceAddress,
       "port502ConnTable": port502ConnTable,
       "port502ConnEntry": port502ConnEntry,
       "port502ConnLocalPort": port502ConnLocalPort,
       "port502ConnRemAddress": port502ConnRemAddress,
       "port502ConnRemPort": port502ConnRemPort,
       "port502ConnType": port502ConnType,
       "port502ConnMsgIn": port502ConnMsgIn,
       "port502ConnMsgOut": port502ConnMsgOut,
       "port502ConnMsgErr": port502ConnMsgErr,
       "port502XwayNet": port502XwayNet,
       "port502XwayStation": port502XwayStation,
       "port502MsgIn": port502MsgIn,
       "port502MsgOut": port502MsgOut,
       "port502MsgOutErr": port502MsgOutErr,
       "port502AddStackStat": port502AddStackStat,
       "port502AddStackStatTable": port502AddStackStatTable,
       "port502AddStackStatEntry": port502AddStackStatEntry,
       "port502AddStackStatIndex": port502AddStackStatIndex,
       "port502PeaKTcpRetransSegs": port502PeaKTcpRetransSegs,
       "ioScanning": ioScanning,
       "ioScanningV2": ioScanningV2,
       "ioScanStatusChange": ioScanStatusChange,
       "ioScanStatus": ioScanStatus,
       "ioScanMaxDevice": ioScanMaxDevice,
       "ioScanPolledDevice": ioScanPolledDevice,
       "ioScanTransSend": ioScanTransSend,
       "ioScanGlbHealth": ioScanGlbHealth,
       "ioScanDeviceTable": ioScanDeviceTable,
       "ioScanDeviceEntry": ioScanDeviceEntry,
       "ioScanDeviceRemAddress": ioScanDeviceRemAddress,
       "ioScanDeviceHealth": ioScanDeviceHealth,
       "ioScanDeviceRate": ioScanDeviceRate,
       "ioScanInputLocalAddress": ioScanInputLocalAddress,
       "ioScanOutputLocalAddress": ioScanOutputLocalAddress,
       "globalData": globalData,
       "globalDataV2": globalDataV2,
       "glbDataStatusChange": glbDataStatusChange,
       "glbDataStatus": glbDataStatus,
       "glbDataMaxPub": glbDataMaxPub,
       "glbDataMaxSub": glbDataMaxSub,
       "glbDataPub": glbDataPub,
       "glbDataSub": glbDataSub,
       "glbDataPubErr": glbDataPubErr,
       "glbDataSubErr": glbDataSubErr,
       "glbDataGlbSubHealth": glbDataGlbSubHealth,
       "glbDataPubTable": glbDataPubTable,
       "glbDataPubEntry": glbDataPubEntry,
       "glbDataPubSourceAddress": glbDataPubSourceAddress,
       "glbDataPubHostId": glbDataPubHostId,
       "glbDataPubNetId": glbDataPubNetId,
       "glbDataPubGroupId": glbDataPubGroupId,
       "glbDataPubCnt": glbDataPubCnt,
       "glbDataPubErrCnt": glbDataPubErrCnt,
       "glbDataPubDistribRate": glbDataPubDistribRate,
       "glbDataPubDuplicateErr": glbDataPubDuplicateErr,
       "glbDataSubTable": glbDataSubTable,
       "glbDataSubEntry": glbDataSubEntry,
       "glbDataSubSourceAddress": glbDataSubSourceAddress,
       "glbDataSubHostId": glbDataSubHostId,
       "glbDataSubNetId": glbDataSubNetId,
       "glbDataSubGroupId": glbDataSubGroupId,
       "glbDataSubCnt": glbDataSubCnt,
       "glbDataSubErrCnt": glbDataSubErrCnt,
       "glbDataMinimumSeparation": glbDataMinimumSeparation,
       "glbDataHealth": glbDataHealth,
       "glbDataHealthTimeOut": glbDataHealthTimeOut,
       "glbDataLastRecErr": glbDataLastRecErr,
       "web": web,
       "webV2": webV2,
       "webStatusChange": webStatusChange,
       "webStatus": webStatus,
       "webPassword": webPassword,
       "webSuccessfullAccess": webSuccessfullAccess,
       "webFailedAttempts": webFailedAttempts,
       "addressServer": addressServer,
       "addressServerV2": addressServerV2,
       "addressServerStatusChange": addressServerStatusChange,
       "addressServerStatus": addressServerStatus,
       "equipmentProfile": equipmentProfile,
       "equipmentProfileV2": equipmentProfileV2,
       "profileLed": profileLed,
       "profileProductName": profileProductName,
       "profileVersion": profileVersion,
       "profileCommunicationServices": profileCommunicationServices,
       "profileGlobalStatus": profileGlobalStatus,
       "profileIpConfigMode": profileIpConfigMode,
       "profileRoleName": profileRoleName,
       "profileBandwidthMgt": profileBandwidthMgt,
       "profileBandwidthDistTable": profileBandwidthDistTable,
       "profileBandwidthDistEntry": profileBandwidthDistEntry,
       "bandwidthDistributionIndex": bandwidthDistributionIndex,
       "port502Bandwidth": port502Bandwidth,
       "ioScanningBandwidth": ioScanningBandwidth,
       "globalDataBandwidth": globalDataBandwidth,
       "otherBandwidth": otherBandwidth,
       "profileLedDisplayTable": profileLedDisplayTable,
       "profileLedDisplayEntry": profileLedDisplayEntry,
       "ledIndex": ledIndex,
       "ledName": ledName,
       "ledDescr": ledDescr,
       "ledState": ledState,
       "profileSlot": profileSlot,
       "profileCPUType": profileCPUType,
       "profileTrapTableEntriesMax": profileTrapTableEntriesMax,
       "profileTrapTable": profileTrapTable,
       "profileTrapEntry": profileTrapEntry,
       "trapCommunityName": trapCommunityName,
       "remoteIpAddress": remoteIpAddress,
       "authenticationTrap": authenticationTrap,
       "port502Trap": port502Trap,
       "ioScanningTrap": ioScanningTrap,
       "globalDataTrap": globalDataTrap,
       "webTrap": webTrap,
       "addressServerTrap": addressServerTrap,
       "profileTrap": profileTrap,
       "timeManagementTrap": timeManagementTrap,
       "emailTrap": emailTrap,
       "profileSpecificId": profileSpecificId,
       "profileIpAddress": profileIpAddress,
       "profileIpNetMask": profileIpNetMask,
       "profileIpGateway": profileIpGateway,
       "profileMacAddress": profileMacAddress,
       "profileImplementationClass": profileImplementationClass,
       "premiumProfile": premiumProfile,
       "quantumProfile": quantumProfile,
       "qnoe": qnoe,
       "qNoeCommand": qNoeCommand,
       "microProfile": microProfile,
       "mEtz": mEtz,
       "etzIpMgtStatus": etzIpMgtStatus,
       "etzIpMgtDhcpTries": etzIpMgtDhcpTries,
       "etzIpMgtDhcpMode": etzIpMgtDhcpMode,
       "etzRepUserBkups": etzRepUserBkups,
       "etzRepAutoBkups": etzRepAutoBkups,
       "etzRepStatus": etzRepStatus,
       "etzRepFTPcnxErrors": etzRepFTPcnxErrors,
       "etzRepFTPxferErrors": etzRepFTPxferErrors,
       "momentumIoProfile": momentumIoProfile,
       "momentumIoBaseType": momentumIoBaseType,
       "momentumIoBaseName": momentumIoBaseName,
       "momentumIoMasterIPTable": momentumIoMasterIPTable,
       "momentumIoMasterIPEntry": momentumIoMasterIPEntry,
       "momentumIoMasterIPValue": momentumIoMasterIPValue,
       "momentumIoModuleTimeOut": momentumIoModuleTimeOut,
       "momentumIoASCIIModuleHeader": momentumIoASCIIModuleHeader,
       "momentumIoReservationTime": momentumIoReservationTime,
       "momentumIoInputDataTable": momentumIoInputDataTable,
       "momentumIoInputDataEntry": momentumIoInputDataEntry,
       "momentumIoInputDataIndex": momentumIoInputDataIndex,
       "momentumIoInputDataValues": momentumIoInputDataValues,
       "momentumIoNumInputWords": momentumIoNumInputWords,
       "momentumIoNumInputPoints": momentumIoNumInputPoints,
       "momentumIoOutputDataTable": momentumIoOutputDataTable,
       "momentumIoOutputDataEntry": momentumIoOutputDataEntry,
       "momentumIoOutputDataIndex": momentumIoOutputDataIndex,
       "momentumIoOutputDataValues": momentumIoOutputDataValues,
       "momentumIoNumOutputWords": momentumIoNumOutputWords,
       "momentumIoNumOutputPoints": momentumIoNumOutputPoints,
       "momentumM1eProfile": momentumM1eProfile,
       "advantysProfile": advantysProfile,
       "gatewayProfile": gatewayProfile,
       "modiconM340Profile": modiconM340Profile,
       "timeManagement": timeManagement,
       "ntp": ntp,
       "ntpV2": ntpV2,
       "ntpStatusChange": ntpStatusChange,
       "ntpServerChange": ntpServerChange,
       "ntpLnkSrvStatusChange": ntpLnkSrvStatusChange,
       "ntpLeapSecond": ntpLeapSecond,
       "ntpDSTChange": ntpDSTChange,
       "ntpStatus": ntpStatus,
       "ntpSrvAddr": ntpSrvAddr,
       "ntpLnkSrvStatus": ntpLnkSrvStatus,
       "ntpReqCnt": ntpReqCnt,
       "ntpRespCnt": ntpRespCnt,
       "ntpErrCnt": ntpErrCnt,
       "ntpDate": ntpDate,
       "ntpTime": ntpTime,
       "ntpTimeZone": ntpTimeZone,
       "ntpDSTStatus": ntpDSTStatus,
       "ntpLastErr": ntpLastErr,
       "email": email,
       "smtp": smtp,
       "smtpV2": smtpV2,
       "smtpStatusChange": smtpStatusChange,
       "smtpLnkSrvChange": smtpLnkSrvChange,
       "emailTable": emailTable,
       "emailEntry": emailEntry,
       "emailIndex": emailIndex,
       "smtpStatus": smtpStatus,
       "smtpSrvAddr": smtpSrvAddr,
       "smtpMailSentCnt": smtpMailSentCnt,
       "smtpErrCnt": smtpErrCnt,
       "smtpLastErr": smtpLastErr,
       "smtpLastMailElapsedTime": smtpLastMailElapsedTime,
       "smtpLnkSrvStatus": smtpLnkSrvStatus,
       "smtpSrvChkFailCnt": smtpSrvChkFailCnt,
       "tfeMibVersion": tfeMibVersion,
       "tfeMibVersionNumber": tfeMibVersionNumber,
       "tfeMibVersionDate": tfeMibVersionDate}
)
