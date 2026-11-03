<?xml version="1.0" encoding="UTF-8"?>
<!-- Synthetic SCL test fixture authored for PEAT (not derived from vendor files). -->
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="PEAT_TEST_SUB" version="3" revision="7" toolID="PEAT synthetic fixture" nameStructure="IEDName">
    <History>
      <Hitem version="3" revision="6" when="2026-01-05T10:00:00Z" who="engineer-a" what="Added GOOSE trip" why="Breaker failure scheme"/>
      <Hitem version="3" revision="7" when="2026-02-11T09:30:00Z" who="engineer-b" what="Changed VLAN" why="Segmentation"/>
    </History>
  </Header>
  <Substation name="SUB1">
    <VoltageLevel name="E1">
      <Bay name="Q01">
        <LNode iedName="PROT1" ldInst="PRO" lnClass="PTOC" lnInst="1"/>
      </Bay>
      <Bay name="Q02">
        <LNode iedName="MU1" ldInst="MU" lnClass="TCTR" lnInst="1"/>
      </Bay>
    </VoltageLevel>
  </Substation>
  <Communication>
    <SubNetwork name="StationBus" type="8-MMS">
      <ConnectedAP iedName="PROT1" apName="S1" redProt="prp">
        <Address>
          <P type="IP">192.0.2.10</P>
          <P type="IP-SUBNET">255.255.255.0</P>
          <P type="IP-GATEWAY">192.0.2.1</P>
          <P type="OSI-TSEL">0001</P>
          <P type="OSI-PSEL">00000001</P>
        </Address>
        <GSE ldInst="PRO" cbName="gcbTrip">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-10</P>
            <P type="APPID">1000</P>
            <P type="VLAN-ID">064</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
          <MinTime unit="s" multiplier="m">4</MinTime>
          <MaxTime unit="s" multiplier="m">1000</MaxTime>
        </GSE>
        <PhysConn type="Connection">
          <P type="Port">5A</P>
        </PhysConn>
        <PhysConn type="RedConn">
          <P type="Port">5B</P>
        </PhysConn>
      </ConnectedAP>
      <ConnectedAP iedName="HMI1" apName="S1">
        <Address>
          <P type="IP">192.0.2.100</P>
          <P type="IP-SUBNET">255.255.255.0</P>
        </Address>
      </ConnectedAP>
    </SubNetwork>
    <SubNetwork name="ProcessBus" type="8-MMS">
      <ConnectedAP iedName="MU1" apName="P1">
        <SMV ldInst="MU" cbName="svcb1">
          <Address>
            <P type="MAC-Address">01-0C-CD-04-00-01</P>
            <P type="APPID">4000</P>
            <P type="VLAN-ID">064</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
        </SMV>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="PROT1" desc="Feeder protection" manufacturer="ACME" type="PR-100" configVersion="2.1" originalSclVersion="2007" originalSclRevision="B" originalSclRelease="4">
    <Services>
      <GOOSE max="8"/>
      <SMVsc max="2"/>
      <ClientServices goose="true" sv="true"/>
      <FileHandling/>
    </Services>
    <AccessPoint name="S1">
      <Server>
        <Authentication/>
        <LDevice inst="PRO" desc="Protection">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DataSet name="dsTrip">
              <FCDA ldInst="PRO" prefix="" lnClass="PTRC" lnInst="1" doName="Tr" fc="ST"/>
              <FCDA ldInst="PRO" prefix="" lnClass="PTRC" lnInst="1" doName="Str" fc="ST"/>
            </DataSet>
            <DataSet name="dsMeas">
              <FCDA ldInst="PRO" prefix="" lnClass="MMXU" lnInst="1" doName="TotW" fc="MX"/>
            </DataSet>
            <ReportControl name="urcbMeas" rptID="PROT1/Meas" datSet="dsMeas" confRev="1" buffered="false" bufTime="50" intgPd="1000">
              <TrgOps dchg="true" period="true"/>
              <OptFields seqNum="true"/>
              <RptEnabled max="2">
                <ClientLN iedName="HMI1" apRef="S1" ldInst="LD0" lnClass="IHMI" lnInst="1"/>
              </RptEnabled>
            </ReportControl>
            <GSEControl name="gcbTrip" appID="PROT1_TRIP" datSet="dsTrip" confRev="2">
              <IEDName>MU1</IEDName>
            </GSEControl>
            <SettingControl numOfSGs="6" actSG="1"/>
            <Inputs>
              <ExtRef iedName="MU1" ldInst="MU" lnClass="TCTR" lnInst="1" doName="Amp" serviceType="SMV" srcLDInst="MU" srcCBName="svcb1"/>
              <ExtRef iedName="MU1" ldInst="MU" lnClass="TVTR" lnInst="1" doName="Vol" serviceType="SMV" srcLDInst="MU" srcCBName="svcb1"/>
              <ExtRef iedName="BUS1" ldInst="PRO" lnClass="PTRC" lnInst="1" doName="Tr"/>
            </Inputs>
          </LN0>
          <LN lnClass="LPHD" inst="1" lnType="LPHD_T"/>
          <LN prefix="" lnClass="PTOC" inst="1" lnType="PTOC_T"/>
          <LN lnClass="XCBR" inst="1" lnType="XCBR_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <IED name="MU1" manufacturer="ACME" type="MU-9" configVersion="1.0">
    <AccessPoint name="P1">
      <Server>
        <Authentication none="false" password="true"/>
        <LDevice inst="MU">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DataSet name="dsSV">
              <FCDA ldInst="MU" lnClass="TCTR" lnInst="1" doName="Amp" fc="MX"/>
              <FCDA ldInst="MU" lnClass="TVTR" lnInst="1" doName="Vol" fc="MX"/>
            </DataSet>
            <SampledValueControl name="svcb1" smvID="MU1_SV1" datSet="dsSV" confRev="1" smpRate="80" nofASDU="1" securityEnable="Signature">
              <IEDName>PROT1</IEDName>
            </SampledValueControl>
          </LN0>
          <LN lnClass="TCTR" inst="1" lnType="TCTR_T"/>
          <LN lnClass="TVTR" inst="1" lnType="TVTR_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates/>
</SCL>
