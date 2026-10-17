"""Generate a fabricated OT file tree so OTDataMap can be tried without real data.

Everything here is invented: no real site, vendor account, address or credential.
Run:  python samples/make_samples.py
"""

from __future__ import annotations

import contextlib
import os
import time
from pathlib import Path

ROOT = Path(__file__).parent / "example_site"

SCD = """<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL">
  <Header id="EXAMPLE_BAY" version="1" revision="3"/>
  <Communication>
    <SubNetwork name="StationBus">
      <ConnectedAP iedName="IED_PROT_01" apName="S1">
        <Address><P type="IP">10.20.30.11</P><P type="IP-SUBNET">255.255.255.0</P></Address>
        <GSE ldInst="LD0" cbName="gcb01"><Address><P type="APPID">3001</P></Address></GSE>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="IED_PROT_01" manufacturer="ExampleVendor" type="EX-500"/>
</SCL>
"""

SWITCH_CFG = """!
version 15.2
hostname EX-SW-BAY1
!
enable secret 5 $1$ExAmPlE$FabricatedHashForDemoOnly
username operator password 7 104D000A0618
!
snmp-server community public RO
!
line vty 0 4
 transport input telnet
!
end
"""

COMTRADE_CFG = """EXAMPLE_SUBSTATION,REC_01,1999
4,3A,1D
1,IA,,,A,0.001,0,0,-32768,32767,600.0,1.0,P
2,IB,,,A,0.001,0,0,-32768,32767,600.0,1.0,P
3,IC,,,A,0.001,0,0,-32768,32767,600.0,1.0,P
1,TRIP,0
50
1
2000,1000
01/02/2026,10:15:30.000000
01/02/2026,10:15:30.250000
ASCII
1
"""

HISTORIAN = "timestamp,tagname,value,quality\n" + "".join(
    f"2026-01-0{d%9+1}T00:00:00Z,UNIT1.FEEDER{d%4+1}.MW,{30+d%17}.4,Good\n"
    for d in range(400)
)

L5X = """<?xml version="1.0" encoding="UTF-8"?>
<RSLogix5000Content SchemaRevision="1.0" SoftwareVersion="32.00">
  <Controller Name="EX_LINE1" ProcessorType="1756-L71">
    <Tags><Tag Name="SCADA_Password" DataType="STRING" ExternalAccess="Read/Write"/></Tags>
  </Controller>
</RSLogix5000Content>
"""

ROSTER = ("full name,employee id,shift,phone\n"
          "A. Example,EMP-0001,Day,+00 000 000 001\n"
          "B. Example,EMP-0002,Night,+00 000 000 002\n")

KEYFILE = ("-----BEGIN RSA PRIVATE KEY-----\n"
           "ZmFicmljYXRlZCBzYW1wbGUga2V5IC0gbm90IGEgcmVhbCBrZXkK\n"
           "-----END RSA PRIVATE KEY-----\n")

FILES = {
    # in the right place
    "engineering/bay1/EXAMPLE_BAY.scd": SCD,
    "engineering/bay1/line1.L5X": L5X,
    "engineering/network/EX-SW-BAY1_running-config.cfg": SWITCH_CFG,
    "engineering/device_descriptions/EX-500.gsdml": "<ISO15745Profile/>\n",
    "historian/exports/unit1_mw_2026Q1.csv": HISTORIAN,
    "historian/exports/unit1_mw_2026Q1_copy.csv": HISTORIAN,
    "reports/monthly/january_summary.pdf": "%PDF-1.4\nfabricated\n",
    "records/REC_01_20260102.cfg": COMTRADE_CFG,
    "records/REC_01_20260102.dat": "1,0,100,-100,50,0\n" * 50,
    # in the wrong place
    "transfer/outgoing/EXAMPLE_BAY.scd": SCD,
    "vendor/exchange/line1.L5X": L5X,
    "vendor/exchange/EX-SW-BAY1_running-config.cfg": SWITCH_CFG,
    "dmz/share/unit1_mw_2026Q1.csv": HISTORIAN,
    "users/jdoe/desktop/EXAMPLE_BAY.scd": SCD,
    "users/jdoe/OneDrive/site_backup/plant_image.bak": "FABRICATED BACKUP BLOB\n" * 200,
    "users/jdoe/downloads/id_rsa": KEYFILE,
    "shared/common/shift_roster_2026.csv": ROSTER,
    "shared/common/asset_list_site.csv":
        "device,vendor,model,ip\nIED_PROT_01,ExampleVendor,EX-500,10.20.30.11\n",
    "archive/2020/plant_full_backup.bak": "FABRICATED OLD BACKUP\n" * 100,
}

# A contractor handover package: one zip that hides everything that matters.
ARCHIVE_MEMBERS = {
    "handover/EXAMPLE_BAY.scd": SCD,
    "handover/line1.L5X": L5X,
    "handover/switches/EX-SW-BAY1_running-config.cfg": SWITCH_CFG,
    "handover/docs/commissioning_report.pdf": "%PDF-1.4\nfabricated\n",
    "handover/keys/id_rsa": KEYFILE,
}
ARCHIVES = {"vendor/exchange/EXAMPLE_handover_2026.zip": ARCHIVE_MEMBERS}

OLD = {"archive/2020/plant_full_backup.bak": 2200,
       "records/REC_01_20260102.cfg": 900}


def main() -> None:
    for rel, content in FILES.items():
        path = ROOT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    import zipfile
    for rel, members in ARCHIVES.items():
        path = ROOT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, content in members.items():
                zf.writestr(name, content)
    for rel, days in OLD.items():
        path = ROOT / rel
        old = time.time() - days * 86400
        os.utime(path, (old, old))
    # one world-readable restricted file, where the platform supports it
    with contextlib.suppress(OSError):
        os.chmod(ROOT / "vendor/exchange/line1.L5X", 0o666)
    print(f"wrote {len(FILES)} fabricated files and {len(ARCHIVES)} archive(s) "
          f"to {ROOT}")


if __name__ == "__main__":
    main()
