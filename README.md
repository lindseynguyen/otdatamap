# OTDataMap

**Where does OT data actually live, how sensitive is it, and which copies are in the wrong place?**

Most OT security tooling looks at devices and traffic. OTDataMap looks at the *data*: the
substation configurations, PLC programs, historian exports, backups, drawings and rosters
that pile up on file shares, engineering laptops, vendor folders and somebody's OneDrive.

Point it at a folder and it produces a **data inventory with a classification and a risk
score for every object**, plus findings for the copies that should not be where they are.

It only **reads files**. It never connects to a device and never writes to the folder you scan.

> **Status: alpha.** Rules and scoring are deliberately simple and fully editable in YAML.
> If a file is misclassified, that is a bug worth reporting — the catalogue is the product.

```
19 objects, 67.1 KB, 10 restricted
  critical: 6  high: 2  medium: 4  low: 7

findings:
     5  DATA-RESTRICTED-IN-SHARED
     5  DATA-SECRET-CLEARTEXT
     4  DATA-OUTSIDE-ZONE
     4  DATA-UNDECLARED-STORE
     4  DATA-WORLD-READABLE
     3  DATA-SPRAWL-DUPLICATE
     1  DATA-RESTRICTED-EGRESS
     1  DATA-RETENTION-EXCEEDED
     1  DATA-STALE
```

## Try it in 30 seconds

No real data required — the repo ships a fabricated site:

```bash
pip install -e .
python samples/make_samples.py
otdatamap scan samples/example_site --model samples/site.yaml --html report.html
```

Open `report.html`. It is a single self-contained file: no network, no external assets,
light and dark theme, safe to hand to a plant manager.

## What it does

**1. Classifies every file into an OT data class.** 17 classes out of the box, matched by
extension, file name and content signature — content wins, so a COMTRADE `.cfg` is a
disturbance record and a Cisco `.cfg` is a device configuration.

| Class | Sensitivity | Why it matters |
|---|---|---|
| `substation-config` (SCD/ICD/CID/SSD) | restricted | Describes protection and GOOSE wiring of a whole bay |
| `plc-program` (L5X, TIA, XEF, CODESYS) | restricted | The control logic itself |
| `hmi-project`, `network-device-config`, `credential-store`, `system-backup` | restricted | |
| `process-capture`, `historian-export`, `engineering-drawing`, `asset-register`, `personal-data`, `firmware-image` | confidential | |
| `disturbance-record`, `log-data`, `device-description`, `vendor-document` | internal | |

`otdatamap classes` prints the full catalogue. Every entry carries a **sensitivity**, an
**impact rating** (safety / availability / integrity / confidentiality — safety and
availability weigh heaviest, which is what makes this an OT catalogue rather than an IT one)
and a **retention period**.

**2. Detects exposure.** For each object: where it sits (shared area, vendor folder,
cloud-synced folder, removable media, personal desktop), cleartext secrets inside it, weak
file permissions, identical copies spread across folders, age against its retention rule.

**3. Scores and explains.** Risk = class sensitivity and impact (max 45) + exposure signals
(max 55). Each finding carries the **IEC 62443-3-3 system requirements** it gives evidence
against and the related **MITRE ATT&CK for ICS** techniques, plus a remediation line.

| Rule | Severity | Raised when |
|---|---|---|
| `DATA-SECRET-CLEARTEXT` | critical | A password, SNMP community or private key sits in a data object |
| `DATA-RESTRICTED-EGRESS` | critical | Restricted data in a cloud-synced folder or on removable media |
| `DATA-RESTRICTED-IN-SHARED` | high | Restricted data in a shared, vendor or personal area |
| `DATA-OUTSIDE-ZONE` | high | Object above the maximum class its zone allows |
| `DATA-WORLD-READABLE` | high | World-writable, or world-readable in an exposed area |
| `DATA-SPRAWL-DUPLICATE` | medium | The same content in three or more folders |
| `DATA-UNDECLARED-STORE` | medium | Sensitive data in a folder the site model never mentions |
| `DATA-RETENTION-EXCEEDED` / `DATA-STALE` | medium | Kept too long, or a backup that stopped being refreshed |
| `DATA-NO-OWNER` | medium | Sensitive data in a zone with nobody named |

**4. Checks against your zones.** An optional site model maps folders to IEC 62443 zones
with a maximum data class, an SL-T and an owner. That turns *"this file looks sensitive"*
into *"this file is two classes above what its zone allows, and it belongs to Control
Systems Engineering"*.

```bash
otdatamap init-model -o site.yaml      # starter model, edit the paths
otdatamap scan /mnt/plant_share --model site.yaml --html report.html
```

```yaml
zones:
  - id: dmz
    name: IT/OT DMZ
    sl_t: 2
    max_class: internal        # anything above this is a finding
    owner: Plant IT
    paths: [dmz, transfer]
```

## Outputs

```bash
otdatamap scan ./site --html report.html --json inventory.json --csv inventory.csv
otdatamap scan ./site --fail-on high      # exit code 2 — use it in a pipeline
```

- **HTML** — summary cards, what data is here, sensitivity split, per-zone table, findings
  with 62443/ATT&CK mapping, and the flagged objects ranked by risk
- **JSON** — every object with its class, signals, findings and SHA-256
- **CSV** — the data inventory itself, ready for the register you have to maintain anyway

## Make it yours

The two YAML files under `otdatamap/rules/` are the whole brain of the tool, and both can be
overridden without touching code:

```bash
otdatamap scan ./site --classes my_classes.yaml --rules my_exposure.yaml
```

- `--classes` adds or replaces data classes (same `id` wins over the default)
- `--rules` changes path patterns, secret regexes, thresholds and severity bands

Site naming conventions differ everywhere, so the location patterns (`*/vendor*/*`,
`*/onedrive*/*`, …) are the first thing most people will want to edit.

## Install

```bash
git clone https://github.com/lindseynguyen/otdatamap.git
cd otdatamap
pip install -e .
```

Python 3.9+ and PyYAML. Nothing else.

## Scope and honesty

- It reads file **content** only for text-like files, and only the first 256 KB.
- It does not open proprietary binary projects (TIA, ACD, WinCC); those are classified by
  name and extension. Pair it with a parser-level tool when you need what is inside.
- Risk scores are a prioritisation aid, not an assessment. The 62443 and ATT&CK references
  are evidence pointers for a human assessor, not a compliance verdict.
- It cannot see access control lists, Active Directory groups, or who actually opened a file.
  "Who can read this" is still a question you have to answer with your own systems.

## Contributing

The most valuable contribution is a **class that is wrong for your plant**: a file type that
is misidentified, a vendor naming convention the patterns miss, or a data class that matters
where you work and is not in the catalogue. Open an issue with the file extension, a
sanitised name pattern and what it should be.

MIT licensed.
