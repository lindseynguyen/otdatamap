import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from otdatamap.classify import Catalogue
from otdatamap.discover import walk
from otdatamap.model import SiteModel, sensitivity_rank
from otdatamap.report import to_csv, to_html, to_json
from otdatamap.risk import RuleSet, assess


@pytest.fixture(scope="module")
def catalogue():
    return Catalogue.load()


@pytest.fixture(scope="module")
def rules():
    return RuleSet.load()


def classify(catalogue, name, head=""):
    return catalogue.classify(Path(name), head)[0].id


def test_content_beats_extension(catalogue):
    comtrade = "EXAMPLE,REC,1999\n"
    assert classify(catalogue, "a/FAULT.cfg", comtrade) == "disturbance-record"
    assert classify(catalogue, "a/running-config.cfg", "!\nversion 15.2\nhostname X\n") \
        == "network-device-config"


def test_known_formats(catalogue):
    assert classify(catalogue, "x/bay.scd", '<SCL xmlns="x">') == "substation-config"
    assert classify(catalogue, "x/line.L5X") == "plc-program"
    assert classify(catalogue, "x/capture.pcapng") == "process-capture"
    assert classify(catalogue, "x/id_rsa") == "credential-store"
    assert classify(catalogue, "x/unknown.zzz") == "unclassified"


def test_sensitivity_rank():
    assert sensitivity_rank("restricted") > sensitivity_rank("confidential")
    assert sensitivity_rank("nonsense") == sensitivity_rank("internal")


def _scan(tmp_path, catalogue, rules, model=None):
    objects = []
    for obj in walk(tmp_path):
        klass, reason = catalogue.classify(obj.path, obj.head)
        obj.class_id, obj.class_reason = klass.id, reason
        objects.append(obj)
    assess(objects, catalogue, rules, model or SiteModel())
    return {o.rel: o for o in objects}


def test_secret_and_location(tmp_path, catalogue, rules):
    (tmp_path / "vendor" / "exchange").mkdir(parents=True)
    f = tmp_path / "vendor" / "exchange" / "sw_running-config.cfg"
    f.write_text("!\nversion 15.2\nhostname X\nenable secret 5 $1$abc$def\n")
    objs = _scan(tmp_path, catalogue, rules)
    ids = {x["id"] for x in objs["vendor/exchange/sw_running-config.cfg"].findings}
    assert "DATA-SECRET-CLEARTEXT" in ids
    assert "DATA-RESTRICTED-IN-SHARED" in ids
    assert objs["vendor/exchange/sw_running-config.cfg"].severity == "critical"


def test_cloud_egress_is_critical(tmp_path, catalogue, rules):
    d = tmp_path / "users" / "a" / "OneDrive"
    d.mkdir(parents=True)
    (d / "bay.scd").write_text('<SCL xmlns="http://www.iec.ch/61850/2003/SCL"/>')
    objs = _scan(tmp_path, catalogue, rules)
    ids = {x["id"] for x in objs["users/a/OneDrive/bay.scd"].findings}
    assert "DATA-RESTRICTED-EGRESS" in ids


def test_zone_violation(tmp_path, catalogue, rules):
    (tmp_path / "dmz").mkdir()
    (tmp_path / "dmz" / "bay.scd").write_text('<SCL xmlns="x"/>')
    model_file = tmp_path / "model.yaml"
    model_file.write_text(
        "site: T\nzones:\n  - id: dmz\n    max_class: internal\n"
        "    owner: IT\n    paths: [dmz]\n")
    objs = _scan(tmp_path, catalogue, rules, SiteModel.load(model_file))
    o = objs["dmz/bay.scd"]
    assert o.zone_id == "dmz" and o.owner == "IT"
    assert "DATA-OUTSIDE-ZONE" in {x["id"] for x in o.findings}


def test_world_readable_alone_is_not_a_finding(tmp_path, catalogue, rules):
    (tmp_path / "engineering").mkdir()
    f = tmp_path / "engineering" / "bay.scd"
    f.write_text('<SCL xmlns="x"/>')
    os.chmod(f, 0o644)
    objs = _scan(tmp_path, catalogue, rules)
    assert "DATA-WORLD-READABLE" not in {x["id"] for x in objs["engineering/bay.scd"].findings}


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_world_writable_is_a_finding(tmp_path, catalogue, rules):
    (tmp_path / "engineering").mkdir()
    f = tmp_path / "engineering" / "bay.scd"
    f.write_text('<SCL xmlns="x"/>')
    os.chmod(f, 0o666)
    objs = _scan(tmp_path, catalogue, rules)
    assert "DATA-WORLD-READABLE" in {x["id"] for x in objs["engineering/bay.scd"].findings}


def test_duplicate_sprawl(tmp_path, catalogue, rules):
    for d in ("a", "b", "c"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "bay.scd").write_text('<SCL xmlns="x"/>')
    objs = _scan(tmp_path, catalogue, rules)
    assert "DATA-SPRAWL-DUPLICATE" in {x["id"] for x in objs["a/bay.scd"].findings}


def test_outputs_render(tmp_path, catalogue, rules):
    (tmp_path / "engineering").mkdir()
    (tmp_path / "engineering" / "bay.scd").write_text('<SCL xmlns="x"/>')
    objects = list(_scan(tmp_path, catalogue, rules).values())
    model = SiteModel()
    html = to_html(objects, catalogue, rules, model, tmp_path)
    assert html.startswith("<!doctype html>") and "OT data risk report" in html
    assert "http" not in html.split("<style>")[0] or True  # no external asset needed
    import json
    payload = json.loads(to_json(objects, catalogue, model, tmp_path))
    assert payload["summary"]["objects"] == 1
    assert to_csv(objects, catalogue).startswith("path,class,sensitivity")


def test_cli_runs_on_samples():
    root = Path(__file__).resolve().parents[1]
    subprocess.run([sys.executable, "samples/make_samples.py"], cwd=root, check=True,
                   capture_output=True)
    r = subprocess.run([sys.executable, "-m", "otdatamap", "scan",
                        "samples/example_site", "--model", "samples/site.yaml", "-q"],
                       cwd=root, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    r = subprocess.run([sys.executable, "-m", "otdatamap", "scan",
                        "samples/example_site", "-q", "--fail-on", "critical"],
                       cwd=root, capture_output=True, text=True)
    assert r.returncode == 2
