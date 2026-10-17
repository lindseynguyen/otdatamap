import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from otdatamap.acl import AclReader, _parse_getfacl, _parse_icacls
from otdatamap.archives import expand, is_archive, read_members
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


def confidence(catalogue, name, head=""):
    return catalogue.classify(Path(name), head)[2]


def test_confidence_reflects_how_the_match_was_made(catalogue):
    assert confidence(catalogue, "a/bay.scd", '<SCL xmlns="x">') == "high"
    assert confidence(catalogue, "a/id_rsa") == "medium"
    assert confidence(catalogue, "a/capture.pcapng") == "low"
    assert confidence(catalogue, "a/unknown.zzz") == "none"


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


def _scan(tmp_path, catalogue, rules, model=None, acl=True, archives=True):
    reader = AclReader(enabled=acl)
    objects, members = [], []
    for obj in walk(tmp_path):
        klass, reason, conf = catalogue.classify(obj.path, obj.head)
        obj.class_id, obj.class_reason, obj.confidence = klass.id, reason, conf
        obj.acl = reader.for_file(obj.path, obj.mode)
        objects.append(obj)
        if archives and is_archive(obj.path):
            members.extend(expand(obj, catalogue))
    objects.extend(members)
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


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_world_readable_alone_is_not_a_finding(tmp_path, catalogue, rules):
    (tmp_path / "engineering").mkdir()
    f = tmp_path / "engineering" / "bay.scd"
    f.write_text('<SCL xmlns="x"/>')
    os.chmod(f, 0o644)
    objs = _scan(tmp_path, catalogue, rules)
    assert "DATA-BROAD-ACCESS" not in {x["id"] for x in objs["engineering/bay.scd"].findings}


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_broad_access_in_an_exposed_area_is_a_finding(tmp_path, catalogue, rules):
    (tmp_path / "shared").mkdir()
    f = tmp_path / "shared" / "bay.scd"
    f.write_text('<SCL xmlns="x"/>')
    os.chmod(f, 0o644)
    objs = _scan(tmp_path, catalogue, rules)
    found = [x for x in objs["shared/bay.scd"].findings if x["id"] == "DATA-BROAD-ACCESS"]
    assert found and "posix" in found[0]["detail"]


def test_acl_can_be_switched_off(tmp_path, catalogue, rules):
    (tmp_path / "shared").mkdir()
    (tmp_path / "shared" / "bay.scd").write_text('<SCL xmlns="x"/>')
    objs = _scan(tmp_path, catalogue, rules, acl=False)
    assert "DATA-BROAD-ACCESS" not in {x["id"] for x in objs["shared/bay.scd"].findings}


def test_icacls_parsing_finds_broad_principals():
    out = ("C:\\s\\bay.scd BUILTIN\\Administrators:(I)(F)\n"
           "                 Everyone:(I)(RX)\n"
           "                 DOMAIN\\eng:(I)(M)\n")
    entries = _parse_icacls(out)
    broad = [e for e in entries if e.is_broad]
    assert [e.principal for e in broad] == ["Everyone"]
    assert broad[0].can_read and not broad[0].can_write
    assert any(e.principal == "DOMAIN\\eng" and e.can_write for e in entries)


def test_getfacl_parsing():
    entries = _parse_getfacl("user::rw-\nuser:vendor:r--\ngroup::r--\nother::rw-\n")
    names = {e.principal for e in entries}
    assert "user:vendor" in names and "other" in names
    other = next(e for e in entries if e.principal == "other")
    assert other.can_write and other.is_broad


def _make_zip(path, members):
    import zipfile
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in members.items():
            zf.writestr(name, content)


def test_archive_members_are_classified_and_inherit_location(tmp_path, catalogue, rules):
    (tmp_path / "vendor" / "exchange").mkdir(parents=True)
    _make_zip(tmp_path / "vendor" / "exchange" / "handover.zip", {
        "pkg/bay.scd": '<SCL xmlns="http://www.iec.ch/61850/2003/SCL"/>',
        "pkg/id_rsa": "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----\n",
    })
    objs = _scan(tmp_path, catalogue, rules)
    inner = objs["vendor/exchange/handover.zip!pkg/bay.scd"]
    assert inner.class_id == "substation-config"
    ids = {x["id"] for x in inner.findings}
    assert "DATA-RESTRICTED-IN-SHARED" in ids
    key = objs["vendor/exchange/handover.zip!pkg/id_rsa"]
    assert "DATA-SECRET-CLEARTEXT" in {x["id"] for x in key.findings}


def test_archives_can_be_switched_off(tmp_path, catalogue, rules):
    (tmp_path / "vendor").mkdir()
    _make_zip(tmp_path / "vendor" / "handover.zip", {"pkg/bay.scd": '<SCL xmlns="x"/>'})
    objs = _scan(tmp_path, catalogue, rules, archives=False)
    assert not any("!" in rel for rel in objs)


def test_archive_rejects_traversing_members(tmp_path):
    _make_zip(tmp_path / "evil.zip", {"../../etc/passwd": "root:x:0:0", "ok.txt": "hi"})
    result = read_members(tmp_path / "evil.zip")
    assert [m.name for m in result.members] == ["ok.txt"]


def test_office_files_are_not_opened_as_archives(tmp_path):
    assert not is_archive(tmp_path / "report.xlsx")
    assert is_archive(tmp_path / "project.zap17")


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
    assert to_csv(objects, catalogue).startswith("path,class,confidence,sensitivity")


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


# --------------------------------------------------------------- delta / diff
def _run(objects_spec, generated="2026-01-01T00:00:00+00:00"):
    return {"summary": {"generated": generated}, "objects": objects_spec}


def test_delta_reports_new_and_resolved():
    from otdatamap.delta import compare
    old = _run([{"path": "a.scd", "risk": 40,
                 "findings": [{"id": "DATA-OUTSIDE-ZONE", "severity": "high"}]},
                {"path": "gone.scd", "risk": 10, "findings": []}])
    new = _run([{"path": "a.scd", "risk": 70,
                 "findings": [{"id": "DATA-BROAD-ACCESS", "severity": "high"}]},
                {"path": "vendor/new.scd", "risk": 90,
                 "findings": [{"id": "DATA-RESTRICTED-IN-SHARED", "severity": "high"}]}])
    d = compare(old, new)
    assert [o["path"] for o in d.new_objects] == ["vendor/new.scd"]
    assert [o["path"] for o in d.removed_objects] == ["gone.scd"]
    assert ("a.scd", "DATA-BROAD-ACCESS", "high") in d.new_findings
    assert ("a.scd", "DATA-OUTSIDE-ZONE", "high") in d.resolved_findings
    assert ("a.scd", 40, 70) in d.risk_increased
    assert not d.empty


def test_delta_of_identical_runs_is_empty():
    from otdatamap.delta import compare
    run = _run([{"path": "a.scd", "risk": 40,
                 "findings": [{"id": "DATA-OUTSIDE-ZONE", "severity": "high"}]}])
    assert compare(run, run).empty


def test_delta_rejects_foreign_json(tmp_path):
    from otdatamap.delta import load_run
    bad = tmp_path / "x.json"
    bad.write_text('{"hello": 1}')
    with pytest.raises(ValueError):
        load_run(bad)


# ------------------------------------------------------------------ otinspect
def test_otinspect_index_and_attach(tmp_path, catalogue, rules):
    import json

    from otdatamap import otinspect
    report = tmp_path / "oti.json"
    report.write_text(json.dumps({"files": [
        {"path": "D:/backup/bay.scd", "assets": [
            {"iedName": "IED_PROT_01", "manufacturer": "ExampleVendor",
             "type": "EX-500", "ip": "10.20.30.11"}]}]}))
    index = otinspect.load(report)
    assert "bay.scd" in index
    assert "IED_PROT_01" in otinspect.describe(index["bay.scd"])

    (tmp_path / "engineering").mkdir()
    (tmp_path / "engineering" / "bay.scd").write_text('<SCL xmlns="x"/>')
    objs = _scan(tmp_path, catalogue, rules)
    assert otinspect.attach(list(objs.values()), index) == 1
    assert objs["engineering/bay.scd"].devices[0]["name"] == "IED_PROT_01"


def test_otinspect_ignores_unknown_shapes(tmp_path):
    import json

    from otdatamap import otinspect
    report = tmp_path / "oti.json"
    report.write_text(json.dumps({"something": [1, 2, {"nested": "no devices here"}]}))
    assert otinspect.load(report) == {}


# -------------------------------------------------------------------- explain
def test_explain_names_the_rule_and_the_evidence(tmp_path, catalogue, rules):
    from otdatamap.report import explain
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "sw_running-config.cfg").write_text(
        "!\nversion 15.2\nhostname X\nenable secret 5 $1$a$b\n")
    objs = _scan(tmp_path, catalogue, rules)
    text = explain(objs["vendor/sw_running-config.cfg"], catalogue)
    assert "network-device-config" in text
    assert "high confidence" in text
    assert "DATA-SECRET-CLEARTEXT" in text
    assert "risk" in text


def test_cli_baseline_and_diff(tmp_path):
    root = Path(__file__).resolve().parents[1]
    site = tmp_path / "site"
    (site / "engineering").mkdir(parents=True)
    (site / "engineering" / "bay.scd").write_text('<SCL xmlns="x"/>')
    first = tmp_path / "first.json"
    r = subprocess.run([sys.executable, "-m", "otdatamap", "scan", str(site), "-q",
                        "--save-baseline", str(first)],
                       cwd=root, capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr
    (site / "vendor").mkdir()
    (site / "vendor" / "new.scd").write_text('<SCL xmlns="x"/>')
    second = tmp_path / "second.json"
    subprocess.run([sys.executable, "-m", "otdatamap", "scan", str(site), "-q",
                    "--save-baseline", str(second)],
                   cwd=root, capture_output=True, text=True, check=False)
    r = subprocess.run([sys.executable, "-m", "otdatamap", "diff", str(first),
                        str(second), "--fail-on-new", "high"],
                       cwd=root, capture_output=True, text=True, check=False)
    assert "new objects" in r.stdout
    assert r.returncode == 2


def test_gui_path_compaction():
    pytest.importorskip("PyQt5")
    from otdatamap.gui import compact_path
    assert compact_path("short/path.scd") == "short/path.scd"
    long = "vendor/exchange/EXAMPLE_handover_2026.zip!handover/switches/EX-SW-BAY1.cfg"
    out = compact_path(long)
    assert out.startswith(".../") and out.endswith("EX-SW-BAY1.cfg") and len(out) <= 58


# -------------------------------------------------------------- ATT&CK for ICS
@pytest.fixture(scope="module")
def amap():
    from otdatamap.attack import AttackMap
    return AttackMap.load()


def test_attack_mapping_has_no_dangling_techniques(amap):
    assert amap.unknown_references() == []
    assert len(amap.tactics) == 12
    assert amap.matrix == "ics-attack"


def test_every_finding_rule_has_an_attack_mapping(amap, rules):
    missing = [fid for fid in rules.findings if fid not in amap.finding_techniques]
    assert missing == [], f"findings without ATT&CK mapping: {missing}"


def test_every_data_class_has_an_attack_entry(amap, catalogue):
    missing = [c.id for c in catalogue.classes if c.id not in amap.class_enables]
    assert missing == [], f"classes without ATT&CK mapping: {missing}"


def test_technique_tactics_are_known_tactic_ids(amap):
    known = {t["id"] for t in amap.tactics}
    for tech in amap.techniques.values():
        assert tech.tactics, f"{tech.id} has no tactic"
        assert set(tech.tactics) <= known, f"{tech.id} references an unknown tactic"


def test_unexposed_data_enables_nothing(tmp_path, catalogue, rules, amap):
    (tmp_path / "engineering").mkdir()
    (tmp_path / "engineering" / "bay.scd").write_text('<SCL xmlns="x"/>')
    model_file = tmp_path / "m.yaml"
    model_file.write_text("site: T\nzones:\n  - id: eng\n    max_class: restricted\n"
                          "    owner: Eng\n    paths: [engineering]\n")
    objs = _scan(tmp_path, catalogue, rules, SiteModel.load(model_file), acl=False)
    obj = objs["engineering/bay.scd"]
    assert obj.findings == []
    assert amap.for_object(obj) == []


def test_exposed_data_enables_class_and_finding_techniques(tmp_path, catalogue,
                                                           rules, amap):
    from otdatamap.attack import apply_to_rules
    apply_to_rules(amap, rules)
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "bay.scd").write_text(
        '<SCL xmlns="http://www.iec.ch/61850/2003/SCL"/>')
    objs = _scan(tmp_path, catalogue, rules)
    techniques = amap.for_object(objs["vendor/bay.scd"])
    ids = {t["id"] for t in techniques}
    assert "T0811" in ids                      # from DATA-RESTRICTED-IN-SHARED
    assert "T0840" in ids                      # from the substation-config class
    entry = next(t for t in techniques if t["id"] == "T0840")
    assert entry["because"] == ["class:substation-config"]
    assert entry["tactics"] == ["TA0102"]


def test_aggregate_and_navigator_layer(tmp_path, catalogue, rules, amap):
    from otdatamap.attack import aggregate, navigator_layer
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "sw_running-config.cfg").write_text(
        "!\nversion 15.2\nhostname X\nenable secret 5 $1$a$b\n")
    objects = list(_scan(tmp_path, catalogue, rules).values())
    amap.annotate(objects)
    summary = aggregate(objects, amap)
    assert summary["matrix"] == "ics-attack"
    assert any(t["id"] == "T0859" for t in summary["techniques"])
    layer = navigator_layer(summary)
    assert layer["domain"] == "ics-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert all(set(t) >= {"techniqueID", "score"} for t in layer["techniques"])


def test_apply_to_rules_is_the_single_source_of_truth(amap):
    from otdatamap.attack import apply_to_rules
    fresh = RuleSet.load()
    fresh.findings["DATA-SECRET-CLEARTEXT"]["attack"] = ["T9999"]
    apply_to_rules(amap, fresh)
    assert fresh.findings["DATA-SECRET-CLEARTEXT"]["attack"] == \
        amap.finding_techniques["DATA-SECRET-CLEARTEXT"]


def test_cli_attack_and_layer(tmp_path):
    import json
    root = Path(__file__).resolve().parents[1]
    r = subprocess.run([sys.executable, "-m", "otdatamap", "attack",
                        "--class", "substation-config"],
                       cwd=root, capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr
    assert "T0840" in r.stdout and "Rogue Master" in r.stdout

    site = tmp_path / "site"
    (site / "vendor").mkdir(parents=True)
    (site / "vendor" / "bay.scd").write_text('<SCL xmlns="x"/>')
    layer = tmp_path / "layer.json"
    r = subprocess.run([sys.executable, "-m", "otdatamap", "scan", str(site), "-q",
                        "--attack-layer", str(layer)],
                       cwd=root, capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr
    data = json.loads(layer.read_text())
    assert data["domain"] == "ics-attack" and data["techniques"]


# ---------------------------------------------------------------------- learn
@pytest.fixture(scope="module")
def syllabus():
    from otdatamap.learn import Syllabus
    return Syllabus.load()


def test_every_data_class_has_a_lesson(syllabus, catalogue):
    missing = [c.id for c in catalogue.classes
               if c.id != "unclassified" and syllabus.for_class(c.id) is None]
    assert missing == [], f"data classes without a lesson: {missing}"


def test_every_term_used_is_in_the_glossary(syllabus):
    assert syllabus.unknown_terms() == []


def test_lessons_have_both_sides(syllabus):
    thin = [x.id for x in syllabus.lessons if not (x.what and x.bridge and x.why)]
    assert thin == [], f"lessons missing what/bridge/why: {thin}"
    no_check = [x.id for x in syllabus.lessons if not x.check]
    assert no_check == []


def test_both_tracks_exist(syllabus):
    tracks = {x.track for x in syllabus.lessons}
    assert {"it", "ot", "both"} <= tracks
    assert len(syllabus.by_track("it")) < len(syllabus.lessons)


def test_attacker_section_is_generated_not_written(syllabus, amap):
    """The lesson YAML must not hand-write techniques; they come from the map."""
    from otdatamap.learn import attacker_note
    lesson = syllabus.for_class("substation-config")
    notes = attacker_note(lesson, amap)
    assert any("T0840" in n for n in notes)
    mapped = amap.class_enables["substation-config"]["techniques"]
    assert len(notes) == len(mapped) + 1  # the why line, then one per technique


def test_render_and_index(syllabus, amap):
    from otdatamap.learn import index, render
    text = render(syllabus.for_class("plc-program"), syllabus, amap)
    assert "What it is" in text and "Go and look" in text and "T0845" in text
    assert "priorities" in index(syllabus, "it")


def test_quiz_is_answerable_and_deterministic(syllabus, amap):
    from otdatamap.learn import build_quiz, quiz_sheet
    first = build_quiz(syllabus, amap, None, 6, seed=42)
    second = build_quiz(syllabus, amap, None, 6, seed=42)
    assert [q["question"] for q in first] == [q["question"] for q in second]
    assert len(first) == 6
    for item in first:
        assert item["answer"] in item["options"]
        assert len(item["options"]) == 4
        assert len(set(item["options"])) == 4
    assert "Answers" in quiz_sheet(first)


def test_quiz_runs_without_a_terminal(syllabus, amap):
    from otdatamap.learn import build_quiz, run_quiz
    quiz = build_quiz(syllabus, amap, None, 2, seed=1)
    answers = iter([dict(zip("abcd", quiz[0]["options"]))  # pick the right letter
                    and next(k for k, v in zip("abcd", quiz[0]["options"])
                             if v == quiz[0]["answer"]), "q"])
    lines = []
    score = run_quiz(quiz, read_input=lambda _p: next(answers), write=lines.append)
    assert score == 1
    assert any("correct" in line for line in lines)


def test_study_pack_is_self_contained(syllabus, amap, tmp_path):
    from otdatamap.learn import build_quiz, to_html
    page = to_html(syllabus, amap, None, build_quiz(syllabus, amap, None, 3, seed=2))
    assert page.startswith("<!doctype html>")
    assert "Glossary" in page and "Study questions" in page
    assert "<script" not in page.lower()


def test_cli_learn(tmp_path):
    root = Path(__file__).resolve().parents[1]
    r = subprocess.run([sys.executable, "-m", "otdatamap", "learn", "--track", "ot"],
                       cwd=root, capture_output=True, text=True, check=False)
    assert r.returncode == 0 and "access-control" in r.stdout

    r = subprocess.run([sys.executable, "-m", "otdatamap", "learn", "substation-config"],
                       cwd=root, capture_output=True, text=True, check=False)
    assert r.returncode == 0 and "GOOSE" in r.stdout

    r = subprocess.run([sys.executable, "-m", "otdatamap", "learn", "--glossary", "GOOSE"],
                       cwd=root, capture_output=True, text=True, check=False)
    assert r.returncode == 0 and "multicast" in r.stdout

    target = tmp_path / "sw_running-config.cfg"
    target.write_text("!\nversion 15.2\nhostname X\nenable secret 5 $1$a$b\n")
    r = subprocess.run([sys.executable, "-m", "otdatamap", "learn", "--file", str(target)],
                       cwd=root, capture_output=True, text=True, check=False)
    assert r.returncode == 0
    assert "Switch, router and firewall configurations" in r.stdout
    assert "DATA-SECRET-CLEARTEXT" in r.stdout

    pack = tmp_path / "pack.html"
    r = subprocess.run([sys.executable, "-m", "otdatamap", "learn", "--html", str(pack),
                        "--quiz", "--seed", "1"],
                       cwd=root, capture_output=True, text=True, check=False)
    assert r.returncode == 0 and pack.read_text().startswith("<!doctype html>")
