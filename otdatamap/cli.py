"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List

from . import __version__
from .classify import Catalogue
from .discover import DataObject, walk
from .learn import render
from .model import TEMPLATE, SiteModel
from .report import build_summary, explain, to_csv, to_html, to_json
from .risk import SEVERITY_ORDER, RuleSet
from .util import human_size

BANNER = "otdatamap %s - read-only OT data classification and risk analysis" % __version__


def _scan(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1

    catalogue = Catalogue.load()
    if args.classes:
        catalogue = catalogue.merge(Catalogue.load(Path(args.classes)))
    rules = RuleSet.load(Path(args.rules)) if args.rules else RuleSet.load()
    from .attack import AttackMap, aggregate, apply_to_rules, navigator_layer
    amap = AttackMap.load(Path(args.attack) if args.attack else None)
    apply_to_rules(amap, rules)
    model = SiteModel.load(Path(args.model)) if args.model else SiteModel()

    if not args.quiet:
        print(BANNER)
        print(f"scanning {root} ...")

    from .acl import AclReader
    from .archives import expand, is_archive

    acl_reader = AclReader(enabled=not args.no_acl)
    objects: List[DataObject] = []
    members: List[DataObject] = []
    for obj in walk(root, max_file_mb=args.max_file_mb):
        klass, reason, confidence = catalogue.classify(obj.path, obj.head)
        obj.class_id, obj.class_reason, obj.confidence = klass.id, reason, confidence
        obj.acl = acl_reader.for_file(obj.path, obj.mode)
        objects.append(obj)
        if not args.no_archives and is_archive(obj.path):
            members.extend(expand(obj, catalogue,
                                  max_members=args.max_archive_members))
    objects.extend(members)

    if args.from_otinspect:
        from . import otinspect
        try:
            index = otinspect.load(Path(args.from_otinspect))
        except (OSError, ValueError) as exc:
            print(f"error: cannot read {args.from_otinspect}: {exc}", file=sys.stderr)
            return 1
        matched = otinspect.attach(objects, index)
        if not args.quiet:
            print(f"OTInspect: {len(index)} files with devices, {matched} matched here")

    if not objects:
        print("no files found", file=sys.stderr)
        return 1

    from .risk import assess
    assess(objects, catalogue, rules, model)
    amap.annotate(objects)
    attack_summary = aggregate(objects, amap)

    summary = build_summary(objects, catalogue, model, root)
    if args.html:
        Path(args.html).write_text(
            to_html(objects, catalogue, rules, model, root, top=args.top,
                    attack_summary=attack_summary),
            encoding="utf-8")
    if args.json:
        Path(args.json).write_text(
            to_json(objects, catalogue, model, root, attack_summary), encoding="utf-8")
    if args.csv:
        Path(args.csv).write_text(to_csv(objects, catalogue), encoding="utf-8")

    payload = None
    if args.save_baseline or args.baseline:
        payload = json.loads(to_json(objects, catalogue, model, root, attack_summary))
    if args.save_baseline:
        Path(args.save_baseline).write_text(json.dumps(payload, indent=2,
                                                       ensure_ascii=False),
                                            encoding="utf-8")
    delta = None
    if args.baseline:
        from .delta import compare, load_run, text_summary
        try:
            baseline = load_run(Path(args.baseline))
        except (OSError, ValueError) as exc:
            print(f"error: cannot read baseline: {exc}", file=sys.stderr)
            return 1
        delta = compare(baseline, payload)

    if not args.quiet:
        sev = summary["severity"]
        inside = sum(1 for o in objects if "!" in o.rel)
        extra = f", {inside} inside archives" if inside else ""
        print(f"\n{summary['objects']} objects, {human_size(summary['bytes'])}, "
              f"{summary['restricted_objects']} restricted{extra}")
        print(f"  access control: {acl_reader.backend}")
        print("  " + "  ".join(f"{s}: {sev.get(s, 0)}" for s in
                               ["critical", "high", "medium", "low"]))
        enabled = attack_summary.get("techniques", [])
        if enabled:
            tactics = [t for t in attack_summary["tactics"] if t["techniques"]]
            print(f"\nATT&CK for ICS: {len(enabled)} techniques across "
                  f"{len(tactics)} tactics are paid for by this data")
            for t in enabled[:5]:
                print(f"  {t['id']:<12} {t['name']:<44} {t['objects']:>4} objects")
            if len(enabled) > 5:
                print(f"  ... {len(enabled) - 5} more "
                      f"(otdatamap scan ... --attack-layer layer.json)")
        if summary["findings"]:
            print("\nfindings:")
            for fid, count in sorted(summary["findings"].items(), key=lambda kv: -kv[1]):
                print(f"  {count:4d}  {fid}")
        if delta is not None:
            from .delta import text_summary
            print("\nchange since the baseline:")
            print(text_summary(delta))
        for out, label in ((args.html, "HTML"), (args.json, "JSON"), (args.csv, "CSV")):
            if out:
                print(f"\n{label}: {out}")

    if args.attack_layer:
        Path(args.attack_layer).write_text(
            json.dumps(navigator_layer(attack_summary,
                                       f"OTDataMap exposure - {root.name}"),
                       indent=2), encoding="utf-8")

    if args.explain:
        shown = [o for o in sorted(objects, key=lambda o: (-o.risk, o.rel))
                 if o.findings][:args.top]
        if shown:
            print("\nwhy these objects scored as they did:\n")
            for obj in shown:
                print(explain(obj, catalogue, rules))
                print()

    if args.fail_on:
        floor = SEVERITY_ORDER.index(args.fail_on)
        worst = max((SEVERITY_ORDER.index(o.severity) for o in objects), default=0)
        if worst >= floor:
            return 2
    return 0


def _init_model(args: argparse.Namespace) -> int:
    out = Path(args.output) if args.output else None
    if out and out.exists() and not args.force:
        print(f"error: {out} exists (use --force)", file=sys.stderr)
        return 1
    if out:
        out.write_text(TEMPLATE, encoding="utf-8")
        print(f"wrote {out}")
    else:
        sys.stdout.write(TEMPLATE)
    return 0


def _classes(args: argparse.Namespace) -> int:
    catalogue = Catalogue.load()
    if args.classes:
        catalogue = catalogue.merge(Catalogue.load(Path(args.classes)))
    print(f"{'id':26} {'sensitivity':13} {'impact':7} retention")
    for c in catalogue.classes:
        ret = f"{c.retention_days}d" if c.retention_days else "-"
        print(f"{c.id:26} {c.sensitivity:13} {c.impact_max:<7} {ret}   {c.title}")
    return 0


def _learn_about_file(path: Path, syllabus, amap, catalogue) -> int:
    """Anchor the lesson to a real file: classify it, then explain what it is."""
    from .acl import AclReader
    from .classify import is_textual
    from .discover import DataObject
    from .model import SiteModel
    from .report import explain
    from .risk import RuleSet, assess

    if not path.is_file():
        print(f"error: {path} is not a file", file=sys.stderr)
        return 1
    st = path.stat()
    head = ""
    if is_textual(path):
        raw = path.open("rb").read(262144)
        if b"\x00" not in raw[:2048]:
            head = raw.decode("utf-8", errors="replace")
    from datetime import datetime, timezone
    obj = DataObject(path=path, rel=path.name, size=st.st_size,
                     mtime=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc),
                     mode=st.st_mode & 0o777, head=head)
    klass, reason, confidence = catalogue.classify(path, head)
    obj.class_id, obj.class_reason, obj.confidence = klass.id, reason, confidence
    obj.acl = AclReader().for_file(path, obj.mode)
    rules = RuleSet.load()
    from .attack import apply_to_rules
    apply_to_rules(amap, rules)
    assess([obj], catalogue, rules, SiteModel())
    amap.annotate([obj])

    lesson = syllabus.for_class(klass.id)
    if lesson:
        print(render(lesson, syllabus, amap))
        print()
    else:
        print(f"No lesson yet for the class {klass.id}.\n")
    print("This file")
    print("-" * 78)
    print(explain(obj, catalogue))
    if not obj.findings:
        print("    nothing flagged - but it was judged on its own, with no site "
              "model and no neighbours to compare against")
    return 0


def _learn(args: argparse.Namespace) -> int:
    from .attack import AttackMap
    from .learn import Syllabus, build_quiz, index, quiz_sheet, run_quiz, to_html

    syllabus = Syllabus.load(Path(args.lessons) if args.lessons else None)
    amap = AttackMap.load(Path(args.attack) if args.attack else None)

    if args.html:
        quiz = build_quiz(syllabus, amap, args.track, args.quiz_n, args.seed) \
            if args.quiz else None
        Path(args.html).write_text(to_html(syllabus, amap, args.track, quiz),
                                   encoding="utf-8")
        print(f"study pack: {args.html}")
        return 0

    if args.glossary is not None:
        if args.glossary:
            definition = syllabus.glossary.get(args.glossary)
            if not definition:
                near = [t for t in syllabus.glossary
                        if args.glossary.lower() in t.lower()]
                print(f"no entry for {args.glossary}"
                      + (f" - did you mean {', '.join(near)}?" if near else ""),
                      file=sys.stderr)
                return 1
            print(f"{args.glossary}\n" + _wrap_text(definition))
        else:
            for term, definition in sorted(syllabus.glossary.items()):
                print(f"{term}\n" + _wrap_text(definition) + "\n")
        return 0

    if args.about_file:
        return _learn_about_file(Path(args.about_file), syllabus, amap,
                                 Catalogue.load())

    if args.quiz:
        quiz = build_quiz(syllabus, amap, args.track, args.quiz_n, args.seed)
        if not quiz:
            print("no questions could be built from these lessons", file=sys.stderr)
            return 1
        if args.sheet or not sys.stdin.isatty():
            print(quiz_sheet(quiz))
            return 0
        run_quiz(quiz)
        return 0

    if args.topic:
        lesson = syllabus.get(args.topic) or syllabus.for_class(args.topic)
        if lesson is None:
            print(f"no lesson called {args.topic}", file=sys.stderr)
            print(index(syllabus, args.track), file=sys.stderr)
            return 1
        print(render(lesson, syllabus, amap))
        return 0

    print(BANNER)
    print(index(syllabus, args.track))
    return 0


def _attack(args: argparse.Namespace) -> int:
    import textwrap

    from .attack import AttackMap
    amap = AttackMap.load(Path(args.attack) if args.attack else None)
    unknown = amap.unknown_references()
    if unknown:
        print(f"warning: mapping references unknown techniques: {', '.join(unknown)}",
              file=sys.stderr)

    print(f"{amap.matrix}: {len(amap.techniques)} techniques, "
          f"{len(amap.tactics)} tactics\n")
    print("What each data class pays for once an adversary holds it")
    print("=" * 72)
    for class_id, spec in amap.class_enables.items():
        if args.class_id and class_id != args.class_id:
            continue
        ids = spec.get("techniques") or []
        if not ids:
            continue
        print(f"\n{class_id}")
        for tid in ids:
            tech = amap.techniques.get(str(tid))
            if tech:
                tactics = ", ".join(amap.tactic_name(t) for t in tech.tactics)
                print(f"  {tech.id:<12} {tech.name:<46} {tactics}")
        why = " ".join((spec.get("why") or "").split())
        if why:
            print(textwrap.fill(why, 72, initial_indent="  > ", subsequent_indent="  > "))

    if not args.class_id:
        print("\n\nWhat each finding pays for, whatever the file is")
        print("=" * 72)
        for fid, ids in amap.finding_techniques.items():
            names = ", ".join(f"{t} {amap.techniques[t].name}" for t in ids
                              if t in amap.techniques)
            print(f"\n{fid}\n  {names}")
    return 0


def _diff(args: argparse.Namespace) -> int:
    from .delta import compare, load_run, text_summary
    try:
        old, new = load_run(Path(args.old)), load_run(Path(args.new))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    delta = compare(old, new)
    print(text_summary(delta))
    if args.json:
        Path(args.json).write_text(json.dumps(delta.as_dict(), indent=2,
                                              ensure_ascii=False), encoding="utf-8")
        print(f"\nJSON: {args.json}")
    if args.fail_on_new:
        floor = SEVERITY_ORDER.index(args.fail_on_new)
        if any(SEVERITY_ORDER.index(sev) >= floor for _p, _f, sev in delta.new_findings):
            return 2
    return 0


def _wrap_text(text: str) -> str:
    import textwrap
    return textwrap.fill(text, 78, initial_indent="  ", subsequent_indent="  ")


def _gui(_args: argparse.Namespace) -> int:
    from .gui import main as gui_main
    return gui_main()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="otdatamap", description=BANNER)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="classify a folder and score data risk")
    s.add_argument("path")
    s.add_argument("--model", help="site model YAML (zones, owners)")
    s.add_argument("--classes", help="extra or overriding classification rules (YAML)")
    s.add_argument("--rules", help="exposure and finding rules (YAML)")
    s.add_argument("--html", help="write an HTML report")
    s.add_argument("--json", help="write JSON output")
    s.add_argument("--csv", help="write a CSV data inventory")
    s.add_argument("--top", type=int, default=100, help="rows in the flagged table")
    s.add_argument("--max-file-mb", type=int, default=0,
                   help="skip reading files larger than this (0 = no limit)")
    s.add_argument("--no-acl", action="store_true",
                   help="skip reading access control lists")
    s.add_argument("--no-archives", action="store_true",
                   help="do not look inside zip / TIA archives")
    s.add_argument("--max-archive-members", type=int, default=2000,
                   help="members read per archive (default 2000)")
    s.add_argument("--from-otinspect", metavar="REPORT.JSON",
                   help="OTInspect JSON report: name the devices each file describes")
    s.add_argument("--baseline", metavar="RUN.JSON",
                   help="compare with an earlier run and report what changed")
    s.add_argument("--save-baseline", metavar="RUN.JSON",
                   help="write this run so a later scan can compare against it")
    s.add_argument("--attack", metavar="ATTACK.YAML",
                   help="override the ATT&CK for ICS mapping")
    s.add_argument("--attack-layer", metavar="LAYER.JSON",
                   help="write an ATT&CK Navigator layer of what this data enables")
    s.add_argument("--explain", action="store_true",
                   help="print why each flagged object scored as it did")
    s.add_argument("--fail-on", choices=SEVERITY_ORDER,
                   help="exit code 2 if any object reaches this severity")
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(func=_scan)

    m = sub.add_parser("init-model", help="print a starter site model")
    m.add_argument("-o", "--output")
    m.add_argument("--force", action="store_true")
    m.set_defaults(func=_init_model)

    learn = sub.add_parser("learn", help="study material on OT data, both directions")
    learn.add_argument("topic", nargs="?", help="lesson id, or a data class id")
    learn.add_argument("--track", choices=["it", "ot", "all"],
                       help="it = OT explained for IT people; "
                            "ot = IT security explained for plant people")
    learn.add_argument("--file", dest="about_file", metavar="PATH",
                       help="teach me about THIS file: classify it, then explain it")
    learn.add_argument("--glossary", nargs="?", const="", metavar="TERM",
                       help="print the glossary, or one term")
    learn.add_argument("--quiz", action="store_true", help="ask questions")
    learn.add_argument("--quiz-n", type=int, default=8, help="how many questions")
    learn.add_argument("--sheet", action="store_true",
                       help="print the quiz with its answers instead of asking")
    learn.add_argument("--seed", type=int, help="fix the question order")
    learn.add_argument("--lessons", help="use another lessons YAML")
    learn.add_argument("--attack", help="use another ATT&CK mapping")
    learn.add_argument("--html", help="write a self-contained study pack")
    learn.set_defaults(func=_learn)

    a = sub.add_parser("attack", help="show the ATT&CK for ICS mapping")
    a.add_argument("--attack", help="mapping file to show instead of the default")
    a.add_argument("--class", dest="class_id", help="only this data class")
    a.set_defaults(func=_attack)

    d = sub.add_parser("diff", help="compare two saved JSON runs")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("--json", help="write the delta as JSON")
    d.add_argument("--fail-on-new", choices=SEVERITY_ORDER,
                   help="exit code 2 if a new finding of this severity appeared")
    d.set_defaults(func=_diff)

    g = sub.add_parser("gui", help="open the desktop interface")
    g.set_defaults(func=_gui)

    c = sub.add_parser("classes", help="list the classification catalogue")
    c.add_argument("--classes", help="extra or overriding rules (YAML)")
    c.set_defaults(func=_classes)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
