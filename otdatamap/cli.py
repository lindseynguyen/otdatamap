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

    summary = build_summary(objects, catalogue, model, root)
    if args.html:
        Path(args.html).write_text(
            to_html(objects, catalogue, rules, model, root, top=args.top),
            encoding="utf-8")
    if args.json:
        Path(args.json).write_text(to_json(objects, catalogue, model, root), encoding="utf-8")
    if args.csv:
        Path(args.csv).write_text(to_csv(objects, catalogue), encoding="utf-8")

    payload = None
    if args.save_baseline or args.baseline:
        payload = json.loads(to_json(objects, catalogue, model, root))
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
