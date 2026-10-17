"""Study material: understand the data before judging it.

The gap this serves runs both ways. An IT security engineer knows ACLs and
threat models but has never opened an SCD; a protection engineer knows the
substation but was never told what "Everyone:(RX)" means. Both are usually in
the same meeting.

Lessons live in rules/lessons.yaml. What an adversary gains is NOT written
there: it is generated from attack_ics.yaml, so the teaching and the engine
cannot drift apart.
"""

from __future__ import annotations

import html
import random
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .attack import AttackMap
from .util import load_yaml

DEFAULT_LESSONS = Path(__file__).parent / "rules" / "lessons.yaml"

TRACKS = {
    "it": "OT explained for people who know IT security",
    "ot": "IT security explained for people who know the plant",
    "both": "Useful from either side",
}


@dataclass
class Lesson:
    id: str
    title: str
    track: str = "both"
    data_class: str = ""
    what: str = ""
    bridge: str = ""
    why: str = ""
    check: List[str] = field(default_factory=list)
    terms: List[str] = field(default_factory=list)
    read: List[str] = field(default_factory=list)


@dataclass
class Syllabus:
    lessons: List[Lesson] = field(default_factory=list)
    glossary: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Syllabus":
        data = load_yaml(path or DEFAULT_LESSONS) or {}
        lessons = []
        for raw in data.get("lessons", []) or []:
            lessons.append(Lesson(
                id=str(raw["id"]),
                title=str(raw.get("title") or raw["id"]),
                track=str(raw.get("track") or "both"),
                data_class=str(raw.get("data_class") or ""),
                what=" ".join(str(raw.get("what", "")).split()),
                bridge=" ".join(str(raw.get("bridge", "")).split()),
                why=" ".join(str(raw.get("why", "")).split()),
                check=[" ".join(str(c).split()) for c in (raw.get("check") or [])],
                terms=[str(t) for t in (raw.get("terms") or [])],
                read=[str(r) for r in (raw.get("read") or [])],
            ))
        glossary = {str(k): " ".join(str(v).split())
                    for k, v in (data.get("glossary") or {}).items()}
        return cls(lessons=lessons, glossary=glossary)

    def get(self, lesson_id: str) -> Optional[Lesson]:
        for lesson in self.lessons:
            if lesson.id == lesson_id:
                return lesson
        return None

    def for_class(self, class_id: str) -> Optional[Lesson]:
        for lesson in self.lessons:
            if lesson.data_class == class_id:
                return lesson
        return None

    def by_track(self, track: Optional[str]) -> List[Lesson]:
        if not track or track == "all":
            return list(self.lessons)
        return [x for x in self.lessons if x.track in (track, "both")]

    def unknown_terms(self) -> List[str]:
        missing = set()
        for lesson in self.lessons:
            missing.update(t for t in lesson.terms if t not in self.glossary)
        return sorted(missing)


# ------------------------------------------------------------------ rendering
def _wrap(text: str, indent: str = "  ", width: int = 78) -> str:
    return textwrap.fill(text, width, initial_indent=indent, subsequent_indent=indent)


def attacker_note(lesson: Lesson, amap: AttackMap) -> List[str]:
    """Generated from the ATT&CK mapping, never hand-written here."""
    spec = amap.class_enables.get(lesson.data_class) if lesson.data_class else None
    if not spec:
        return []
    out = []
    why = " ".join((spec.get("why") or "").split())
    if why:
        out.append(why)
    for tid in spec.get("techniques", []):
        tech = amap.techniques.get(str(tid))
        if tech:
            tactics = ", ".join(amap.tactic_name(t) for t in tech.tactics)
            out.append(f"{tech.id}  {tech.name}  ({tactics})")
    return out


def render(lesson: Lesson, syllabus: Syllabus, amap: AttackMap) -> str:
    out = [f"{lesson.title}", "=" * min(len(lesson.title), 78),
           f"[{lesson.id}] track: {lesson.track}"
           + (f" | data class: {lesson.data_class}" if lesson.data_class else "")]
    for label, body in (("What it is", lesson.what),
                        ("Coming from the other side", lesson.bridge),
                        ("Why it matters", lesson.why)):
        if body:
            out += ["", label, _wrap(body)]
    notes = attacker_note(lesson, amap)
    if notes:
        out += ["", "What an adversary gains"]
        out.append(_wrap(notes[0]))
        for note in notes[1:]:
            out.append(f"    {note}")
    if lesson.check:
        out += ["", "Go and look"]
        out += [_wrap(f"- {c}", indent="  ") for c in lesson.check]
    if lesson.terms:
        out += ["", "Terms"]
        for term in lesson.terms:
            definition = syllabus.glossary.get(term, "")
            out.append(_wrap(f"{term}: {definition}", indent="    "))
    if lesson.read:
        out += ["", "Read next"]
        out += [f"    {r}" for r in lesson.read]
    return "\n".join(out)


def index(syllabus: Syllabus, track: Optional[str] = None) -> str:
    out = []
    for key in ("it", "ot", "both"):
        if track and track != "all" and key != track and key != "both":
            continue
        group = [x for x in syllabus.lessons if x.track == key]
        if not group:
            continue
        out.append(f"\n{TRACKS[key]}")
        out.append("-" * 78)
        for lesson in group:
            tag = f" ({lesson.data_class})" if lesson.data_class else ""
            out.append(f"  {lesson.id:<24} {lesson.title}{tag}")
    out.append(f"\n{len(syllabus.glossary)} glossary terms: "
               "otdatamap learn --glossary")
    return "\n".join(out)


# ----------------------------------------------------------------------- quiz
def build_quiz(syllabus: Syllabus, amap: AttackMap, track: Optional[str] = None,
               count: int = 8, seed: Optional[int] = None) -> List[dict]:
    rng = random.Random(seed)
    pool: List[dict] = []
    lessons = [x for x in syllabus.by_track(track) if x.what]

    titles = [x.title for x in lessons]
    for lesson in lessons:
        others = [t for t in titles if t != lesson.title]
        if len(others) < 3:
            continue
        pool.append({
            "question": f"Which topic is this? “{lesson.what}”",
            "answer": lesson.title,
            "options": rng.sample(others, 3) + [lesson.title],
            "why": lesson.why or lesson.bridge,
        })

    def first_sentence(text: str) -> str:
        # split on ". " so that "IEEE C37.111" survives intact
        head = text.split(". ")[0].rstrip(".")
        return head

    terms = [t for t in syllabus.glossary if len(syllabus.glossary[t]) > 20]
    for term in terms:
        answer = first_sentence(syllabus.glossary[term])
        others = [first_sentence(syllabus.glossary[t]) for t in terms
                  if t != term and first_sentence(syllabus.glossary[t]) != answer]
        if len(others) < 3:
            continue
        pool.append({
            "question": f"What is {term}?",
            "answer": answer,
            "options": rng.sample(others, 3) + [answer],
            "why": syllabus.glossary[term],
        })

    all_techniques = list(amap.techniques.values())
    for lesson in lessons:
        spec = amap.class_enables.get(lesson.data_class) if lesson.data_class else None
        if not spec or not spec.get("techniques"):
            continue
        mine = {str(t) for t in spec["techniques"]}
        correct = amap.techniques.get(str(spec["techniques"][0]))
        distractors = [t for t in all_techniques if t.id not in mine]
        if correct is None or len(distractors) < 3:
            continue
        pool.append({
            "question": f"Which ATT&CK for ICS technique does {lesson.title} "
                        f"most directly pay for?",
            "answer": f"{correct.id} {correct.name}",
            "options": [f"{d.id} {d.name}" for d in rng.sample(distractors, 3)]
                       + [f"{correct.id} {correct.name}"],
            "why": " ".join((spec.get("why") or "").split()),
        })

    rng.shuffle(pool)
    quiz = pool[:count]
    for item in quiz:
        rng.shuffle(item["options"])
    return quiz


def quiz_sheet(quiz: List[dict]) -> str:
    """Printable version, for when nobody is at the keyboard."""
    out = ["Study questions", "=" * 78]
    for n, item in enumerate(quiz, 1):
        out.append(f"\n{n}. {item['question']}")
        for letter, option in zip("abcd", item["options"]):
            out.append(f"   {letter}) {option}")
    out += ["", "", "Answers", "-" * 78]
    for n, item in enumerate(quiz, 1):
        out.append(f"{n}. {item['answer']}")
        if item["why"]:
            out.append(_wrap(item["why"], indent="   "))
    return "\n".join(out)


def run_quiz(quiz: List[dict], read_input=input, write=print) -> int:
    score = 0
    for n, item in enumerate(quiz, 1):
        write(f"\n{n}/{len(quiz)}  {item['question']}")
        for letter, option in zip("abcd", item["options"]):
            write(f"   {letter}) {option}")
        try:
            given = read_input("your answer (a-d, or q to stop): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            write("")
            break
        if given == "q":
            break
        chosen = dict(zip("abcd", item["options"])).get(given)
        if chosen == item["answer"]:
            score += 1
            write("   correct")
        else:
            write(f"   not quite - {item['answer']}")
        if item["why"]:
            write(_wrap(item["why"], indent="   "))
    write(f"\n{score} of {len(quiz)}")
    return score


# ----------------------------------------------------------------- study pack
def to_html(syllabus: Syllabus, amap: AttackMap, track: Optional[str] = None,
            quiz: Optional[List[dict]] = None) -> str:
    from .report import CSS

    def e(x):
        return html.escape(str(x))

    lessons = syllabus.by_track(track)
    toc = "".join(f'<li><a href="#{e(x.id)}">{e(x.title)}</a> '
                  f'<span class="sr">{e(x.track)}</span></li>' for x in lessons)
    blocks = []
    for lesson in lessons:
        parts = [f'<h2 id="{e(lesson.id)}">{e(lesson.title)}</h2>',
                 f'<p class="note">{e(lesson.id)} &middot; track {e(lesson.track)}'
                 + (f' &middot; data class <code>{e(lesson.data_class)}</code>'
                    if lesson.data_class else "") + "</p>"]
        for label, body in (("What it is", lesson.what),
                            ("Coming from the other side", lesson.bridge),
                            ("Why it matters", lesson.why)):
            if body:
                parts.append(f"<h3>{label}</h3><p>{e(body)}</p>")
        notes = attacker_note(lesson, amap)
        if notes:
            items = "".join(f"<li><code>{e(n.split('  ')[0])}</code> "
                            f"{e('  '.join(n.split('  ')[1:]))}</li>" for n in notes[1:])
            parts.append(f"<h3>What an adversary gains</h3><p>{e(notes[0])}</p>"
                         f"<ul>{items}</ul>")
        if lesson.check:
            parts.append("<h3>Go and look</h3><ul>"
                         + "".join(f"<li>{e(c)}</li>" for c in lesson.check) + "</ul>")
        if lesson.terms:
            rows = "".join(f"<tr><td><b>{e(t)}</b></td>"
                           f"<td>{e(syllabus.glossary.get(t, ''))}</td></tr>"
                           for t in lesson.terms)
            parts.append(f"<h3>Terms</h3><table>{rows}</table>")
        if lesson.read:
            parts.append("<h3>Read next</h3><ul>"
                         + "".join(f"<li>{e(r)}</li>" for r in lesson.read) + "</ul>")
        blocks.append("<section>" + "".join(parts) + "</section>")

    quiz_html = ""
    if quiz:
        questions = []
        for item in quiz:
            options = "".join(f"<li>{e(o)}</li>" for o in item["options"])
            questions.append(f"<li><b>{e(item['question'])}</b><ol type='a'>{options}"
                             f"</ol></li>")
        answers = "".join(f"<li>{e(item['answer'])}"
                          + (f"<div class='sr'>{e(item['why'])}</div>"
                             if item["why"] else "") + "</li>" for item in quiz)
        quiz_html = (f"<h2 id='quiz'>Study questions</h2><ol>{''.join(questions)}</ol>"
                     f"<h3>Answers</h3><ol>{answers}</ol>")

    glossary_rows = "".join(f"<tr><td><b>{e(k)}</b></td><td>{e(v)}</td></tr>"
                            for k, v in sorted(syllabus.glossary.items()))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OT data: a study pack</title><style>{CSS}
h3{{font-size:14px;margin:16px 0 4px;color:var(--muted);text-transform:uppercase;
letter-spacing:.05em}}
section{{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:18px 22px;margin:14px 0}}
a{{color:var(--accent)}} ul,ol{{padding-left:20px}}
</style></head><body><div class="wrap">
<h1>OT data: a study pack</h1>
<div class="sub">Generated by OTDataMap. The "what an adversary gains" sections are
generated from the tool's own ATT&amp;CK for ICS mapping, so they match what the
scanner reports.</div>
<h2>Contents</h2><ul>{toc}</ul>
{''.join(blocks)}
{quiz_html}
<h2>Glossary</h2><table>{glossary_rows}</table>
<footer>Lessons are editable in <code>otdatamap/rules/lessons.yaml</code>.
A lesson that is wrong for your plant is a bug worth reporting.</footer>
</div></body></html>"""
