"""Renders the report data into ONE self-contained HTML file (jinja2, autoescape on; JSON embedded with <, > and & escaped)."""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..schema import from_iso_z
from .build import build_data

HERE = Path(__file__).resolve().parent
STATUS = {"confirmed": ("✔", "confirmed"), "partial": ("◐", "partial"), "unprovable": ("?", "unprovable"),
          "attempts_only": ("⚠", "attempts only")}


def safe_json(obj) -> str:
    """JSON for a <script type="application/json"> block: no raw <, > or & (so no closing tag or comment opener can appear)."""
    s = json.dumps(obj, sort_keys=True, ensure_ascii=True)
    return s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def timeline(data: dict) -> dict:
    """Positions (percent) of the stage bars and the attempts-only bars on a shared UTC axis."""
    rows = [("stage", s["stage"], s["status"], s["start_raw"], s["end_raw"]) for s in data["stages"]]
    rows += [("actor", a["ip"], "attempts_only", a["first_raw"], a["last_raw"]) for a in data["attempts_only"]]
    if not rows:
        return {"stages": [], "actors": [], "ticks": []}
    t = [(from_iso_z(r[3]), from_iso_z(r[4])) for r in rows]
    t0, t1 = min(a for a, _ in t), max(b for _, b in t)
    if t1 <= t0:
        t1 = t0 + timedelta(seconds=1)
    span = (t1 - t0).total_seconds()
    day = span >= 86400
    out = {"stages": [], "actors": []}
    for r, (a, b) in zip(rows, t):
        left = (a - t0).total_seconds() / span * 100
        width = max((b - a).total_seconds() / span * 100, 0.8)
        left = min(left, 100 - width)
        icon, label = STATUS[r[2]]
        out["stages" if r[0] == "stage" else "actors"].append(
            {"name": r[1], "status": r[2], "icon": icon, "label": label, "left": round(left, 3), "width": round(width, 3),
             "start": a.strftime("%Y-%m-%dT%H:%M:%SZ"), "end": b.strftime("%Y-%m-%dT%H:%M:%SZ")})
    fmt = "%m-%d %H:%M:%S" if day else "%H:%M:%S"
    out["ticks"] = [{"pos": round(i * 20, 1), "label": (t0 + timedelta(seconds=span * i / 5)).strftime(fmt)} for i in range(6)]
    out["day"] = day
    return out


def render_html(data: dict) -> str:
    env = Environment(loader=FileSystemLoader(str(HERE)), autoescape=select_autoescape(["html"]), trim_blocks=True, lstrip_blocks=True,
                      comment_start_string="<<#", comment_end_string="#>>")
    tpl = env.get_template("template.html")
    return tpl.render(d=data, tl=timeline(data), status=STATUS, data_json=safe_json(data))


def build_report(out_dir, case_dir=None, generated_at: str | None = None) -> Path:
    """Writes <out_dir>/report.html from the existing pipeline outputs. No LLM, no pipeline work."""
    out = Path(out_dir)
    html = render_html(build_data(out, case_dir, generated_at))
    path = out / "report.html"
    path.write_text(html, encoding="utf-8", newline="\n")
    return path
