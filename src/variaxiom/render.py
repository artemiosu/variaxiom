"""Static, dependency-free reports for inspectable evolution decisions."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any

from .canonical import JSONValue


def _text(value: Any) -> str:
    return escape(str(value), quote=True)


def render_demo_report(report: dict[str, JSONValue], destination: Path) -> Path:
    """Render the Authority Test as a self-contained HTML file.

    The renderer consumes only trusted structured report data and escapes every
    dynamic value. It does not execute candidate-provided HTML or JavaScript.
    """

    decisions = report.get("decisions", [])
    cards: list[str] = []
    if isinstance(decisions, list):
        for raw in decisions:
            if not isinstance(raw, dict):
                continue
            status = str(raw.get("status", "unknown"))
            accepted = status == "accepted"
            badge_class = "accepted" if accepted else "rejected"
            badge_label = "PROMOTED" if accepted else "REJECTED"
            reasons_raw = raw.get("reasons", [])
            reasons = reasons_raw if isinstance(reasons_raw, list) else [reasons_raw]
            reason_items = "".join(f"<li>{_text(reason)}</li>" for reason in reasons)
            evidence_raw = raw.get("evidence_ids", [])
            evidence = evidence_raw if isinstance(evidence_raw, list) else []
            cards.append(
                f"""
                <article class="decision-card {badge_class}">
                  <div class="decision-head">
                    <div>
                      <p class="eyebrow">candidate</p>
                      <h2>{_text(raw.get('candidate_id', 'unknown'))}</h2>
                    </div>
                    <span class="badge {badge_class}">{badge_label}</span>
                  </div>
                  <h3>Constitutional decision</h3>
                  <ul>{reason_items}</ul>
                  <p class="evidence-count">{len(evidence)} evidence records bound to this candidate</p>
                </article>
                """
            )

    ledger_raw = report.get("ledger", {})
    ledger = ledger_raw if isinstance(ledger_raw, dict) else {}
    valid = bool(ledger.get("valid", False))
    ledger_label = "VALID" if valid else "INVALID"
    ledger_class = "accepted" if valid else "rejected"

    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>Variaxiom — Authority Test</title>
  <style>
    :root {{
      --bg: #070a12;
      --surface: #101625;
      --surface-2: #171f31;
      --text: #f7f9ff;
      --muted: #aeb8cc;
      --line: #2a354d;
      --signal: #9f8cff;
      --accept: #62d9a7;
      --reject: #ff7e87;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
        "Segoe UI", sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: radial-gradient(circle at 20% 0%, #1a1b3b 0, var(--bg) 42%); color: var(--text); }}
    main {{ width: min(1120px, calc(100% - 40px)); margin: 0 auto; padding: 64px 0 80px; }}
    .mark {{ display: inline-flex; align-items: center; gap: 12px; font-weight: 750; letter-spacing: .02em; }}
    .glyph {{ width: 34px; height: 34px; border: 2px solid var(--signal); border-radius: 10px; transform: rotate(45deg); position: relative; }}
    .glyph::after {{ content: ""; position: absolute; width: 12px; height: 12px; border: 2px solid var(--accept); border-radius: 50%; inset: 9px; }}
    h1 {{ max-width: 900px; margin: 64px 0 18px; font-size: clamp(48px, 8vw, 92px); line-height: .96; letter-spacing: -.055em; }}
    .lead {{ max-width: 820px; color: var(--muted); font-size: clamp(19px, 2.3vw, 26px); line-height: 1.45; }}
    .principle {{ margin: 42px 0; padding: 24px 26px; border: 1px solid var(--line); background: rgba(16,22,37,.86); border-radius: 18px; font-size: 18px; }}
    .principle strong {{ color: var(--accept); }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 22px; }}
    .decision-card {{ padding: 28px; background: linear-gradient(160deg, var(--surface-2), var(--surface)); border: 1px solid var(--line); border-radius: 22px; box-shadow: 0 25px 80px rgba(0,0,0,.22); }}
    .decision-card.accepted {{ border-color: rgba(98,217,167,.55); }}
    .decision-card.rejected {{ border-color: rgba(255,126,135,.5); }}
    .decision-head {{ display: flex; justify-content: space-between; gap: 20px; align-items: start; }}
    .eyebrow {{ margin: 0 0 8px; color: var(--muted); text-transform: uppercase; letter-spacing: .16em; font-size: 12px; }}
    h2 {{ margin: 0; font-size: 22px; overflow-wrap: anywhere; }}
    h3 {{ margin-top: 30px; font-size: 15px; text-transform: uppercase; letter-spacing: .11em; color: var(--muted); }}
    ul {{ padding-left: 20px; line-height: 1.55; }}
    .badge {{ flex: none; padding: 8px 10px; border-radius: 999px; font-size: 11px; font-weight: 800; letter-spacing: .09em; }}
    .badge.accepted {{ color: #051b12; background: var(--accept); }}
    .badge.rejected {{ color: #240509; background: var(--reject); }}
    .evidence-count {{ color: var(--muted); font-size: 13px; margin-top: 28px; }}
    .ledger {{ margin-top: 28px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }}
    .metric {{ padding: 20px; background: rgba(16,22,37,.82); border: 1px solid var(--line); border-radius: 16px; }}
    .metric b {{ display: block; margin-top: 8px; font-size: 19px; overflow-wrap: anywhere; }}
    .footer {{ margin-top: 52px; color: var(--muted); border-top: 1px solid var(--line); padding-top: 24px; }}
    code {{ color: #d9d1ff; }}
    @media (max-width: 760px) {{ .grid, .ledger {{ grid-template-columns: 1fr; }} main {{ padding-top: 38px; }} }}
  </style>
</head>
<body>
<main>
  <div class="mark"><span class="glyph" aria-hidden="true"></span> VARIAXIOM</div>
  <h1>Agents mutate.<br>Evidence decides.</h1>
  <p class="lead">The Authority Test proves a simple boundary: functional success does not silently expand an agent's permission to act.</p>
  <div class="principle"><strong>Same implementation. Same passing tests.</strong> Different authority request — different constitutional outcome.</div>
  <section class="grid">{''.join(cards)}</section>
  <section class="ledger" aria-label="Lineage ledger status">
    <div class="metric"><span class="eyebrow">ledger</span><b class="{ledger_class}">{ledger_label}</b></div>
    <div class="metric"><span class="eyebrow">events</span><b>{_text(ledger.get('event_count', 0))}</b></div>
    <div class="metric"><span class="eyebrow">head hash</span><b><code>{_text(str(ledger.get('head_hash', ''))[:16])}…</code></b></div>
  </section>
  <p class="footer">Generated from the hash-chained Variaxiom demo report. Dynamic values are escaped; no candidate-provided executable content is rendered.</p>
</main>
</body>
</html>
"""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(document, encoding="utf-8")
    temporary.replace(destination)
    return destination
