"""No-LLM check: re-run the deterministic layers over every saved ACCEPTED sentence and list those that now fail PATH_NOT_GROUNDED."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from evidenceweave.parsers.pipeline import load_hosts  # noqa: E402
from evidenceweave.verifier.verdicts import PATH_NOT_GROUNDED  # noqa: E402
from evidenceweave.verifier.verify import Verifier, load_case_data  # noqa: E402


def main(out_root=ROOT / "output", cases_root=ROOT / "data" / "cases"):
    total, hits = 0, []
    for case in sorted(p for p in Path(out_root).iterdir() if p.is_dir() and (p / "chain.json").exists()):
        hosts = load_hosts(Path(cases_root) / case.name) if (Path(cases_root) / case.name).exists() else {}
        for d in [case] + sorted((case / "runs").glob("*")) if (case / "runs").exists() else [case]:
            if not (d / "narrative_verified.json").exists() or not (d / "narrative.json").exists():
                continue
            data = load_case_data(d, hosts)
            ver = Verifier(data.events, data.host_names)
            nv = json.loads((d / "narrative_verified.json").read_text(encoding="utf-8"))
            units = [(s["stage"], s["sentences"]) for s in nv["stages"]] + [("executive_summary", nv["executive_summary"])]
            for unit, sents in units:
                for i, s in enumerate(sents):
                    if s.get("source") == "template_fallback":
                        continue  # facts verbatim, not LLM text
                    v = ver.det(data.ctxs[unit], s["text"], s["cites"], i, 0, "llm", False, s.get("fact_ids"))
                    total += 1
                    if PATH_NOT_GROUNDED in v.codes():
                        hits.append((str(d.relative_to(out_root)), unit, s["text"], [r["detail"] for r in v.failures() if r["code"] == PATH_NOT_GROUNDED]))
    print(f"re-checked {total} saved accepted LLM sentences; {len(hits)} would now fail PATH_NOT_GROUNDED")
    for h in hits:
        print(" ", h)


if __name__ == "__main__":
    main()
