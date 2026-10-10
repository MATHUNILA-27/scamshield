import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import ask_llm, analyze as rules_analyze, client

CASES_PATH = Path(__file__).with_name("robustness.json")
RESULTS_PATH = Path(__file__).with_name("robustness_results.json")


def verdict_for(score):
    if score >= 60:
        return "likely_scam"
    if score >= 30:
        return "suspicious"
    return "no_signs_found"


def safe_json_parse(raw):
    if not raw:
        return None
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            m = re.search(r"\{.*\}", raw, re.S)
            if m:
                try:
                    return json.loads(m.group(0))
                except Exception:
                    return None
    return None


def normalize_score(value):
    try:
        value = float(value)
        if value < 0:
            value = 0
        if value > 100:
            value = 100
        return value
    except Exception:
        return None


def run_once(case):
    text = case["text"]
    rule_data = rules_analyze(text)
    rule_score = int(rule_data.get("score", 0))
    rule_verdict = verdict_for(rule_score)
    start = time.perf_counter()
    ai_payload = None
    ai_error = None
    valid_json_first_try = True
    retries_used = 0
    fell_back_to_rules = False
    ai_score = None
    ai_verdict = rule_verdict
    scam_type = "none"

    if client:
        try:
            ai_payload = ask_llm(text, case["lang"])
            if ai_payload is None:
                raise ValueError("AI response was empty")
            parsed = safe_json_parse(ai_payload)
            if parsed is None:
                valid_json_first_try = False
                ai_error = "invalid_json"
                fell_back_to_rules = True
            else:
                scam_type = parsed.get("scam_type", "none")
                ai_score = normalize_score(parsed.get("risk", rule_score))
                if ai_score is None:
                    valid_json_first_try = False
                    ai_error = "risk_not_numeric"
                    fell_back_to_rules = True
                else:
                    ai_verdict = verdict_for(ai_score)
        except Exception as exc:
            ai_error = str(exc)
            fell_back_to_rules = True
    else:
        ai_error = "LLM_API_KEY missing"
        fell_back_to_rules = True

    if fell_back_to_rules:
        score = rule_score
        verdict = rule_verdict
        scam_type = case.get("expected") if case["expected"] == "genuine" else "none"
    else:
        if ai_score is not None:
            score = round(0.6 * ai_score + 0.4 * rule_score)
            if rule_score >= 60:
                score = max(score, rule_score)
            verdict = verdict_for(score)
        else:
            score = rule_score
            verdict = rule_verdict

    elapsed = time.perf_counter() - start
    return {
        "rules_only": {"verdict": rule_verdict, "score": rule_score, "scam_type": "none"},
        "ai_only": {
            "verdict": ai_verdict,
            "score": ai_score if ai_score is not None else rule_score,
            "scam_type": scam_type,
            "error": ai_error,
            "valid_json_first_try": valid_json_first_try,
            "retries_used": retries_used,
            "fallback_to_rules": fell_back_to_rules,
            "response_time": elapsed,
        },
        "combined": {"verdict": verdict, "score": score, "scam_type": scam_type},
        "valid_json_first_try": valid_json_first_try,
        "retries_used": retries_used,
        "fallback_to_rules": fell_back_to_rules,
        "response_time": elapsed,
        "exception": ai_error,
    }


def analyze_cases():
    cases = json.load(open(CASES_PATH, encoding="utf-8"))
    all_runs = []
    failures = []
    drift = []
    invalid_json_total = 0
    fallback_total = 0
    slowest = []

    summary = {
        "tune": {"scams_caught_suspicious_or_above": 0, "scam_total": 0, "genuine_wrongly_flagged": 0, "genuine_total": 0, "uncertain_ok_total": 0, "uncertain_ok_seen": 0, "injection_fooled": 0},
        "holdout": {"scams_caught_suspicious_or_above": 0, "scam_total": 0, "genuine_wrongly_flagged": 0, "genuine_total": 0, "uncertain_ok_total": 0, "uncertain_ok_seen": 0, "injection_fooled": 0},
    }
    category_counts = {}
    lang_counts = {}

    for case in cases:
        runs = []
        for _ in range(3):
            result = run_once(case)
            runs.append(result)
            slowest.append({"id": case["id"], "split": case["split"], "time": result["response_time"], "lang": case["lang"], "expected": case["expected"]})
            invalid_json_total += 0 if result["valid_json_first_try"] else 1
            fallback_total += 1 if result["fallback_to_rules"] else 0
        verdicts = [r["combined"]["verdict"] for r in runs]
        if len(set(verdicts)) > 1:
            drift.append({"id": case["id"], "expected": case["expected"], "verdicts": verdicts})

        final = runs[-1]
        final_verdict = final["combined"]["verdict"]
        key = case["split"]
        if case["expected"] == "scam":
            summary[key]["scam_total"] += 1
            if final_verdict in {"suspicious", "likely_scam"}:
                summary[key]["scams_caught_suspicious_or_above"] += 1
        elif case["expected"] == "genuine":
            summary[key]["genuine_total"] += 1
            if final_verdict != "no_signs_found":
                summary[key]["genuine_wrongly_flagged"] += 1
        elif case["expected"] == "uncertain_ok":
            summary[key]["uncertain_ok_total"] += 1
            if final_verdict in {"suspicious", "likely_scam"}:
                summary[key]["uncertain_ok_seen"] += 1

        if case["category"] not in category_counts:
            category_counts[case["category"]] = {"tune": {"scam_total": 0, "scam_caught": 0, "genuine_total": 0, "genuine_wrongly_flagged": 0, "uncertain_ok_total": 0, "uncertain_ok_seen": 0}, "holdout": {"scam_total": 0, "scam_caught": 0, "genuine_total": 0, "genuine_wrongly_flagged": 0, "uncertain_ok_total": 0, "uncertain_ok_seen": 0}}
        cat = category_counts[case["category"]][case["split"]]
        if case["expected"] == "scam":
            cat["scam_total"] += 1
            if final_verdict in {"suspicious", "likely_scam"}:
                cat["scam_caught"] += 1
        elif case["expected"] == "genuine":
            cat["genuine_total"] += 1
            if final_verdict != "no_signs_found":
                cat["genuine_wrongly_flagged"] += 1
        elif case["expected"] == "uncertain_ok":
            cat["uncertain_ok_total"] += 1
            if final_verdict in {"suspicious", "likely_scam"}:
                cat["uncertain_ok_seen"] += 1

        if case["lang"] not in lang_counts:
            lang_counts[case["lang"]] = {"tune": {"scam_total": 0, "scam_caught": 0, "genuine_total": 0, "genuine_wrongly_flagged": 0, "uncertain_ok_total": 0, "uncertain_ok_seen": 0}, "holdout": {"scam_total": 0, "scam_caught": 0, "genuine_total": 0, "genuine_wrongly_flagged": 0, "uncertain_ok_total": 0, "uncertain_ok_seen": 0}}
        lang = lang_counts[case["lang"]][case["split"]]
        if case["expected"] == "scam":
            lang["scam_total"] += 1
            if final_verdict in {"suspicious", "likely_scam"}:
                lang["scam_caught"] += 1
        elif case["expected"] == "genuine":
            lang["genuine_total"] += 1
            if final_verdict != "no_signs_found":
                lang["genuine_wrongly_flagged"] += 1
        elif case["expected"] == "uncertain_ok":
            lang["uncertain_ok_total"] += 1
            if final_verdict in {"suspicious", "likely_scam"}:
                lang["uncertain_ok_seen"] += 1

        if case["category"] == "F":
            if final_verdict in {"suspicious", "likely_scam"}:
                summary[key]["injection_fooled"] += 1
            if case["expected"] == "scam" and final_verdict == "no_signs_found":
                failures.append({"id": case["id"], "expected": case["expected"], "verdict": final_verdict, "text": case["text"], "note": case["note"]})

        if final_verdict not in {"no_signs_found", "suspicious", "likely_scam"}:
            failures.append({"id": case["id"], "expected": case["expected"], "verdict": final_verdict, "text": case["text"], "note": case["note"]})
        elif case["expected"] == "genuine" and final_verdict != "no_signs_found":
            failures.append({"id": case["id"], "expected": case["expected"], "verdict": final_verdict, "text": case["text"], "note": case["note"]})
        elif case["expected"] == "scam" and final_verdict == "no_signs_found":
            failures.append({"id": case["id"], "expected": case["expected"], "verdict": final_verdict, "text": case["text"], "note": case["note"]})
        elif case["expected"] == "uncertain_ok" and final_verdict == "likely_scam" and "prompt" not in case["text"].lower():
            failures.append({"id": case["id"], "expected": case["expected"], "verdict": final_verdict, "text": case["text"], "note": case["note"]})

        all_runs.append({"case": case, "runs": runs, "final_verdict": final_verdict})

    summary["tune"]["likely_scam_only"] = 0
    summary["holdout"]["likely_scam_only"] = 0
    for case in cases:
        key = case["split"]
        final = next(r for r in all_runs if r["case"]["id"] == case["id"])
        fv = final["final_verdict"]
        if case["expected"] == "scam" and fv == "likely_scam":
            summary[key]["likely_scam_only"] += 1

    slowest = sorted(slowest, key=lambda x: x["time"], reverse=True)[:5]
    print("LLM_API_KEY present:", bool(client))
    print("TUNE:")
    print(json.dumps(summary["tune"], indent=2, ensure_ascii=False))
    print("HOLDOUT:")
    print(json.dumps(summary["holdout"], indent=2, ensure_ascii=False))
    print("INJECTION CASES FOOLED:", summary["tune"]["injection_fooled"] + summary["holdout"]["injection_fooled"])
    print("INVALID JSON RATE:", invalid_json_total, "of", len(cases))
    print("FALLBACKS:", fallback_total, "of", len(cases))
    print("SLOWEST 5:")
    print(json.dumps(slowest, indent=2, ensure_ascii=False))
    if failures:
        print("FAILURES:")
        for item in failures:
            print(json.dumps(item, ensure_ascii=False))
    if drift:
        print("VERDICT CHANGES BETWEEN RUNS:")
        print(json.dumps(drift, ensure_ascii=False))

    payload = {
        "metadata": {"llm_api_key_present": bool(client), "cases_total": len(cases), "tune_cases": sum(1 for c in cases if c["split"] == "tune"), "holdout_cases": sum(1 for c in cases if c["split"] == "holdout")},
        "summary": summary,
        "category_by_split": category_counts,
        "language_by_split": lang_counts,
        "failures": failures,
        "verdict_drift": drift,
        "slowest": slowest,
        "invalid_json_total": invalid_json_total,
        "fallback_total": fallback_total,
        "results": all_runs,
    }
    json.dump(payload, open(RESULTS_PATH, "w", encoding="utf-8"), ensure_ascii=False, indent=2)


if __name__ == "__main__":
    analyze_cases()
