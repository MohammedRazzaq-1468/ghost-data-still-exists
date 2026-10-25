#!/usr/bin/env python3
"""Evaluate sample predictions and run small behavior checks for the solution."""
from __future__ import annotations

import argparse
import collections
import csv
import json
import sys
from pathlib import Path

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE))
import main as solution  # noqa: E402


STEP_FIELDS = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")


def read_rows(path: Path) -> dict[str, dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return {row["case_id"]: row for row in csv.DictReader(stream)}


def evaluate(expected_path: Path, predicted_path: Path) -> dict[str, object]:
    expected, predicted = read_rows(expected_path), read_rows(predicted_path)
    status_correct = sum(expected[key]["deletion_status"] == predicted.get(key, {}).get("deletion_status") for key in expected)
    tp = fp = fn = exact_sequences = aligned_fields = total_fields = 0
    expected_steps = predicted_steps = 0
    for case_id, gold in expected.items():
        gold_steps = json.loads(gold["steps_json"])
        pred_row = predicted.get(case_id)
        pred_steps = json.loads(pred_row["steps_json"]) if pred_row else []
        expected_steps += len(gold_steps)
        predicted_steps += len(pred_steps)
        step_key = lambda item: tuple(item.get(name) for name in STEP_FIELDS)
        gold_keys = collections.Counter(step_key(item) for item in gold_steps)
        pred_keys = collections.Counter(step_key(item) for item in pred_steps)
        matched = sum((gold_keys & pred_keys).values())
        tp += matched
        fp += len(pred_steps) - matched
        fn += len(gold_steps) - matched
        if [step_key(item) for item in gold_steps] == [step_key(item) for item in pred_steps]:
            exact_sequences += 1
        for pos in range(max(len(gold_steps), len(pred_steps))):
            for name in STEP_FIELDS:
                total_fields += 1
                if pos < len(gold_steps) and pos < len(pred_steps) and gold_steps[pos].get(name) == pred_steps[pos].get(name):
                    aligned_fields += 1
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "expected_cases": len(expected),
        "predicted_cases": len(predicted),
        "status_correct": status_correct,
        "status_accuracy": status_correct / len(expected) if expected else 1.0,
        "exact_step_sequences": exact_sequences,
        "sequence_accuracy": exact_sequences / len(expected) if expected else 1.0,
        "expected_steps": expected_steps,
        "predicted_steps": predicted_steps,
        "step_true_positive": tp,
        "step_false_positive": fp,
        "step_false_negative": fn,
        "step_precision": precision,
        "step_recall": recall,
        "step_f1": f1,
        "aligned_field_matches": aligned_fields,
        "aligned_field_comparisons": total_fields,
        "aligned_field_accuracy": aligned_fields / total_fields if total_fields else 1.0,
    }


def custom_checks() -> list[tuple[str, bool]]:
    aliases = {"user_id": {"user_32"}, "name": {"Mateo Rios"}, "email": {"mateo@example.test"},
               "phone": set(), "email_hash": set()}
    decoy = solution.Fact("evidence_x", "2026-10-01T00:00:00+00:00", "2026-10-01T00:00:00+00:00",
                          "account_service", "account_9116", "USER_PROFILE", "PRESENT",
                          {"resource_id": "account_9116", "user_id": "user_9116", "full_name": "Mateo Rios Gil"})
    absent = solution.Fact("evidence_y", "2026-10-01T00:00:00+00:00", "2026-10-01T00:00:00+00:00",
                           "account_service", "account_404", "USER_PROFILE", "PRESENT",
                           {"resource_id": "account_404", "http_status": "404", "rows": "0"})
    tombstone = solution.Fact("evidence_z", "2026-10-01T00:00:00+00:00", "2026-10-01T00:00:00+00:00",
                              "identity_service", "tombstone_77", "ACCOUNT_TOMBSTONE", "PRESENT",
                              {"resource_id": "tombstone_77", "user_id": "user_77"})
    tombstone_aliases = {"user_id": {"user_77"}, "email": set(), "phone": set(), "name": set(), "email_hash": set()}
    return [
        ("Spanish deletion wording is authorized", solution.authorized_deletion("Quiero eliminar mi cuenta y mis datos personales.")),
        ("Marketing-only unsubscribe is not deletion", not solution.authorized_deletion("Please unsubscribe me from marketing emails.")),
        ("A longer decoy name is not a subject match", not solution.fact_matches(decoy, aliases)),
        ("HTTP 404 readback maps to ABSENT", solution.infer_state(absent.attrs, absent.category) == "ABSENT"),
        ("Stable tombstone user_id may remain", not solution.subject_pii_present(tombstone, tombstone_aliases)),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected", type=Path, required=True, help="Public sample_output.csv")
    parser.add_argument("--predictions", type=Path, required=True, help="Generated sample predictions")
    args = parser.parse_args()
    result = evaluate(args.expected, args.predictions)
    checks = custom_checks()
    result["custom_checks"] = [{"case": name, "passed": passed} for name, passed in checks]
    print(json.dumps(result, indent=2))
    return 0 if all(passed for _, passed in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
