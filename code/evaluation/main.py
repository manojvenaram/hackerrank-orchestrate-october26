#!/usr/bin/env python3
"""
Evaluation Runner for Ghost Data Still Exists Deletion Audit Agent.
Evaluates prediction accuracy against ground truth:
- Case-level status accuracy
- Step-level and field-level accuracy
- Sequence accuracy
- Detailed breakdown and edge cases
"""

import os
import sys
import csv
import json
import argparse
from typing import Dict, List, Tuple, Any


def load_dataset(csv_path: str) -> Dict[str, Tuple[str, List[Dict[str, Any]]]]:
    """Loads a CSV containing case_id, deletion_status, steps_json."""
    data = {}
    if not os.path.exists(csv_path):
        print(f"Error: {csv_path} does not exist.")
        return data

    with open(csv_path, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cid = row['case_id']
            status = row['deletion_status']
            try:
                steps = json.loads(row['steps_json'])
            except Exception:
                steps = []
            data[cid] = (status, steps)
    return data


def evaluate(predictions_path: str, ground_truth_path: str) -> Dict[str, Any]:
    """Runs full evaluation comparing predictions against ground truth."""
    pred = load_dataset(predictions_path)
    golden = load_dataset(ground_truth_path)

    total_cases = len(golden)
    if total_cases == 0:
        print("No ground truth cases found for evaluation.")
        return {}

    status_correct = 0
    step_exact_correct = 0
    total_steps_golden = 0
    total_steps_pred = 0
    field_matches = {
        'phase': 0,
        'system_id': 0,
        'resource_id': 0,
        'operation': 0,
        'state': 0,
        'evidence_id': 0
    }
    field_total = 0

    mismatches = []

    for cid in sorted(golden.keys()):
        g_status, g_steps = golden[cid]
        p_status, p_steps = pred.get(cid, ('', []))

        status_ok = (g_status == p_status)
        if status_ok:
            status_correct += 1

        total_steps_golden += len(g_steps)
        total_steps_pred += len(p_steps)

        steps_ok = (g_steps == p_steps)
        if status_ok and steps_ok:
            step_exact_correct += 1
        else:
            mismatches.append({
                'case_id': cid,
                'status_ok': status_ok,
                'golden_status': g_status,
                'pred_status': p_status,
                'golden_count': len(g_steps),
                'pred_count': len(p_steps),
                'golden_steps': g_steps,
                'pred_steps': p_steps
            })

        # Step-level field alignment comparison
        min_len = min(len(g_steps), len(p_steps))
        for i in range(min_len):
            gs = g_steps[i]
            ps = p_steps[i]
            field_total += 1
            for k in field_matches.keys():
                if gs.get(k) == ps.get(k):
                    field_matches[k] += 1

    status_acc = status_correct / total_cases * 100
    exact_acc = step_exact_correct / total_cases * 100

    field_acc = {}
    for k, v in field_matches.items():
        field_acc[k] = (v / field_total * 100) if field_total > 0 else 0

    print("="*60)
    print("GHOST DATA STILL EXISTS: AUDIT EVALUATION SUMMARY")
    print("="*60)
    print(f"Total Evaluated Cases:        {total_cases}")
    print(f"Case Status Accuracy:         {status_correct}/{total_cases} ({status_acc:.1f}%)")
    print(f"Exact Sequence & Step Match:  {step_exact_correct}/{total_cases} ({exact_acc:.1f}%)")
    print(f"Total Steps (Golden vs Pred): {total_steps_golden} vs {total_steps_pred}")
    print("\nField-Level Step Accuracies:")
    for k, acc in field_acc.items():
        print(f"  - {k:<15}: {acc:.1f}%")

    if mismatches:
        print(f"\nTotal Mismatched Cases: {len(mismatches)}")
        for m in mismatches[:5]:
            print(f"  Case {m['case_id']}: Golden={m['golden_status']} (steps={m['golden_count']}) vs Pred={m['pred_status']} (steps={m['pred_count']})")

    return {
        'total_cases': total_cases,
        'status_accuracy': status_acc,
        'exact_step_accuracy': exact_acc,
        'field_accuracies': field_acc,
        'mismatches_count': len(mismatches)
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate Deletion Audit Predictions")
    parser.add_argument('--pred', default='scratch/sample_output_pred.csv', help="Path to predicted CSV")
    parser.add_argument('--golden', default='dataset/sample_output.csv', help="Path to ground truth CSV")
    args = parser.parse_args()

    evaluate(args.pred, args.golden)


if __name__ == '__main__':
    main()
