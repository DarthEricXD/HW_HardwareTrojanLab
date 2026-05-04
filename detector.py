import re
import os
import csv
import glob


def detect_trojan(verilog_code: str) -> dict:
    code_lower = verilog_code.lower()

    flags = {
        "trojan_marker":      "trojan" in code_lower,
        "internal_counter":   len(re.findall(r'\b\w*counter\w*\b', verilog_code, re.I)) >= 1
                              or len(re.findall(r'<=\s*\w+\s*\+\s*1', verilog_code)) >= 2,
        "magic_constant":     len(re.findall(r"==\s*\d+|==\s*\d+'[bh][0-9a-fA-F]+", verilog_code)) >= 1,
        "conditional_payload": bool(re.search(r'if\s*\(\s*!?\s*\w*trigger\w*', verilog_code, re.I))
                               or bool(re.search(r'if\s*\(\s*\w+\s*==\s*\d+', verilog_code)),
        "suspicious_logic":   bool(re.search(r'count\s*<=\s*count\s*\+\s*2', verilog_code))
                              or bool(re.search(r'result\s*=\s*8\'hFF', verilog_code))
                              or bool(re.search(r'trojan_insertion_begin', verilog_code, re.I)),
    }

    score = sum(1 for v in flags.values() if v)

    return {
        "is_suspicious": score >= 2,
        "score": score,
        "details": flags,
        "confidence": "High" if score >= 3 else "Medium" if score >= 2 else "Low",
    }


def evaluate_batch(trojaned_dir="./batch_trojan_designs",
                   csv_out="summary.csv"):
    """
    Run the detector over all trojaned and clean samples.

    Layout assumed:
      trojaned_dir/*.v          — clean baseline designs (true negatives)
      trojaned_dir/**/*_HT*.v   — AI-generated trojaned designs (true positives)

    Prints a per-file table and an overall evaluation, then writes summary.csv.
    """
    rows = []

    # Trojaned samples: files with _HT in the name (generated outputs in subdirs)
    trojaned_files = sorted(f for f in glob.glob(f"{trojaned_dir}/**/*.v", recursive=True)
                            if "_HT" in os.path.basename(f))
    # Clean samples: top-level .v files in trojaned_dir (baseline designs)
    clean_files = sorted(glob.glob(f"{trojaned_dir}/*.v"))

    labeled = [(f, True) for f in trojaned_files] + [(f, False) for f in clean_files]

    if not labeled:
        print("No files found. Check trojaned_dir and clean_dir paths.")
        return

    print(f"{'File':<45} {'Expected':<10} {'Detected':<10} {'Score':<7} {'Conf':<8} {'Result'}")
    print("-" * 100)

    tp = fp = tn = fn = 0

    for fpath, is_trojaned in labeled:
        with open(fpath, 'r') as f:
            code = f.read()

        result = detect_trojan(code)
        detected = result["is_suspicious"]
        expected_label = "trojaned" if is_trojaned else "clean"
        detected_label = "trojaned" if detected else "clean"

        if is_trojaned and detected:
            outcome, tp = "TP", tp + 1
        elif is_trojaned and not detected:
            outcome, fn = "FN", fn + 1
        elif not is_trojaned and detected:
            outcome, fp = "FP", fp + 1
        else:
            outcome, tn = "TN", tn + 1

        fname = os.path.basename(fpath)
        print(f"{fname:<45} {expected_label:<10} {detected_label:<10} "
              f"{result['score']:<7} {result['confidence']:<8} {outcome}")

        rows.append({
            "file": fname,
            "path": fpath,
            "expected": expected_label,
            "detected": detected_label,
            "score": result["score"],
            "confidence": result["confidence"],
            "outcome": outcome,
            **{f"flag_{k}": v for k, v in result["details"].items()},
        })

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy  = (tp + tn) / total if total > 0 else 0.0

    print("\n" + "=" * 60)
    print(f"Total samples : {total}  ({len(trojaned_files)} trojaned, {len(clean_files)} clean)")
    print(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"Precision : {precision:.2f}")
    print(f"Recall    : {recall:.2f}")
    print(f"F1        : {f1:.2f}")
    print(f"Accuracy  : {accuracy:.2f}")
    print("=" * 60)

    if fp > 0:
        print("\nFalse positives (clean files flagged as suspicious):")
        for r in rows:
            if r["outcome"] == "FP":
                print(f"  {r['file']}  score={r['score']}  flags={[k for k,v in r.items() if k.startswith('flag_') and v]}")

    if fn > 0:
        print("\nFalse negatives (trojaned files missed):")
        for r in rows:
            if r["outcome"] == "FN":
                print(f"  {r['file']}  score={r['score']}  flags={[k for k,v in r.items() if k.startswith('flag_') and v]}")

    # Write CSV
    if rows:
        fieldnames = list(rows[0].keys())
        with open(csv_out, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nResults written to {csv_out}")


if __name__ == "__main__":
    evaluate_batch()
