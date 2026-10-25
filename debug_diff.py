import csv, json

exp = {r["case_id"]: r for r in csv.DictReader(open("dataset/sample_output.csv", encoding="utf-8-sig"))}
pred = {r["case_id"]: r for r in csv.DictReader(open("sample_predictions.csv", encoding="utf-8-sig"))}


def key(s):
    return (s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"], s["evidence_id"])


total_missing = 0
total_extra = 0
status_mismatch = 0
for cid in sorted(exp):
    g = json.loads(exp[cid]["steps_json"])
    p = json.loads(pred[cid]["steps_json"])
    gk = {key(x) for x in g}
    pk = {key(x) for x in p}
    missing = [x for x in g if key(x) not in pk]
    extra = [x for x in p if key(x) not in gk]
    if exp[cid]["deletion_status"] != pred[cid]["deletion_status"] or missing or extra:
        status_mismatch += 1
        total_missing += len(missing)
        total_extra += len(extra)
        print(f"=== {cid}  status exp={exp[cid]['deletion_status']} pred={pred[cid]['deletion_status']}")
        for m in missing:
            print("  MISSING:", m)
        for e in extra:
            print("  EXTRA:", e)
print(f"\ncases with differences: {status_mismatch}, missing steps: {total_missing}, extra steps: {total_extra}")
