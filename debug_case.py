import csv, json, sys
sys.path.insert(0, "code")
import main as solution

dataset = solution.Path("dataset")
identities, email_to_user = solution.build_identity_index(dataset)
index = solution.EvidenceIndex(dataset)

req = {r["case_id"]: r for r in csv.DictReader(open("dataset/sample_deletion_requests.csv", encoding="utf-8-sig"))}

def show(cid):
    r = req[cid]
    email = r["email"]
    uid = email_to_user.get(solution.norm(email), "")
    aliases = solution.aliases_for(identities.get(uid, {}), email) if uid else {"email": {email}, "user_id": set(), "name": set(), "phone": set(), "email_hash": set()}
    facts = solution.latest_facts_for_case(index, aliases, r["audit_at"])
    print(f"===== {cid}  email={email} uid={uid} audit_at={r['audit_at']} status={r['reported_status']}")
    print(f"    aliases: { {k: sorted(v) for k,v in aliases.items()} }")
    print(f"    matched facts ({len(facts)}):")
    for f in facts:
        a = solution.assessment(f, aliases)
        print(f"      [{f.category}] {f.system_id}/{f.resource_id} state={f.state} file={f.file_id} obs={f.observed_at} cap={f.captured_at} assessment={a}")
        # show pii keys in attrs
        pii = {kk: vv for kk, vv in solution.flatten_scalars(f.attrs).items() if solution.norm(kk.split(".")[-1]) in solution.PII_KEYS}
        if pii:
            print(f"         pii_attrs={pii}")
    # Show all facts in index that involve these resources but weren't matched
    relevant_resources = set()
    for f in index.facts:
        if f.file_id in {"evidence_94", "evidence_56", "evidence_92", "evidence_51"}:
            relevant_resources.add((f.system_id, f.resource_id, f.category, f.state, f.file_id))
    if relevant_resources:
        print(f"    index facts from evidence_94/56/92/51:")
        for item in sorted(relevant_resources):
            print(f"      {item}")

for cid in ["case_03", "case_04", "case_09", "case_21", "case_31"]:
    show(cid)
