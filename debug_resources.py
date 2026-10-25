import csv, json, sys
sys.path.insert(0, 'code')
import main as solution

dataset = solution.Path('dataset')
index = solution.EvidenceIndex(dataset)

# Find all facts for resources mentioned in missing steps
resources = ['account_6440', 'account_4990', 'account_410', 'account_7012', 'account_4163',
             'account_4857', 'account_8858', 'analytics_9406', 'analytics_901', 'analytics_5335',
             'analytics_1895', 'analytics_4566', 'analytics_4574', 'analytics_6077',
             'audit_record_4902', 'audit_record_6645', 'audit_record_5569', 'audit_record_4128',
             'audit_record_7095', 'audit_record_3954', 'audit_record_1707', 'account_3960',
             'account_5521', 'account_5037']
for rid in resources:
    print(f'=== {rid} ===')
    found = False
    for f in index.facts:
        if f.resource_id == rid:
            found = True
            print(f'  file={f.file_id} system={f.system_id} cat={f.category} state={f.state} obs={f.observed_at} cap={f.captured_at}')
            for k, v in sorted(solution.flatten_scalars(f.attrs).items()):
                if v is not None and str(v).strip():
                    print(f'    {k}={v}')
    if not found:
        print('  (no facts in index)')
