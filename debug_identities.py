import csv, sys
sys.path.insert(0, 'code')
import main as solution

dataset = solution.Path('dataset')
identities, email_to_user = solution.build_identity_index(dataset)

# Check which user each sample email maps to
req = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig'))}
for cid in sorted(req):
    r = req[cid]
    email = r['email']
    uid = email_to_user.get(solution.norm(email), '')
    print(cid + ' email=' + email + ' -> uid=' + uid)
