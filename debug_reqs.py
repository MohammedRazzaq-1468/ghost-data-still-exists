import csv
req = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig'))}
for cid in ['case_09','case_18','case_20','case_22','case_23','case_24','case_29','case_30','case_32']:
    r = req[cid]
    print(cid + ': email=' + r['email'] + ' reported=' + r['reported_status'] + ' audit_at=' + r['audit_at'])
    print('  text: ' + r['request_text'][:100])
