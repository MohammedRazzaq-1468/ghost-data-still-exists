import csv
rows = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8-sig')))
print('total rows:', len(rows))
link_rows = [r for r in rows if r.get('action') == 'LINK_RESOURCE_IDENTITY']
print('LINK_RESOURCE_IDENTITY rows:', len(link_rows))
for r in link_rows:
    print(r)
