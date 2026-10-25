content = open("code/main.py", "r", encoding="utf-8-sig").read()
old1 = "if row.get(\"action\") != \"LINK_RESOURCE_IDENTITY\":"
new1 = "if row.get(\"event_type\") != \"LINK_RESOURCE_IDENTITY\":"
assert old1 in content, "Fix 1 target not found"
content = content.replace(old1, new1)
print("Fix 1 applied: action -> event_type")
open("code/main.py", "w", encoding="utf-8-sig").write(content)
print("Done")
