content = open('code/main.py', 'r', encoding='utf-8-sig').read()

helper = '''
    def _extract_json_line(self, line: str):
        stripped = line.strip()
        if not stripped.startswith('{'):
            return None
        try:
            jstart = line.index('{')
            return json.loads(line[jstart:])
        except (json.JSONDecodeError, ValueError):
            return None
'''

marker = '    def _parse_log(self, path: Path, file_id: str, captured: str) -> None:'
assert marker in content, 'marker not found'
content = content.replace(marker, helper + marker)

old_pass1 = '''        for line in lines:
            kv = self._kv(line)
            trace_id = kv.get("trace_id", "")
            if trace_id:
                for key in ("subject_key", "subject_ref", "correlation_key", "user_id", "email", "phone", "email_hash", "lookup_key", "match_key"):
                    if kv.get(key):
                        trace_identity[trace_id][key] = kv[key]'''

new_pass1 = '''        for line in lines:
            kv = self._kv(line)
            trace_id = kv.get("trace_id", "")
            if not trace_id:
                obj = self._extract_json_line(line)
                if obj:
                    trace_id = obj.get("trace_id", "")
                    if trace_id:
                        kv = {str(k): str(v) for k, v in obj.items() if v is not None}
            if trace_id:
                for key in ("subject_key", "subject_ref", "correlation_key", "user_id", "email", "phone", "email_hash", "lookup_key", "match_key"):
                    if kv.get(key):
                        trace_identity[trace_id][key] = kv[key]'''

assert old_pass1 in content, 'pass1 not found'
content = content.replace(old_pass1, new_pass1)

old_pass2_start = '''        for line in lines:
            m = re.match(r"\\s*(\\d{4}-\\d\\d-\\d\\dT[^\\s|]+)", line)
            timestamp = m.group(1) if m else captured
            # Handover format'''

new_pass2_start = '''        for line in lines:
            m = re.match(r"\\s*(\\d{4}-\\d\\d-\\d\\dT[^\\s|]+)", line)
            timestamp = m.group(1) if m else captured
            # JSON structured log line
            obj = self._extract_json_line(line)
            if obj is not None:
                resource = obj.get("resource_id")
                if not resource:
                    continue
                event = (obj.get("event") or "").casefold()
                system = (obj.get("service") or obj.get("logger") or "").casefold()
                if not system:
                    continue
                kv = {str(k): str(v) for k, v in obj.items() if v is not None}
                trace_id = kv.get("trace_id", "")
                kv.update({k: v for k, v in trace_identity.get(trace_id, {}).items() if not kv.get(k)})
                category = ""
                fact_system = system
                if "profile_lookup" in event or ("profile_read" in event and system == "account_service"):
                    category = "USER_PROFILE"
                elif "index_query" in event or "search" in system:
                    category = "SEARCH_INDEX_ENTRY"
                elif "support" in system or "ticket" in event or "message" in event or "attachment" in event:
                    category = "SUPPORT_ATTACHMENT" if "attachment" in event else "SUPPORT_MESSAGE"
                elif "analytics" in system:
                    category = "ANALYTICS_PROFILE"
                elif "connector" in event or "integration" in system:
                    category = "DATA_FLOW"
                elif "restore" in event or "backup" in system:
                    category = "BACKUP_ARCHIVE"
                elif "audit" in event or "security" in system:
                    category = "SECURITY_AUDIT_LOG"
                elif "export" in event or "export" in system:
                    category = "USER_EXPORT"
                elif "delivery" in event or "notification" in system:
                    category = "EMAIL_DELIVERY_LOG"
                if not category:
                    continue
                relevant = (event.endswith("_completed") or "pii_scan" in event
                            or event.endswith("_blocked") or event.endswith("_disabled") or event.endswith("_found")
                            or event in {"connector_heartbeat", "restore_candidate_evaluated"})
                if not relevant:
                    continue
                attrs = dict(kv)
                attrs.update({"resource_id": resource, "event": event, "system": fact_system, "record_type": category})
                self.add(file_id, captured, attrs, {"system": fact_system, "record_type": category}, (fact_system, event), line, 4)
                continue
            # Handover format'''

assert old_pass2_start in content, 'pass2 not found'
content = content.replace(old_pass2_start, new_pass2_start)

open('code/main.py', 'w', encoding='utf-8-sig').write(content)
print('Fix 2 applied: JSON log line parsing added')
