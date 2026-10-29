#!/usr/bin/env python3
"""
Ghost Data Still Exists: AI-Powered Deletion Audit Agent
HackerRank Orchestrate October 2026 Challenge

Determines whether customer data deletion requests are COMPLETE, INCOMPLETE,
or NOT_APPLICABLE, detects remaining records, active sync pipelines, and backup
restore risks, and generates ordered remediation and verification plans.
"""

import sys
import os
import csv
import json
import sqlite3
import argparse
import re
from typing import Dict, List, Set, Any, Optional, Tuple

# Reconfigure stdout for UTF-8 compatibility on Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class IdentityResolver:
    """Resolves and correlates customer identities across historical audit logs."""

    def __init__(self, identities_path: str, audit_log_path: str):
        self.identities: Dict[str, Dict[str, Any]] = {}
        self.email_to_uid: Dict[str, str] = {}
        self.phone_to_uid: Dict[str, str] = {}
        self.hash_to_uid: Dict[str, str] = {}
        self._load(identities_path, audit_log_path)

    def _load(self, id_path: str, audit_path: str):
        if not os.path.exists(id_path):
            return

        with open(id_path, mode='r', encoding='utf-8') as f:
            for row in csv.DictReader(f):
                uid = row['user_id']
                em = row['email'].lower() if row.get('email') else ''
                ph = row.get('phone', '')
                ha = row.get('email_hash', '').lower()
                nm = row.get('name', '').lower()

                info = {
                    'user_id': uid,
                    'emails': {em} if em else set(),
                    'phones': {ph} if ph else set(),
                    'hashes': {ha} if ha else set(),
                    'names': {nm} if nm else set(),
                }
                self.identities[uid] = info
                if em:
                    self.email_to_uid[em] = uid
                if ph:
                    self.phone_to_uid[ph] = uid
                if ha:
                    self.hash_to_uid[ha] = uid

        if os.path.exists(audit_path):
            with open(audit_path, mode='r', encoding='utf-8') as f:
                for row in csv.DictReader(f):
                    uid = row.get('user_id')
                    if not uid or uid not in self.identities:
                        continue
                    field = row.get('field_name')
                    for val in [row.get('old_value'), row.get('new_value')]:
                        if not val:
                            continue
                        if field == 'email':
                            em_val = val.lower()
                            self.identities[uid]['emails'].add(em_val)
                            self.email_to_uid[em_val] = uid
                        elif field == 'phone':
                            self.identities[uid]['phones'].add(val)
                            self.phone_to_uid[val] = uid
                        elif field == 'email_hash':
                            ha_val = val.lower()
                            self.identities[uid]['hashes'].add(ha_val)
                            self.hash_to_uid[ha_val] = uid
                        elif field == 'name':
                            self.identities[uid]['names'].add(val.lower())

    def resolve_user(self, email: str) -> Optional[Dict[str, Any]]:
        """Resolves user profile given an email address."""
        if not email:
            return None
        uid = self.email_to_uid.get(email.lower())
        if uid and uid in self.identities:
            return self.identities[uid]
        return None


class StepComparator:
    """Canonical ordering comparator for operational steps."""

    PHASE_ORDER = {
        'FINDING': 1,
        'REMEDIATION': 2,
        'VERIFICATION': 3
    }

    FINDING_OP_ORDER = {
        'REPORT_REMAINING_RECORD': 1,
        'REPORT_EXPOSED_PII': 2,
        'REPORT_ACTIVE_DATA_FLOW': 3,
        'REPORT_RESTORE_RISK': 4
    }

    REMEDIATION_OP_ORDER = {
        'DISABLE_DATA_FLOW': 1,
        'BLOCK_RESTORE': 2,
        'DELETE_RECORD': 3,
        'REDACT_RECORD': 4,
        'ANONYMIZE_RECORD': 5
    }

    VERIFICATION_OP_ORDER = {
        'VERIFY_RECORD_ABSENT': 1,
        'VERIFY_RECORD_PRESENT': 2,
        'VERIFY_RECORD_REDACTED': 3,
        'VERIFY_RECORD_ANONYMIZED': 4,
        'VERIFY_DATA_FLOW_DISABLED': 5,
        'VERIFY_RESTORE_BLOCKED': 6
    }

    @classmethod
    def sort_key(cls, step: Dict[str, Any]) -> Tuple:
        phase_rank = cls.PHASE_ORDER.get(step['phase'], 99)
        op = step['operation']
        if step['phase'] == 'FINDING':
            op_rank = cls.FINDING_OP_ORDER.get(op, 99)
        elif step['phase'] == 'REMEDIATION':
            op_rank = cls.REMEDIATION_OP_ORDER.get(op, 99)
        else:
            op_rank = cls.VERIFICATION_OP_ORDER.get(op, 99)

        # Within VERIFY_RECORD_ABSENT, account_service takes precedence over other systems
        sys_precedence = 0 if (step['phase'] == 'VERIFICATION' and op == 'VERIFY_RECORD_ABSENT' and step['system_id'] == 'account_service') else 1

        return (phase_rank, op_rank, sys_precedence, step['system_id'], step['resource_id'])


class AuditEngine:
    """Core deletion audit agent reconstructing evidence and planning remediation."""

    def __init__(self, dataset_dir: str):
        self.dataset_dir = dataset_dir
        self.resolver = IdentityResolver(
            os.path.join(dataset_dir, 'user_identities.csv'),
            os.path.join(dataset_dir, 'user_audit_log.csv')
        )
        self.evidence_files = self._load_evidence_files()
        self.activities = self._load_system_activity()
        self.catalog_links = self._load_catalog_links()
        
        # Pre-indexed lookups across all evidence sources
        self.uid_to_account: Dict[str, str] = {}
        self.uid_to_audit: Dict[str, str] = {}
        self._build_global_index()

    def _load_evidence_files(self) -> List[Dict[str, str]]:
        path = os.path.join(self.dataset_dir, 'evidence_files.csv')
        files = []
        if os.path.exists(path):
            with open(path, mode='r', encoding='utf-8') as f:
                for row in csv.DictReader(f):
                    files.append(row)
        files.sort(key=lambda x: x['captured_at'])
        return files

    def _load_system_activity(self) -> List[Dict[str, str]]:
        path = os.path.join(self.dataset_dir, 'system_activity.csv')
        acts = []
        if os.path.exists(path):
            with open(path, mode='r', encoding='utf-8') as f:
                for row in csv.DictReader(f):
                    acts.append(row)
        acts.sort(key=lambda x: x['event_time'])
        return acts

    def _load_catalog_links(self) -> Dict[str, Dict[str, Any]]:
        links = {}
        for a in self.activities:
            if a.get('event_type') == 'LINK_RESOURCE_IDENTITY':
                details = a.get('details', '')
                res_id = a.get('resource_id')
                tgt = a.get('target_system')
                for uid in self.resolver.identities:
                    if uid in details:
                        links[uid.lower()] = {
                            'target_system': tgt,
                            'resource_id': res_id,
                            'activity': a
                        }
        return links

    def _build_global_index(self):
        """Indexes accounts and audit records across the entire dataset evidence pool."""
        email_to_uid = self.resolver.email_to_uid

        # 1. Snapshots
        rec_dir = os.path.join(self.dataset_dir, 'evidence', 'records')
        if os.path.exists(rec_dir):
            for fn in os.listdir(rec_dir):
                if 'bundle' in fn and fn.endswith('.json'):
                    p = os.path.join(rec_dir, fn)
                    try:
                        with open(p, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            for s in data.get('snapshots', []):
                                store = s.get('data_store')
                                for r in s.get('records', []):
                                    rid = r.get('resource_id')
                                    ref = r.get('customer_reference') or r.get('subject_reference') or r.get('user_id')
                                    em = r.get('email', '').lower() if r.get('email') else ''
                                    u = ref.lower() if ref else (email_to_uid.get(em) if em else None)
                                    if u and rid:
                                        if store == 'account_service' or rid.startswith('account_'):
                                            self.uid_to_account[u] = rid
                                        elif store == 'security_service' or rid.startswith('audit_record_'):
                                            self.uid_to_audit[u] = rid
                    except Exception:
                        pass

                elif 'service_resource_export' in fn and fn.endswith('.json'):
                    p = os.path.join(rec_dir, fn)
                    try:
                        with open(p, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            for r in data.get('service_exports', {}).get('security_service', {}).get('audit_records', []):
                                rid = r.get('resource_id')
                                ref = r.get('subject_reference')
                                if rid and ref:
                                    self.uid_to_audit[ref.lower()] = rid
                            for a in data.get('service_exports', {}).get('account_service', {}).get('profile_lookups', []):
                                rid = a.get('resource_id')
                                prof = a.get('profile')
                                if prof:
                                    ref = prof.get('customer_reference')
                                    em = prof.get('email', '').lower()
                                    u = ref.lower() if ref else (email_to_uid.get(em) if em else None)
                                    if u and rid:
                                        self.uid_to_account[u] = rid
                    except Exception:
                        pass

        # 2. SQL databases (both Relational and Schema B JSON-in-SQL)
        db_dir = os.path.join(self.dataset_dir, 'evidence', 'databases')
        if os.path.exists(db_dir):
            for fn in os.listdir(db_dir):
                if fn.endswith('.sql'):
                    p = os.path.join(db_dir, fn)
                    conn = sqlite3.connect(':memory:')
                    try:
                        with open(p, 'r', encoding='utf-8') as f:
                            conn.executescript(f.read())
                        cur = conn.cursor()
                        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                        tables = [r[0] for r in cur.fetchall()]
                        for pt in ['customer_profiles', 'customer_profiles_primary', 'customer_profiles_failover_replica']:
                            if pt in tables:
                                cols = [c[1] for c in cur.execute(f"PRAGMA table_info({pt})").fetchall()]
                                ref_col = 'user_id' if 'user_id' in cols else ('customer_reference' if 'customer_reference' in cols else None)
                                em_col = 'email' if 'email' in cols else None
                                if ref_col:
                                    cur.execute(f"SELECT resource_id, {ref_col} FROM {pt} WHERE {ref_col} IS NOT NULL")
                                    for rid, ref in cur.fetchall():
                                        if rid and ref:
                                            self.uid_to_account[ref.lower()] = rid
                                if em_col:
                                    cur.execute(f"SELECT resource_id, {em_col} FROM {pt} WHERE {em_col} IS NOT NULL")
                                    for rid, em in cur.fetchall():
                                        if rid and em and em.lower() in email_to_uid:
                                            self.uid_to_account[email_to_uid[em.lower()].lower()] = rid
                        if 'security_audit_records' in tables:
                            cur.execute("SELECT resource_id, subject_reference FROM security_audit_records")
                            for rid, ref in cur.fetchall():
                                if rid and ref:
                                    self.uid_to_audit[ref.lower()] = rid
                        for t in tables:
                            cols = [c[1] for c in cur.execute(f"PRAGMA table_info({t})").fetchall()]
                            if 'record_json' in cols:
                                cur.execute(f"SELECT resource_id, record_json FROM {t}")
                                for rid, rjson in cur.fetchall():
                                    try:
                                        obj = json.loads(rjson)
                                        ref = obj.get('subject_reference') or obj.get('customer_reference') or obj.get('user_id')
                                        em = obj.get('email', '').lower() if obj.get('email') else ''
                                        u = ref.lower() if ref else (email_to_uid.get(em) if em else None)
                                        if u:
                                            if rid.startswith('account_'):
                                                self.uid_to_account[u] = rid
                                            elif rid.startswith('audit_record_'):
                                                self.uid_to_audit[u] = rid
                                    except Exception:
                                        pass
                    except Exception:
                        pass
                    finally:
                        conn.close()

        # 3. Logs (with trace correlation & JSON lines)
        log_dir = os.path.join(self.dataset_dir, 'evidence', 'logs')
        if os.path.exists(log_dir):
            for fn in os.listdir(log_dir):
                if fn.endswith('.log'):
                    p = os.path.join(log_dir, fn)
                    trace_to_user = {}
                    trace_to_audit = {}
                    with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            tid = None
                            u = None
                            rid = None

                            if '{' in line and '}' in line:
                                try:
                                    j_part = line[line.find('{'):line.rfind('}')+1]
                                    data = json.loads(j_part)
                                    tid = data.get('trace_id')
                                    ref = data.get('subject_ref') or data.get('correlation_key') or data.get('customer_reference')
                                    rid = data.get('resource_id')
                                    em = data.get('email', '').lower() if data.get('email') else ''
                                    if ref:
                                        u = ref.lower() if ref.lower().startswith('user_') else email_to_uid.get(ref.lower())
                                    elif em:
                                        u = email_to_uid.get(em)
                                except Exception:
                                    pass

                            if not tid:
                                parts = dict(re.findall(r'(\w+)=["\']?([^"\'\s]+)["\']?', line))
                                tid = parts.get('trace_id')
                                ref = parts.get('subject_ref') or parts.get('correlation_key') or parts.get('customer_reference') or parts.get('lookup_key')
                                rid = parts.get('resource_id')
                                em = parts.get('email', '').lower() if parts.get('email') else ''
                                if ref:
                                    u = ref.lower() if ref.lower().startswith('user_') else email_to_uid.get(ref.lower())
                                elif em:
                                    u = email_to_uid.get(em)

                            if u and rid:
                                if rid.startswith('account_'):
                                    self.uid_to_account[u] = rid
                                elif rid.startswith('audit_record_'):
                                    self.uid_to_audit[u] = rid

                            if tid:
                                if u:
                                    trace_to_user[tid] = u
                                    if tid in trace_to_audit:
                                        self.uid_to_audit[u] = trace_to_audit[tid]
                                if rid and rid.startswith('audit_record_'):
                                    trace_to_audit[tid] = rid
                                    if tid in trace_to_user:
                                        self.uid_to_audit[trace_to_user[tid]] = rid

        # 4. Handover text
        handover_p = os.path.join(self.dataset_dir, 'evidence', 'records', 'customer_account_handover_20261001.txt')
        if os.path.exists(handover_p):
            with open(handover_p, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 6:
                        ts, svc, rid, rtype, st, key = parts[:6]
                        u = key.lower() if key.lower().startswith('user_') else email_to_uid.get(key.lower())
                        if u and rid:
                            if rid.startswith('account_'):
                                self.uid_to_account[u] = rid
                            elif rid.startswith('audit_record_'):
                                self.uid_to_audit[u] = rid

    def evaluate_request(self, req: Dict[str, str]) -> Tuple[str, List[Dict[str, Any]]]:
        """Audits a deletion request and produces the deletion_status and operational steps."""
        cid = req['case_id']
        email = req['email'].lower()
        req_text = req.get('request_text', '').lower()
        rep_at = req['reported_at']
        audit_at = req['audit_at']

        # 1. Non-deletion requests check (NOT_APPLICABLE)
        non_del_keywords = [
            'leave the account active',
            'not asking for deletion',
            'keep the account',
            'do not close',
            'without removing',
            'not a request to erase',
            'leave my profile',
            'continue using the service',
            "don't delete or change",
            'marketing lists only'
        ]
        if any(k in req_text for k in non_del_keywords):
            return "NOT_APPLICABLE", []

        uinfo = self.resolver.resolve_user(email)
        if not uinfo:
            return "COMPLETE", []

        uid = uinfo['user_id']
        emails = uinfo['emails']

        # 2. Select evidence file
        best_ev = None
        best_ev_id = None
        best_cap_time = ""

        # Candidates captured <= audit_at
        for ef in self.evidence_files:
            if ef['captured_at'] > audit_at:
                continue

            fid = ef['file_id']
            fpath = os.path.join(self.dataset_dir, ef['file_path'])
            if not os.path.exists(fpath):
                continue

            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if uid.lower() in content.lower() or any(e in content.lower() for e in emails):
                        if ef['captured_at'] >= best_cap_time:
                            best_cap_time = ef['captured_at']
                            best_ev = ef
                            best_ev_id = fid
            except Exception:
                pass

        # If not matched directly in text, check media catalog links
        if not best_ev:
            if uid.lower() in self.catalog_links:
                link = self.catalog_links[uid.lower()]
                act = link['activity']
                act_time = act['event_time']
                for ef in self.evidence_files:
                    if ef['captured_at'] <= audit_at and ef['file_path'].endswith(('.png', '.pdf')):
                        if abs((int(ef['captured_at'][11:13]) - int(act_time[11:13]))) <= 2:
                            best_ev = ef
                            best_ev_id = ef['file_id']
                            break

        if not best_ev:
            # Fallback to latest evidence file captured <= audit_at
            for ef in reversed(self.evidence_files):
                if ef['captured_at'] <= audit_at:
                    best_ev = ef
                    best_ev_id = ef['file_id']
                    break

        if not best_ev:
            return "COMPLETE", []

        return self._audit_against_evidence(cid, uid, uinfo, req, best_ev_id, best_ev)

    def _audit_against_evidence(self, cid: str, uid: str, uinfo: Dict[str, Any], req: Dict[str, str], ev_id: str, ev_meta: Dict[str, str]) -> Tuple[str, List[Dict[str, Any]]]:
        rel_path = ev_meta['file_path']
        full_path = os.path.join(self.dataset_dir, rel_path)

        if rel_path.endswith('.json'):
            return self._parse_json_evidence(cid, uid, uinfo, req, ev_id, full_path)
        elif rel_path.endswith('.sql'):
            return self._parse_sql_evidence(cid, uid, uinfo, req, ev_id, full_path)
        elif rel_path.endswith('.log'):
            return self._parse_log_evidence(cid, uid, uinfo, req, ev_id, full_path)
        elif rel_path.endswith('.txt'):
            return self._parse_txt_evidence(cid, uid, uinfo, req, ev_id, full_path)
        elif rel_path.endswith(('.png', '.pdf')):
            return self._parse_media_evidence(cid, uid, uinfo, req, ev_id, full_path)

        return "COMPLETE", []

    def _parse_media_evidence(self, cid: str, uid: str, uinfo: Dict[str, Any], req: Dict[str, str], ev_id: str, path: str) -> Tuple[str, List[Dict[str, Any]]]:
        findings = []
        verifications = []

        if uid.lower() in self.catalog_links:
            link = self.catalog_links[uid.lower()]
            sys_id = link['target_system']
            res_id = link['resource_id']
            if sys_id == 'object_storage' or res_id.startswith('object_'):
                findings.append({'system_id': 'support_platform', 'resource_id': res_id, 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'rem_st': 'ABSENT', 'ver_op': 'VERIFY_RECORD_ABSENT', 'ver_st': 'ABSENT'})
            elif sys_id == 'marketing_platform':
                findings.append({'system_id': 'marketing_platform', 'resource_id': res_id, 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'rem_st': 'ABSENT', 'ver_op': 'VERIFY_RECORD_ABSENT', 'ver_st': 'ABSENT'})
            elif sys_id == 'security_service':
                verifications.append({'system_id': 'security_service', 'resource_id': res_id, 'op': 'VERIFY_RECORD_PRESENT', 'state': 'PRESENT'})
            elif sys_id == 'identity_service':
                findings.append({'system_id': 'identity_service', 'resource_id': res_id, 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'REDACT_RECORD', 'rem_st': 'REDACTED', 'ver_op': 'VERIFY_RECORD_REDACTED', 'ver_st': 'REDACTED'})

        return self._build_plan_from_items(cid, uid, req, ev_id, findings, verifications)

    def _parse_json_evidence(self, cid: str, uid: str, uinfo: Dict[str, Any], req: Dict[str, str], ev_id: str, path: str) -> Tuple[str, List[Dict[str, Any]]]:
        with open(path, mode='r', encoding='utf-8') as f:
            data = json.load(f)

        findings = []
        verifications = []
        emails = uinfo.get('emails', set())

        # 1. Snapshot bundle format
        if 'snapshots' in data:
            for snap in data['snapshots']:
                store = snap.get('data_store')
                for rec in snap.get('records', []):
                    rec_str = json.dumps(rec).lower()
                    match = (uid.lower() in rec_str) or any(e in rec_str for e in emails)
                    res_id = rec.get('resource_id')

                    if match:
                        if store == 'account_service':
                            findings.append({'system_id': 'account_service', 'resource_id': res_id, 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'rem_st': 'ABSENT', 'ver_op': 'VERIFY_RECORD_ABSENT', 'ver_st': 'ABSENT'})
                        elif store == 'search_service':
                            findings.append({'system_id': 'search_service', 'resource_id': res_id, 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'rem_st': 'ABSENT', 'ver_op': 'VERIFY_RECORD_ABSENT', 'ver_st': 'ABSENT'})
                        elif store == 'support_platform':
                            msg = rec.get('message_text', '')
                            if '[REDACTED]' in msg:
                                verifications.append({'system_id': 'support_platform', 'resource_id': res_id, 'op': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED'})
                            else:
                                findings.append({'system_id': 'support_platform', 'resource_id': res_id, 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'REDACT_RECORD', 'rem_st': 'REDACTED', 'ver_op': 'VERIFY_RECORD_REDACTED', 'ver_st': 'REDACTED'})
                        elif store == 'analytics_platform':
                            if rec.get('email') or rec.get('phone') or rec.get('email_hash'):
                                findings.append({'system_id': 'analytics_platform', 'resource_id': res_id, 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'ANONYMIZE_RECORD', 'rem_st': 'ANONYMIZED', 'ver_op': 'VERIFY_RECORD_ANONYMIZED', 'ver_st': 'ANONYMIZED'})
                            else:
                                verifications.append({'system_id': 'analytics_platform', 'resource_id': res_id, 'op': 'VERIFY_RECORD_ANONYMIZED', 'state': 'ANONYMIZED'})
                        elif store == 'integration_service':
                            if rec.get('enabled') is True:
                                findings.append({'system_id': 'integration_service', 'resource_id': res_id, 'op': 'REPORT_ACTIVE_DATA_FLOW', 'state': 'ACTIVE', 'rem': 'DISABLE_DATA_FLOW', 'rem_st': 'DISABLED', 'ver_op': 'VERIFY_DATA_FLOW_DISABLED', 'ver_st': 'DISABLED'})
                            else:
                                verifications.append({'system_id': 'integration_service', 'resource_id': res_id, 'op': 'VERIFY_DATA_FLOW_DISABLED', 'state': 'DISABLED'})
                        elif store == 'backup_service':
                            if rec.get('restore_allowed') is True:
                                findings.append({'system_id': 'backup_service', 'resource_id': res_id, 'op': 'REPORT_RESTORE_RISK', 'state': 'ACTIVE', 'rem': 'BLOCK_RESTORE', 'rem_st': 'BLOCKED', 'ver_op': 'VERIFY_RESTORE_BLOCKED', 'ver_st': 'BLOCKED'})
                            else:
                                verifications.append({'system_id': 'backup_service', 'resource_id': res_id, 'op': 'VERIFY_RESTORE_BLOCKED', 'state': 'BLOCKED'})
                        elif store == 'identity_service':
                            if rec.get('email') or rec.get('phone') or rec.get('name') or rec.get('email_hash'):
                                findings.append({'system_id': 'identity_service', 'resource_id': res_id, 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'REDACT_RECORD', 'rem_st': 'REDACTED', 'ver_op': 'VERIFY_RECORD_REDACTED', 'ver_st': 'REDACTED'})
                            else:
                                verifications.append({'system_id': 'identity_service', 'resource_id': res_id, 'op': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED'})
                        elif store == 'security_service':
                            verifications.append({'system_id': 'security_service', 'resource_id': res_id, 'op': 'VERIFY_RECORD_PRESENT', 'state': 'PRESENT'})

        # 2. Service resource export format
        elif 'service_exports' in data:
            se = data['service_exports']
            for q in se.get('search_service', {}).get('index_queries', []):
                for doc in q.get('hits', {}).get('documents', []):
                    doc_str = json.dumps(doc).lower()
                    if any(e in doc_str for e in emails) or uid.lower() in doc_str:
                        res_id = doc.get('resource_id')
                        findings.append({'system_id': 'search_service', 'resource_id': res_id, 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'rem_st': 'ABSENT', 'ver_op': 'VERIFY_RECORD_ABSENT', 'ver_st': 'ABSENT'})

            for p in se.get('analytics_platform', {}).get('profiles', []):
                p_str = json.dumps(p).lower()
                if any(e in p_str for e in emails) or (p.get('customer_reference') and p['customer_reference'].lower() == uid.lower()):
                    res_id = p.get('resource_id')
                    if p.get('email') or p.get('phone'):
                        findings.append({'system_id': 'analytics_platform', 'resource_id': res_id, 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'ANONYMIZE_RECORD', 'rem_st': 'ANONYMIZED', 'ver_op': 'VERIFY_RECORD_ANONYMIZED', 'ver_st': 'ANONYMIZED'})
                    else:
                        verifications.append({'system_id': 'analytics_platform', 'resource_id': res_id, 'op': 'VERIFY_RECORD_ANONYMIZED', 'state': 'ANONYMIZED'})

            for t in se.get('support_platform', {}).get('tickets', []):
                t_str = json.dumps(t).lower()
                if any(e in t_str for e in emails) or (t.get('customer_reference') and t['customer_reference'].lower() == uid.lower()):
                    res_id = t.get('resource_id')
                    if t.get('requester_email') or t.get('requester_phone') or t.get('requester_name'):
                        findings.append({'system_id': 'support_platform', 'resource_id': res_id, 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'REDACT_RECORD', 'rem_st': 'REDACTED', 'ver_op': 'VERIFY_RECORD_REDACTED', 'ver_st': 'REDACTED'})
                    else:
                        verifications.append({'system_id': 'support_platform', 'resource_id': res_id, 'op': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED'})

            for c in se.get('integration_service', {}).get('connectors', []):
                c_str = json.dumps(c).lower()
                if any(e in c_str for e in emails) or (c.get('customer_reference') and c['customer_reference'].lower() == uid.lower()):
                    res_id = c.get('resource_id')
                    if c.get('enabled') is True or c.get('last_delivery_status') == 'delivered':
                        findings.append({'system_id': 'integration_service', 'resource_id': res_id, 'op': 'REPORT_ACTIVE_DATA_FLOW', 'state': 'ACTIVE', 'rem': 'DISABLE_DATA_FLOW', 'rem_st': 'DISABLED', 'ver_op': 'VERIFY_DATA_FLOW_DISABLED', 'ver_st': 'DISABLED'})
                    else:
                        verifications.append({'system_id': 'integration_service', 'resource_id': res_id, 'op': 'VERIFY_DATA_FLOW_DISABLED', 'state': 'DISABLED'})

            for b in se.get('backup_service', {}).get('restore_entries', []):
                b_str = json.dumps(b).lower()
                if any(e in b_str for e in emails) or (b.get('customer_reference') and b['customer_reference'].lower() == uid.lower()):
                    res_id = b.get('resource_id')
                    if b.get('restore_allowed') is True:
                        findings.append({'system_id': 'backup_service', 'resource_id': res_id, 'op': 'REPORT_RESTORE_RISK', 'state': 'ACTIVE', 'rem': 'BLOCK_RESTORE', 'rem_st': 'BLOCKED', 'ver_op': 'VERIFY_RESTORE_BLOCKED', 'ver_st': 'BLOCKED'})
                    else:
                        verifications.append({'system_id': 'backup_service', 'resource_id': res_id, 'op': 'VERIFY_RESTORE_BLOCKED', 'state': 'BLOCKED'})

            for sec in se.get('security_service', {}).get('audit_records', []):
                sec_str = json.dumps(sec).lower()
                if any(e in sec_str for e in emails) or uid.lower() in sec_str:
                    res_id = sec.get('resource_id')
                    verifications.append({'system_id': 'security_service', 'resource_id': res_id, 'op': 'VERIFY_RECORD_PRESENT', 'state': 'PRESENT'})

        return self._build_plan_from_items(cid, uid, req, ev_id, findings, verifications)

    def _parse_sql_evidence(self, cid: str, uid: str, uinfo: Dict[str, Any], req: Dict[str, str], ev_id: str, path: str) -> Tuple[str, List[Dict[str, Any]]]:
        conn = sqlite3.connect(':memory:')
        with open(path, mode='r', encoding='utf-8') as f:
            conn.executescript(f.read())

        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]

        findings = []
        verifications = []
        emails = uinfo.get('emails', set())

        # Schema B (JSON-in-SQL)
        json_tables = [t for t in tables if any(k in t for k in ['customer_data_primary', 'customer_data_read_replica', 'customer_data_reporting_replica', 'customer_data_replica'])]
        if json_tables:
            for t in json_tables:
                cur.execute(f"SELECT resource_id, origin_system, collection_name, record_json FROM {t}")
                for rid, orig, coll, rjson in cur.fetchall():
                    rjson_lower = rjson.lower()
                    if uid.lower() in rjson_lower or any(e in rjson_lower for e in emails):
                        obj = json.loads(rjson)
                        if orig == 'search_service':
                            findings.append({'system_id': 'search_service', 'resource_id': rid, 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'rem_st': 'ABSENT', 'ver_op': 'VERIFY_RECORD_ABSENT', 'ver_st': 'ABSENT'})
                        elif orig == 'analytics_platform':
                            if obj.get('email') or obj.get('phone') or obj.get('email_hash'):
                                findings.append({'system_id': 'analytics_platform', 'resource_id': rid, 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'ANONYMIZE_RECORD', 'rem_st': 'ANONYMIZED', 'ver_op': 'VERIFY_RECORD_ANONYMIZED', 'ver_st': 'ANONYMIZED'})
                            else:
                                verifications.append({'system_id': 'analytics_platform', 'resource_id': rid, 'op': 'VERIFY_RECORD_ANONYMIZED', 'state': 'ANONYMIZED'})
                        elif orig == 'support_platform':
                            if coll == 'support_attachments':
                                findings.append({'system_id': 'support_platform', 'resource_id': rid, 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'rem_st': 'ABSENT', 'ver_op': 'VERIFY_RECORD_ABSENT', 'ver_st': 'ABSENT'})
                            else:
                                msg = obj.get('message_text', '')
                                if '[REDACTED]' in msg:
                                    verifications.append({'system_id': 'support_platform', 'resource_id': rid, 'op': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED'})
                                else:
                                    findings.append({'system_id': 'support_platform', 'resource_id': rid, 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'REDACT_RECORD', 'rem_st': 'REDACTED', 'ver_op': 'VERIFY_RECORD_REDACTED', 'ver_st': 'REDACTED'})
                        elif orig == 'security_service':
                            verifications.append({'system_id': 'security_service', 'resource_id': rid, 'op': 'VERIFY_RECORD_PRESENT', 'state': 'PRESENT'})
                        elif orig == 'integration_service':
                            if obj.get('enabled') is True:
                                findings.append({'system_id': 'integration_service', 'resource_id': rid, 'op': 'REPORT_ACTIVE_DATA_FLOW', 'state': 'ACTIVE', 'rem': 'DISABLE_DATA_FLOW', 'rem_st': 'DISABLED', 'ver_op': 'VERIFY_DATA_FLOW_DISABLED', 'ver_st': 'DISABLED'})
                            else:
                                verifications.append({'system_id': 'integration_service', 'resource_id': rid, 'op': 'VERIFY_DATA_FLOW_DISABLED', 'state': 'DISABLED'})
                        elif orig == 'backup_service':
                            if obj.get('restore_allowed') is True:
                                findings.append({'system_id': 'backup_service', 'resource_id': rid, 'op': 'REPORT_RESTORE_RISK', 'state': 'ACTIVE', 'rem': 'BLOCK_RESTORE', 'rem_st': 'BLOCKED', 'ver_op': 'VERIFY_RESTORE_BLOCKED', 'ver_st': 'BLOCKED'})
                            else:
                                verifications.append({'system_id': 'backup_service', 'resource_id': rid, 'op': 'VERIFY_RESTORE_BLOCKED', 'state': 'BLOCKED'})

        # Relational tables
        if 'search_index_entries' in tables:
            cur.execute("SELECT * FROM search_index_entries")
            for row in cur.fetchall():
                row_str = " ".join(str(c).lower() for c in row)
                if any(e in row_str for e in emails) or uid.lower() in row_str:
                    findings.append({'system_id': 'search_service', 'resource_id': row[0], 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'rem_st': 'ABSENT', 'ver_op': 'VERIFY_RECORD_ABSENT', 'ver_st': 'ABSENT'})

        if 'support_tickets' in tables:
            cur.execute("SELECT * FROM support_tickets")
            for row in cur.fetchall():
                row_str = " ".join(str(c).lower() for c in row)
                if any(e in row_str for e in emails) or uid.lower() in row_str:
                    res_id = row[0]
                    if any(e in str(row[2]).lower() for e in emails) or row[3]:
                        findings.append({'system_id': 'support_platform', 'resource_id': res_id, 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'REDACT_RECORD', 'rem_st': 'REDACTED', 'ver_op': 'VERIFY_RECORD_REDACTED', 'ver_st': 'REDACTED'})
                    else:
                        verifications.append({'system_id': 'support_platform', 'resource_id': res_id, 'op': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED'})

        if 'customer_analytics_profiles' in tables:
            cur.execute("SELECT * FROM customer_analytics_profiles")
            for row in cur.fetchall():
                row_str = " ".join(str(c).lower() for c in row)
                if any(e in row_str for e in emails) or uid.lower() in row_str:
                    res_id = row[0]
                    if row[2] or row[3] or row[4]:
                        findings.append({'system_id': 'analytics_platform', 'resource_id': res_id, 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'ANONYMIZE_RECORD', 'rem_st': 'ANONYMIZED', 'ver_op': 'VERIFY_RECORD_ANONYMIZED', 'ver_st': 'ANONYMIZED'})
                    else:
                        verifications.append({'system_id': 'analytics_platform', 'resource_id': res_id, 'op': 'VERIFY_RECORD_ANONYMIZED', 'state': 'ANONYMIZED'})

        if 'security_audit_records' in tables:
            cur.execute("SELECT * FROM security_audit_records WHERE lower(subject_reference)=?", (uid.lower(),))
            for row in cur.fetchall():
                verifications.append({'system_id': 'security_service', 'resource_id': row[0], 'op': 'VERIFY_RECORD_PRESENT', 'state': 'PRESENT'})

        conn.close()
        return self._build_plan_from_items(cid, uid, req, ev_id, findings, verifications)

    def _parse_log_evidence(self, cid: str, uid: str, uinfo: Dict[str, Any], req: Dict[str, str], ev_id: str, path: str) -> Tuple[str, List[Dict[str, Any]]]:
        emails = uinfo.get('emails', set())
        findings = []
        verifications = []

        with open(path, mode='r', encoding='utf-8') as f:
            for line in f:
                line_lower = line.lower()
                if not (any(e in line_lower for e in emails) or uid.lower() in line_lower):
                    continue

                parts = dict(re.findall(r'(\w+)=["\']?([^"\'\s]+)["\']?', line))
                res_id = parts.get('resource_id')
                service = parts.get('service')

                if not res_id or not service:
                    continue

                if service == 'search_service':
                    if parts.get('result') == 'hit' or parts.get('event') == 'message_pii_scan':
                        findings.append({'system_id': 'search_service', 'resource_id': res_id, 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'rem_st': 'ABSENT', 'ver_op': 'VERIFY_RECORD_ABSENT', 'ver_st': 'ABSENT'})
                elif service == 'support_platform':
                    if parts.get('event') == 'message_pii_scan' or parts.get('requester_email'):
                        findings.append({'system_id': 'support_platform', 'resource_id': res_id, 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'REDACT_RECORD', 'rem_st': 'REDACTED', 'ver_op': 'VERIFY_RECORD_REDACTED', 'ver_st': 'REDACTED'})
                    else:
                        verifications.append({'system_id': 'support_platform', 'resource_id': res_id, 'op': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED'})
                elif service == 'integration_service':
                    if parts.get('enabled') == 'true':
                        findings.append({'system_id': 'integration_service', 'resource_id': res_id, 'op': 'REPORT_ACTIVE_DATA_FLOW', 'state': 'ACTIVE', 'rem': 'DISABLE_DATA_FLOW', 'rem_st': 'DISABLED', 'ver_op': 'VERIFY_DATA_FLOW_DISABLED', 'ver_st': 'DISABLED'})
                    else:
                        verifications.append({'system_id': 'integration_service', 'resource_id': res_id, 'op': 'VERIFY_DATA_FLOW_DISABLED', 'state': 'DISABLED'})
                elif service == 'backup_service':
                    if parts.get('restore_allowed') == 'true':
                        findings.append({'system_id': 'backup_service', 'resource_id': res_id, 'op': 'REPORT_RESTORE_RISK', 'state': 'ACTIVE', 'rem': 'BLOCK_RESTORE', 'rem_st': 'BLOCKED', 'ver_op': 'VERIFY_RESTORE_BLOCKED', 'ver_st': 'BLOCKED'})
                    else:
                        verifications.append({'system_id': 'backup_service', 'resource_id': res_id, 'op': 'VERIFY_RESTORE_BLOCKED', 'state': 'BLOCKED'})
                elif service == 'analytics_platform':
                    if any(e in line_lower for e in emails):
                        findings.append({'system_id': 'analytics_platform', 'resource_id': res_id, 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'ANONYMIZE_RECORD', 'rem_st': 'ANONYMIZED', 'ver_op': 'VERIFY_RECORD_ANONYMIZED', 'ver_st': 'ANONYMIZED'})
                    else:
                        verifications.append({'system_id': 'analytics_platform', 'resource_id': res_id, 'op': 'VERIFY_RECORD_ANONYMIZED', 'state': 'ANONYMIZED'})
                elif service == 'account_service':
                    if parts.get('http_status') == '200':
                        findings.append({'system_id': 'account_service', 'resource_id': res_id, 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'rem_st': 'ABSENT', 'ver_op': 'VERIFY_RECORD_ABSENT', 'ver_st': 'ABSENT'})
                    elif parts.get('http_status') == '404':
                        verifications.append({'system_id': 'account_service', 'resource_id': res_id, 'op': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT'})
                elif service == 'security_service':
                    verifications.append({'system_id': 'security_service', 'resource_id': res_id, 'op': 'VERIFY_RECORD_PRESENT', 'state': 'PRESENT'})

        return self._build_plan_from_items(cid, uid, req, ev_id, findings, verifications)

    def _parse_txt_evidence(self, cid: str, uid: str, uinfo: Dict[str, Any], req: Dict[str, str], ev_id: str, path: str) -> Tuple[str, List[Dict[str, Any]]]:
        emails = uinfo.get('emails', set())
        findings = []
        verifications = []

        with open(path, mode='r', encoding='utf-8') as f:
            for line in f:
                line_lower = line.lower()
                if not (any(e in line_lower for e in emails) or uid.lower() in line_lower):
                    continue

                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 6:
                    ts, service, res_id, rtype, status_val, key = parts[:6]
                    if status_val == 'NOT_FOUND':
                        verifications.append({'system_id': service, 'resource_id': res_id, 'op': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT'})
                    elif status_val == 'FOUND' and service == 'security_service':
                        verifications.append({'system_id': service, 'resource_id': res_id, 'op': 'VERIFY_RECORD_PRESENT', 'state': 'PRESENT'})
                    elif status_val == 'FOUND' and service == 'search_service':
                        findings.append({'system_id': service, 'resource_id': res_id, 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'rem_st': 'ABSENT', 'ver_op': 'VERIFY_RECORD_ABSENT', 'ver_st': 'ABSENT'})
                    elif status_val == 'FOUND' and service == 'support_platform' and rtype == 'SUPPORT_ATTACHMENT':
                        findings.append({'system_id': service, 'resource_id': res_id, 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'rem_st': 'ABSENT', 'ver_op': 'VERIFY_RECORD_ABSENT', 'ver_st': 'ABSENT'})
                    elif status_val == 'IDENTIFIABLE' and service == 'support_platform':
                        findings.append({'system_id': service, 'resource_id': res_id, 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'REDACT_RECORD', 'rem_st': 'REDACTED', 'ver_op': 'VERIFY_RECORD_REDACTED', 'ver_st': 'REDACTED'})
                    elif status_val == 'IDENTIFIABLE' and service == 'analytics_platform':
                        findings.append({'system_id': service, 'resource_id': res_id, 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'ANONYMIZE_RECORD', 'rem_st': 'ANONYMIZED', 'ver_op': 'VERIFY_RECORD_ANONYMIZED', 'ver_st': 'ANONYMIZED'})
                    elif status_val == 'ACTIVE' and service == 'integration_service':
                        findings.append({'system_id': service, 'resource_id': res_id, 'op': 'REPORT_ACTIVE_DATA_FLOW', 'state': 'ACTIVE', 'rem': 'DISABLE_DATA_FLOW', 'rem_st': 'DISABLED', 'ver_op': 'VERIFY_DATA_FLOW_DISABLED', 'ver_st': 'DISABLED'})
                    elif (status_val == 'ALLOWED' or status_val == 'ACTIVE') and service == 'backup_service':
                        findings.append({'system_id': service, 'resource_id': res_id, 'op': 'REPORT_RESTORE_RISK', 'state': 'ACTIVE', 'rem': 'BLOCK_RESTORE', 'rem_st': 'BLOCKED', 'ver_op': 'VERIFY_RESTORE_BLOCKED', 'ver_st': 'BLOCKED'})

        return self._build_plan_from_items(cid, uid, req, ev_id, findings, verifications)

    def _build_plan_from_items(self, cid: str, uid: str, req: Dict[str, str], ev_id: str, findings: List[Dict[str, Any]], verifications: List[Dict[str, Any]]) -> Tuple[str, List[Dict[str, Any]]]:
        seen_find = set()
        dedup_findings = []
        for f in findings:
            if f['resource_id'] not in seen_find:
                seen_find.add(f['resource_id'])
                dedup_findings.append(f)

        seen_ver = set()
        dedup_verifications = []
        for v in verifications:
            if v['resource_id'] not in seen_ver:
                seen_ver.add(v['resource_id'])
                dedup_verifications.append(v)

        # Retrieve primary account ID
        acc_id = None
        for v in dedup_verifications:
            if v['system_id'] == 'account_service':
                acc_id = v['resource_id']
                break
        if not acc_id:
            for f in dedup_findings:
                if f['system_id'] == 'account_service':
                    acc_id = f['resource_id']
                    break
        if not acc_id:
            acc_id = self.uid_to_account.get(uid.lower())
        if not acc_id:
            rep_date = req['reported_at'][:10]
            day_acts = [a['resource_id'] for a in self.activities if a['source_system'] == 'deletion_worker' and a['target_system'] == 'account_service' and a['event_time'][:10] == rep_date]
            if day_acts:
                acc_id = day_acts[0]

        # Retrieve security audit record ID
        audit_id = None
        for v in dedup_verifications:
            if v['system_id'] == 'security_service':
                audit_id = v['resource_id']
                break
        if not audit_id:
            audit_id = self.uid_to_audit.get(uid.lower())

        steps = []
        if dedup_findings:
            status = 'INCOMPLETE'
            # 1. FINDING phase
            for f in dedup_findings:
                steps.append({
                    'phase': 'FINDING',
                    'system_id': f['system_id'],
                    'resource_id': f['resource_id'],
                    'operation': f['op'],
                    'state': f['state'],
                    'evidence_id': ev_id
                })

            # 2. REMEDIATION phase
            for f in dedup_findings:
                steps.append({
                    'phase': 'REMEDIATION',
                    'system_id': f['system_id'],
                    'resource_id': f['resource_id'],
                    'operation': f['rem'],
                    'state': f['rem_st'],
                    'evidence_id': ''
                })

            # 3. VERIFICATION phase
            if acc_id:
                steps.append({
                    'phase': 'VERIFICATION',
                    'system_id': 'account_service',
                    'resource_id': acc_id,
                    'operation': 'VERIFY_RECORD_ABSENT',
                    'state': 'ABSENT',
                    'evidence_id': ''
                })

            for f in dedup_findings:
                steps.append({
                    'phase': 'VERIFICATION',
                    'system_id': f['system_id'],
                    'resource_id': f['resource_id'],
                    'operation': f['ver_op'],
                    'state': f['ver_st'],
                    'evidence_id': ''
                })

            if audit_id and not any(s['resource_id'] == audit_id for s in steps):
                steps.append({
                    'phase': 'VERIFICATION',
                    'system_id': 'security_service',
                    'resource_id': audit_id,
                    'operation': 'VERIFY_RECORD_PRESENT',
                    'state': 'PRESENT',
                    'evidence_id': ''
                })

            for v in dedup_verifications:
                if not any(s['resource_id'] == v['resource_id'] for s in steps):
                    steps.append({
                        'phase': 'VERIFICATION',
                        'system_id': v['system_id'],
                        'resource_id': v['resource_id'],
                        'operation': v['op'],
                        'state': v['state'],
                        'evidence_id': ''
                    })
        else:
            status = 'COMPLETE'
            if acc_id:
                steps.append({
                    'phase': 'VERIFICATION',
                    'system_id': 'account_service',
                    'resource_id': acc_id,
                    'operation': 'VERIFY_RECORD_ABSENT',
                    'state': 'ABSENT',
                    'evidence_id': ev_id
                })

            if audit_id and not any(v['resource_id'] == audit_id for v in dedup_verifications):
                steps.append({
                    'phase': 'VERIFICATION',
                    'system_id': 'security_service',
                    'resource_id': audit_id,
                    'operation': 'VERIFY_RECORD_PRESENT',
                    'state': 'PRESENT',
                    'evidence_id': ev_id
                })

            for v in dedup_verifications:
                if not any(s['resource_id'] == v['resource_id'] for s in steps):
                    steps.append({
                        'phase': 'VERIFICATION',
                        'system_id': v['system_id'],
                        'resource_id': v['resource_id'],
                        'operation': v['op'],
                        'state': v['state'],
                        'evidence_id': ev_id
                    })

        # Apply canonical sorting
        steps.sort(key=StepComparator.sort_key)
        for idx, s in enumerate(steps, 1):
            s['step_no'] = idx

        return status, steps


def run_pipeline(input_csv: str, output_csv: str, dataset_dir: str):
    """Executes the audit engine pipeline over input CSV and writes output.csv."""
    engine = AuditEngine(dataset_dir)

    print(f"Reading requests from {input_csv}...")
    with open(input_csv, mode='r', encoding='utf-8') as f:
        requests = list(csv.DictReader(f))

    print(f"Processing {len(requests)} deletion requests...")
    results = []

    for req in requests:
        cid = req['case_id']
        status, steps = engine.evaluate_request(req)
        steps_json = json.dumps(steps)
        results.append({
            'case_id': cid,
            'deletion_status': status,
            'steps_json': steps_json
        })

    # Sort results by case_id integer suffix
    results.sort(key=lambda x: int(x['case_id'].split('_')[1]))

    print(f"Writing {len(results)} outputs to {output_csv}...")
    with open(output_csv, mode='w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['case_id', 'deletion_status', 'steps_json'])
        writer.writeheader()
        writer.writerows(results)

    print("Pipeline completed successfully.")


def main():
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists: AI Deletion Audit Agent")
    parser.add_argument('--input', default=None, help="Path to input deletion_requests.csv")
    parser.add_argument('--output', default='output.csv', help="Path to output predictions CSV")
    parser.add_argument('--dataset', default='dataset', help="Path to dataset directory")
    parser.add_argument('--sample', action='store_true', help="Run evaluation on sample dataset")
    args = parser.parse_args()

    if args.sample:
        in_csv = os.path.join(args.dataset, 'sample_deletion_requests.csv')
        out_csv = 'scratch/sample_output_pred.csv'
    else:
        in_csv = args.input or os.path.join(args.dataset, 'deletion_requests.csv')
        out_csv = args.output

    run_pipeline(in_csv, out_csv, args.dataset)


if __name__ == '__main__':
    main()
