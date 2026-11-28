#!/usr/bin/env python3
"""Finite root-side acceptance observer for installed gvx generations.

Run only from installed root-owned code through integration sandbox --policy-plan.
Plan v2: schema_version, base_sha256, cases, case_seconds (180..300), controls
(unrelated systemd service identities: name + invocation_id), fixtures (case ->
list of {config, config_sha256}, one approved isolated installation per operation),
network_cases and network_controls. Every fixture is initialized and its exact
image prepared by the ordinary installed lifecycle before this observer runs.
ManagementDirectory is StorageRoot/app; protected Control is never worker state.
Explicit app_bytes/app_inodes reserve part of Data, not additional backing.
The native-app claim remains reserved after stop; only per-instance scratch
claims require reclamation. No app usage is reported as an ephemeral zero.
The observer never installs services, updates approvals, edits configurations or
writes the Store. The immutable fixture configuration selects its finite workload.
Network cases retain one TCP/DNS/HTTP/fresh-resolution operation per instance,
positive operator controls, stable generation/counters and exact redirect hashes.

All 33 existing cases remain selected by their original names. "ipc" quotas now
measure guest-private /tmp on the shared scratch project, not a host IPC mount.
ipc-race observes the real worker's native listener/path-O_PATH pair and the
fixture's guest-local pinned-endpoint replacement race through the normal bridge.
cleanup-crash holds one exact owned scratch allocation, observes retained claims
after module units stop, kills the authenticated worker during DRAIN and uses CLI stop.
Only exact pidfd-pinned owner/worker signals and supported CLI start/stop are used.
Missing or uncertain evidence is never inferred from a single missing unit.
"""
import argparse
import copy
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import platform
import ipaddress
import socket
import re
import selectors
import signal
import sqlite3
import stat
import struct
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

# Bound once from trusted operator inputs, never lab identities.
DATA = MANAGEMENT = CONTROL = STORAGE = IPC = BASE = RUNTIME = IMAGE = MODULE = None
UID = GID = GUEST_UID = GUEST_GID = None
PROFILE = LIMITS = RESOURCES = PLAN = BASE_CONFIG = PUBLIC_CONFIG = None
CURRENT_CASE = MANIFEST = CURRENT_FIXTURE = CHECKER = None
ACTIVE_NETWORK_SPEC = None
NETWORK_CASES = ('network-none', 'network-public', 'network-dns', 'network-redirect', 'ipv6-public', 'dns-rebinding')
REPORT_LIMIT = 128 * 4096
ID = re.compile(r'[0-9a-f]{32}\Z')
INVOCATION = re.compile(r'[0-9a-f]{32}\Z')
QUOTA_NAME = re.compile(r'probe-quota-[A-Za-z0-9]+\Z')
REPORT_NAME = re.compile(r'probe-results-[A-Za-z0-9]+\.ndjson\Z')
QUOTA_FILE = re.compile(r'(allocation|source|link-from-(persistent|scratch|ipc)|empty-[0-9]{5})\Z')
PHASES = {'RUNNING', 'STOPPED', 'STOP_FAILED', 'BACKEND_ERROR'}
STOP_KEYS = {'instance_id', 'snapshot_present', 'state', 'failure_reason',
             'cleanup_complete', 'retained_events', 'retained_bytes',
             'incomplete_events', 'stop_error_code', 'cleanup_error_code',
             'cleanup_failure_phases'}
CASES = ('cpu', 'memory-oom', 'fork', 'thread', 'identity',
         'persistent-bytes', 'persistent-inodes', 'scratch-bytes', 'scratch-inodes',
         'ipc-bytes', 'ipc-inodes', 'combined-bytes', 'combined-inodes',
         'cross-project-link', 'flood', 'init-failure', 'readiness-failure',
         'start-failure', 'startup-budget', 'module-crash', 'runtime-sigkill',
         'normal-exit', 'sigterm', 'sigint', 'cleanup-crash', 'ipc-race', 'ipc-held-unlinked') + NETWORK_CASES
INTERRUPTED = False


class Fault(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def check(until):
    if time.monotonic() >= until:
        raise Fault('DEADLINE')


def interrupted(_sig, _frame):
    global INTERRUPTED
    INTERRUPTED = True


def need(value, code):
    if not value:
        raise Fault(code)


def canonical(path):
    p = Path(path)
    need(p.is_absolute() and str(p) == os.path.normpath(str(p)) and str(p) != '/', 'NONCANONICAL_PATH')
    return p


def open_no_links(path, flags=os.O_RDONLY, mode=0o600):
    """Walk all ancestors with held directory descriptors, including guest trees."""
    p = canonical(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in p.parts[1:-1]:
            other = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = other
        return os.open(p.name, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, mode, dir_fd=fd)
    finally:
        os.close(fd)


def trusted(path, directory=False, private=False):
    p = canonical(path)
    for item in (p, *p.parents):
        fd = open_no_links(item, os.O_RDONLY | os.O_DIRECTORY) if item != Path('/') and (item != p or directory) else None
        try:
            st = os.fstat(fd) if fd is not None else os.lstat(item)
            need(st.st_uid == 0 and not st.st_mode & 0o022, 'UNTRUSTED_OPERATOR_PATH')
            if item == p:
                need(stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode), 'OPERATOR_PATH_TYPE')
                if private:
                    need(st.st_mode & 0o077 == 0, 'OUTPUT_NOT_PRIVATE')
        finally:
            if fd is not None:
                os.close(fd)


def bounded_read(path, limit, pseudo=False):
    fd = open_no_links(path)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode), 'NOT_REGULAR_FILE')
        if not pseudo:
            need(st.st_size <= limit, 'FILE_BOUND_EXCEEDED')
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        need(len(data) <= limit, 'FILE_BOUND_EXCEEDED')
        return bytes(data), st
    finally:
        os.close(fd)


def private_json(path, value):
    fd = open_no_links(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, sort_keys=True, separators=(',', ':'))
        f.write('\n')


def scan_names(path, until, maximum=4096):
    check(until)
    fd = open_no_links(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        names = set()
        with os.scandir(fd) as entries:
            for entry in entries:
                check(until)
                need(len(names) < maximum, 'DIRECTORY_ENTRY_BOUND')
                names.add(entry.name)
        return names
    finally:
        os.close(fd)


def safe_errno(exc):
    return {'error_type': type(exc).__name__, 'errno': getattr(exc, 'errno', None),
            'code': exc.code if isinstance(exc, Fault) else 'OPERATION_FAILED'}


def is_public(case):
    return case in NETWORK_CASES and case != 'network-none'


def config_for(base, case):
    c = copy.deepcopy(PUBLIC_CONFIG if is_public(case) else base)
    fixture = c['modules'][0]['config']
    fixture['lifecycle'] = {'init_artifact': True}
    s = {'kind': case, 'timeout_seconds': 25,
         'trigger_delay_ms': 30000 if case in NETWORK_CASES else 1000 if case == 'normal-exit' else 5000}
    if case == 'cpu':
        s.update(workers=8, timeout_seconds=15)
    elif case == 'memory-oom':
        s.update(kind='memory', memory_bytes=min(2 << 30, RESOURCES['memory_bytes'] * 2), hold_ms=10000)
    elif case in ('fork', 'thread'):
        s.update(attempts=min(256, RESOURCES['pids'] * 2), hold_ms=10000)
    elif case.endswith('-failure'):
        fixture['lifecycle'].update(fail_stage=case.removesuffix('-failure'), readiness_delay_ms=100)
        return c, None
    elif case == 'startup-budget':
        need(c['defaults']['startup_deadline'] == '30s' and LIMITS['hook_rpc_deadline'] == '5s',
             'STARTUP_BUDGET_PREREQUISITE')
        fixture['lifecycle'].update(init_delay_ms=2000, readiness_delay_ms=24000, start_delay_ms=4500)
        return c, None
    elif case in ('module-crash', 'runtime-sigkill', 'normal-exit', 'sigterm', 'sigint', 'cleanup-crash'):
        s['kind'] = 'crash' if case == 'module-crash' else 'identity'
        if case == 'cleanup-crash':
            s.update(kind='quota', timeout_seconds=60, quota={
                'operation': 'held-file', 'target': 'ipc', 'target_bytes': 1 << 20,
                'chunk_bytes': 1 << 20, 'hold_ms': 30000, 'retain_files': True})
    elif case == 'ipc-held-unlinked':
        s.update(kind='quota', timeout_seconds=60, quota={
            'operation': 'held-file', 'target': 'ipc', 'target_bytes': 1 << 20,
            'chunk_bytes': 1 << 20, 'hold_ms': 30000, 'unlink_held': True})
    elif case == 'ipc-race':
        s['kind'] = 'identity'
        fixture['endpoint_race'] = True
    elif case in NETWORK_CASES:
        s.update(kind='network', timeout_seconds=90, network=ACTIVE_NETWORK_SPEC or PLAN['network_cases'][case])
    elif case == 'flood':
        n = LIMITS['log_file_max_bytes'] * (LIMITS['log_retained_files'] + 2)
        need(n <= 64 << 20, 'FIXTURE_OUTPUT_BOUND_TOO_SMALL_FOR_LOG_CONFIG')
        s.update(stdout_bytes=n, stderr_bytes=n, timeout_seconds=40)
    elif case != 'identity':
        q = {'operation': 'bytes', 'target': '', 'chunk_bytes': 1 << 20,
             'hold_ms': 5000, 'retain_files': False}
        if case in ('combined-bytes', 'combined-inodes', 'cross-project-link'):
            q['operation'] = case
            if case == 'combined-bytes':
                q['target_bytes'] = RESOURCES['scratch_bytes'] + (16 << 20)
            elif case == 'combined-inodes':
                q['target_files'] = min(65536, LIMITS['scratch_inode_limit'] + 1024)
        else:
            target, operation = case.split('-')
            q.update(target=target, operation='bytes' if operation == 'bytes' else 'inodes')
            if operation == 'bytes':
                q['target_bytes'] = RESOURCES['persistent_bytes' if target == 'persistent' else 'scratch_bytes'] + (16 << 20)
            else:
                q['target_files'] = min(65536, LIMITS['persistent_inode_limit' if target == 'persistent' else 'scratch_inode_limit'] + 1024)
        s.update(kind='quota', quota=q, timeout_seconds=100)
    fixture['scenario'] = s
    return c, s


def validate_base(base):
    need(base['schema_version'] == 2 and base['backends'] == {} and len(base['modules']) == 1,
         'DEDICATED_BACKENDLESS_CONFIG_REQUIRED')
    m = base['modules'][0]
    need(m['uid'] != 0 and m['gid'] != 0 and not m.get('credential_bindings') and
         re.fullmatch(r'(?:record:sha256:|[^@\s]+@sha256:)[0-9a-f]{64}', m['image']), 'CANONICAL_PREPARED_NONROOT_IMAGE_REQUIRED')
    need(m['approval']['egressPolicy'] == 'EGRESS_POLICY_NONE', 'NONE_BASE_APPROVAL_REQUIRED')
    need('scenario' not in m['config'] and 'lifecycle' not in m['config'], 'BASE_FIXTURE_CONTROLS_PRESENT')
    need(base['host']['quota_backend'] == 'xfs-project' and
         ID.fullmatch(base['host']['runtime_installation_id']) and
         re.fullmatch(r'sha256:[0-9a-f]{64}', base['host']['bundle_digest']), 'INSTALLED_GVX_XFS_REQUIRED')
    need(canonical(base['host']['management_directory']) == canonical(base['host']['storage_root']) / 'app',
         'CANONICAL_QUOTA_BACKED_APP_ROOT_REQUIRED')



def native_app_claim(journal):
    identity = MANIFEST['runtime_installation_id'] + ':app'
    rows = journal.rows('SELECT id,kind,bytes,inodes,project,state FROM storage_claims WHERE id=?',
                        (identity,), maximum=1)
    need(len(rows) == 1, 'NATIVE_APP_RESERVATION_MISSING')
    claim = rows[0]
    need(claim['kind'] == 'native-app' and claim['state'] == 'RESERVED' and claim['project'] > 0 and
         claim['bytes'] == MANIFEST['budget']['app_bytes'] and claim['inodes'] == MANIFEST['budget']['app_inodes'],
         'NATIVE_APP_RESERVATION_MISMATCH')
    generation = journal.rows('SELECT generation FROM storage_generations WHERE claim=?', (identity,), maximum=1)
    need(generation == [{'generation': 'native-app:' + MANIFEST['runtime_installation_id']}],
         'NATIVE_APP_GENERATION_BINDING_MISSING')
    totals = journal.rows("SELECT coalesce(sum(bytes),0) AS bytes,coalesce(sum(inodes),0) AS inodes "
                          "FROM storage_claims WHERE state!='RELEASED' AND kind IN ('persistent','scratch','native-app')",
                          maximum=1)[0]
    need(totals['bytes'] <= MANIFEST['budget']['data_bytes'] and
         totals['inodes'] <= MANIFEST['budget']['data_inodes'], 'DATA_SUBRESERVATIONS_OVERCOMMITTED')
    return claim


def native_app_identity(journal, claim):
    import base64
    app = MANIFEST['identities']['app']
    identities = {}
    for name in ('', 'native', 'logs', 'uploads'):
        path = MANAGEMENT / name
        fd = open_no_links(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            st = os.fstat(fd)
            attrs = bytearray(28)
            fcntl.ioctl(fd, 0x801c581f, attrs, True)
            flags, _, _, project, _, _ = struct.unpack('=IIIII8s', attrs)
            need(st.st_uid == app['uid'] and st.st_gid == app['gid'] and stat.S_IMODE(st.st_mode) == 0o700 and
                 st.st_dev == os.stat(STORAGE).st_dev and project == claim['project'] and flags & 0x200,
                 'NATIVE_APP_QUOTA_OR_CREDENTIAL_IDENTITY')
            records = journal.rows("SELECT record FROM provisioning_ledger WHERE kind='directory' AND identity=?",
                                   (str(path),), maximum=8)
            observed = []
            for row in records:
                record = json.loads(row['record'])
                if record['state'] == 'OBSERVED' and record['product_created'] and not record['existed_before']:
                    raw = base64.b64decode(record['observed']['attributes'], validate=True)
                    observed.append(json.loads(raw))
            need(any(record.get('path') == str(path) and record.get('dev') == st.st_dev and record.get('ino') == st.st_ino and
                     record.get('uid') == app['uid'] and record.get('gid') == app['gid'] and record.get('mode') == 0o700
                     for record in observed), 'NATIVE_APP_LEDGER_INODE_MISMATCH')
            identities[name or 'app'] = {'device': st.st_dev, 'inode': st.st_ino, 'uid': st.st_uid,
                                        'gid': st.st_gid, 'mode': stat.S_IMODE(st.st_mode), 'project': project}
        finally:
            os.close(fd)
    return identities


class Journal:
    def __init__(self):
        path = CONTROL / 'supervisor.sqlite'
        trusted(path)
        self.db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=0.2)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA query_only=ON')
        self.until = time.monotonic() + 1
        self.db.set_progress_handler(lambda: int(time.monotonic() >= self.until), 100)

    def rows(self, sql, args=(), maximum=16):
        self.until = time.monotonic() + 0.5
        cur = self.db.execute(sql, args)
        rows = cur.fetchmany(maximum + 1)
        need(len(rows) <= maximum, 'JOURNAL_ROW_BOUND')
        return [dict(row) for row in rows]

    def active(self):
        return self.rows("SELECT id,epoch,state,cleanup FROM instances WHERE cleanup!='COMPLETE'", maximum=64)

    def installation(self):
        rows = self.rows('SELECT storage_key,project,uid,gid,image FROM installations WHERE module_id=?', (MODULE,))
        if not rows:
            return None
        row = rows[0]
        need(ID.fullmatch(row['storage_key']) and row['uid'] == GUEST_UID and row['gid'] == GUEST_GID,
             'INSTALLATION_IDENTITY')
        return row

    def owned(self, pid, started, epoch=None):
        rows = self.rows('SELECT id,pid,started,state,boot_id,start_identity FROM runtime_epochs WHERE pid=? AND started>=?', (pid, started))
        need(len(rows) <= 1, 'AMBIGUOUS_EPOCH')
        if not rows:
            return None, None
        e = rows[0]
        need(ID.fullmatch(e['id']) and (epoch is None or e['id'] == epoch), 'EPOCH_IDENTITY')
        rows = self.rows('SELECT id,module_id,epoch,lease,state,reason,cleanup,started,ended FROM instances WHERE epoch=?', (e['id'],))
        need(len(rows) <= 1, 'UNEXPECTED_EPOCH_INSTANCES')
        if not rows:
            return e, None
        r = rows[0]
        lease = json.loads(r.pop('lease'))
        o, s = lease['ownership'], lease['spec']
        need(r['module_id'] == MODULE and ID.fullmatch(r['id']) and
             o['instance_id'] == r['id'] == s['instance_id'] and o['epoch_id'] == e['id'] and
             o['runtime_installation_id'] == MANIFEST['runtime_installation_id'] and
             ID.fullmatch(o['installation_id']) and s['module_id'] == MODULE and
             s['image_digest'] == IMAGE and s['uid'] == GUEST_UID and s['gid'] == GUEST_GID,
             'LEASE_IDENTITY')
        paths = {'persistent_path': STORAGE / 'persistent' / o['installation_id'],
                 'scratch_path': STORAGE / 'instances' / r['id'] / 'scratch',
                 'ipc_path': STORAGE / 'instances' / r['id'] / 'ipc',
                 'bootstrap_path': STORAGE / 'instances' / r['id'] / 'bootstrap',
                 'log_path': STORAGE / 'instances' / r['id'] / 'logs'}
        need(all(lease[k] == str(v) for k, v in paths.items()), 'LEASE_PATH_IDENTITY')
        expected = CURRENT_FIXTURE['config']['modules'][0]
        need(s['entrypoint'] == expected['entrypoint'] and (s['args'] or []) == (expected['args'] or [])
             and s['initial_egress'] == ('PUBLIC' if is_public(CURRENT_CASE) else 'NONE')
             and s['resources'] == RESOURCES, 'LEASE_PROFILE_MISMATCH')
        installation = self.installation()
        need(installation and installation['storage_key'] == o['installation_id']
             and installation['project'] == lease['persistent_project'], 'INSTALLATION_LEASE_MISMATCH')
        r['lease'] = lease
        r['claims'] = self.rows('SELECT kind,identity,state FROM resource_claims WHERE instance=? ORDER BY kind', (r['id'],))
        r['creates'] = self.rows('SELECT kind,identity,state,object_id FROM create_submissions WHERE instance=? ORDER BY kind', (r['id'],))
        for key, table in (('unit', 'unit_observations'), ('network', 'network_records'),
                           ('endpoint', 'native_endpoints'), ('roots', 'guest_root_intents')):
            records = self.rows('SELECT record FROM ' + table + ' WHERE instance=?', (r['id'],), maximum=1)
            r[key] = json.loads(records[0]['record']) if records else None
        endpoints = self.rows('SELECT transfer_state,transports_closed FROM native_endpoints WHERE instance=?', (r['id'],), maximum=1)
        r['endpoint_transfer'] = endpoints[0] if endpoints else None
        return e, r

    def worker(self):
        records = self.rows("SELECT record FROM provisioning_ledger WHERE kind='unit'", maximum=128)
        units = []
        for row in records:
            record = json.loads(row['record'])
            attributes = record.get('observed', {}).get('attributes')
            if not attributes:
                continue
            import base64
            properties = json.loads(base64.b64decode(attributes))
            unit = properties.get('unit')
            if unit and unit['name'].startswith('chatanium-worker-') and unit['boot_id'] == boot_identity():
                units.append(unit)
        live = []
        for unit in units:
            try:
                if proc_start(unit['main_pid']) == unit['start_time']:
                    live.append(unit)
            except FileNotFoundError:
                pass
        need(len(live) <= 1, 'AMBIGUOUS_LIVE_WORKER')
        return live[0] if live else None


class DiskQuota(ctypes.Structure):
    _fields_ = [('version', ctypes.c_int8), ('flags', ctypes.c_int8), ('fieldmask', ctypes.c_uint16),
                ('id', ctypes.c_uint32), ('block_hard', ctypes.c_uint64), ('block_soft', ctypes.c_uint64),
                ('inode_hard', ctypes.c_uint64), ('inode_soft', ctypes.c_uint64), ('blocks', ctypes.c_uint64),
                ('inodes', ctypes.c_uint64), ('itimer', ctypes.c_int32), ('btimer', ctypes.c_int32),
                ('iwarns', ctypes.c_uint16), ('bwarns', ctypes.c_uint16), ('timer_high', ctypes.c_int8 * 4),
                ('rtblock_hard', ctypes.c_uint64), ('rtblock_soft', ctypes.c_uint64), ('rtblocks', ctypes.c_uint64),
                ('rttimer', ctypes.c_int32), ('rtwarns', ctypes.c_uint16), ('pad3', ctypes.c_int16),
                ('pad4', ctypes.c_uint8 * 8)]


class Quotas:
    def __init__(self):
        need(platform.machine() == 'x86_64' and ctypes.sizeof(DiskQuota) == 112, 'UNSUPPORTED_QUOTA_ABI')
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.syscall.restype = ctypes.c_long

    def read(self, project):
        d = DiskQuota(version=1, flags=2, id=project)
        # Linux x86_64 quotactl_fd(443), XFS Q_XGETQUOTA / PRJQUOTA; READ ONLY.
        fd = open_no_links(STORAGE, os.O_RDONLY | os.O_DIRECTORY)
        try:
            rc = self.libc.syscall(ctypes.c_long(443), ctypes.c_int(fd),
                                   ctypes.c_uint(((ord('X') << 8 | 3) << 8) | 2),
                                   ctypes.c_uint(project), ctypes.byref(d))
            error = ctypes.get_errno()
        finally:
            os.close(fd) # Never pin the backing mount across owner cleanup.
        if rc != 0:
            return {'project': project, 'status': 'UNAVAILABLE', 'errno': error}
        return {'project': project, 'status': 'MEASURED', 'bytes': d.blocks * 512,
                'inodes': d.inodes, 'hard_bytes': d.block_hard * 512, 'soft_bytes': d.block_soft * 512,
                'hard_inodes': d.inode_hard, 'soft_inodes': d.inode_soft,
                'realtime_bytes': d.rtblocks * 512}



class RuntimeOutput:
    def __init__(self, proc):
        self.proc = proc
        self.selector = selectors.DefaultSelector()
        self.pending = {1: bytearray(), 2: bytearray()}
        self.bytes = {1: 0, 2: 0}
        self.discarded = 0
        self.events = []
        for stream, number in ((proc.stdout, 1), (proc.stderr, 2)):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, number)

    def pump(self, seconds=0.05):
        # Fixed-sized reads, never readline()/communicate() on fixture output.
        for key, _ in self.selector.select(max(0, min(seconds, 0.1))):
            number = key.data
            try:
                chunk = os.read(key.fd, 16384)
            except BlockingIOError:
                continue
            if not chunk:
                self.selector.unregister(key.fileobj)
                key.fileobj.close()
                continue
            self.bytes[number] += len(chunk)
            if number == 2:
                # Raw runtime/daemon errors and module output are never retained.
                continue
            b = self.pending[number]
            b.extend(chunk)
            while b'\n' in b:
                raw, _, rest = b.partition(b'\n')
                b[:] = rest
                if len(raw) > 4096 or len(self.events) >= 64:
                    self.discarded += 1
                    continue
                try:
                    v = json.loads(raw)
                    need(isinstance(v, dict), 'NON_OBSERVATION')
                    need(isinstance(v, dict) and v.get('phase') in PHASES and v.get('modules') == 1
                         and type(v.get('voice')) is bool, 'NON_OBSERVATION')
                    event = {k: v[k] for k in ('phase', 'modules', 'voice')}
                    if isinstance(v.get('stop_failure'), dict):
                        sf = v['stop_failure']
                        filtered = {}
                        for k in STOP_KEYS & sf.keys():
                            value = sf[k]
                            if isinstance(value, (bool, int)) or (isinstance(value, str) and len(value) <= 128
                                    and re.fullmatch(r'[A-Za-z0-9_:.-]*', value)):
                                filtered[k] = value
                            elif k == 'cleanup_failure_phases' and isinstance(value, list) and len(value) <= 16:
                                filtered[k] = [x for x in value if isinstance(x, str) and re.fullmatch(r'[A-Z_]{1,64}', x)]
                        event['stop_failure'] = filtered
                    event['observed_monotonic'] = time.monotonic()
                    self.events.append(event)
                except (ValueError, TypeError, Fault):
                    self.discarded += 1
            if len(b) > 4096:
                b.clear()
                self.discarded += 1

    def running(self):
        return any(x['phase'] == 'RUNNING' for x in self.events)

    def close(self):
        self.selector.close()
        for s in (self.proc.stdout, self.proc.stderr):
            if not s.closed:
                s.close()


def command(argv, until, home, cap=262144, seconds=10):
    """Bound both command time and captured bytes; never expose raw stderr."""
    check(until)
    stop = min(until, time.monotonic() + seconds)
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': str(home), 'LANG': 'C'}
    identity = {}
    p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env, start_new_session=True, close_fds=True, **identity)
    sel = selectors.DefaultSelector()
    data = bytearray()
    stderr_bytes = 0
    try:
        for stream, n in ((p.stdout, 1), (p.stderr, 2)):
            os.set_blocking(stream.fileno(), False)
            sel.register(stream, selectors.EVENT_READ, n)
        while sel.get_map():
            check(stop)
            for key, _ in sel.select(min(0.05, max(0, stop - time.monotonic()))):
                try:
                    b = os.read(key.fd, 16384)
                except BlockingIOError:
                    continue
                if not b:
                    sel.unregister(key.fileobj)
                    key.fileobj.close()
                elif key.data == 1:
                    data.extend(b)
                    need(len(data) <= cap, 'COMMAND_OUTPUT_BOUND')
                else:
                    stderr_bytes += len(b)
                    need(stderr_bytes <= cap, 'COMMAND_STDERR_BOUND')
        rc = p.wait(timeout=max(0.01, stop - time.monotonic()))
        return rc, bytes(data), stderr_bytes
    finally:
        if p.poll() is None:
            p.kill()  # Exact unreaped child, never a process name/group search.
        try:
            p.wait(timeout=2)
        finally:
            sel.close()
            for stream in (p.stdout, p.stderr):
                if not stream.closed:
                    stream.close()


def unit_properties(name, until, home):
    need(re.fullmatch(r'[A-Za-z0-9_.@:-]{1,240}\.(service|scope)', name), 'EXACT_UNIT_NAME_REQUIRED')
    fields = ('Id', 'LoadState', 'ActiveState', 'SubState', 'InvocationID', 'MainPID',
              'ControlGroup', 'Result', 'ExecMainCode', 'ExecMainStatus', 'CPUQuotaPerSecUSec',
              'CPUQuotaPeriodUSec', 'MemoryMax', 'MemorySwapMax', 'TasksMax', 'User', 'Group',
              'NoNewPrivileges', 'CapabilityBoundingSet', 'Delegate', 'BindsTo', 'After')
    rc, raw, _ = command(['/usr/bin/systemctl', 'show', '--no-pager'] +
                         ['--property=' + x for x in fields] + ['--', name], until, home, 32768)
    result = dict(line.split('=', 1) for line in raw.decode('ascii').splitlines() if '=' in line)
    need(rc == 0 or result.get('LoadState') == 'not-found', 'UNIT_OBSERVATION_UNAVAILABLE')
    need(set(result) <= set(fields), 'UNIT_PROPERTIES_INVALID')
    return result


def owned_unit(row, until, home):
    observation = row.get('unit')
    if observation is None:
        need(not any(x['kind'] == 'service' and x['state'] == 'OBSERVED' for x in row['creates']),
             'OBSERVED_SERVICE_WITHOUT_UNIT')
        return None
    identity = observation['unit']
    need(INVOCATION.fullmatch(identity['invocation_id']) and ID.fullmatch(identity['generation'])
         and identity['boot_id'] == boot_identity(), 'UNIT_DURABLE_IDENTITY')
    fingerprint = 'sha256:' + hashlib.sha256(json.dumps(RESOURCES, separators=(',', ':')).encode('ascii')).hexdigest()
    need(identity['resource_fingerprint'] == fingerprint, 'UNIT_RESOURCE_FINGERPRINT_MISMATCH')
    creates = [x for x in row['creates'] if x['kind'] == 'service']
    need(len(creates) == 1 and creates[0]['state'] == 'OBSERVED' and
         creates[0]['object_id'] == identity['generation'] + ':' + identity['invocation_id'],
         'UNIT_SUBMISSION_BINDING')
    actual = unit_properties(identity['name'], until, home)
    if actual.get('LoadState') == 'not-found':
        return {'identity': identity, 'properties': actual, 'live': False, 'missing': True,
                'exit': observation.get('exit')}
    need(actual.get('Id') == identity['name'] and
         actual.get('InvocationID') == identity['invocation_id'] and
         actual.get('ControlGroup') == identity['cgroup_path'], 'UNIT_GENERATION_CHANGED')
    live = actual.get('ActiveState') in ('active', 'activating')
    if live:
        need(int(actual['MainPID']) == identity['main_pid'] and
             proc_start(identity['main_pid']) == identity['start_time'], 'UNIT_MAINPID_CHANGED')
        status, _ = bounded_read(Path('/proc') / str(identity['main_pid']) / 'status', 32768, pseudo=True)
        credentials = dict(line.split(':', 1) for line in status.decode('ascii').splitlines() if ':' in line)
        need(credentials['Uid'].split() == [str(MANIFEST['identities']['sandbox']['uid'])] * 4 and
             credentials['Gid'].split() == [str(MANIFEST['identities']['sandbox']['gid'])] * 4 and
             set(credentials['Groups'].split()) <= {str(MANIFEST['identities']['sandbox']['gid'])} and
             int(credentials['CapEff'].strip(), 16) == 0 and credentials['NoNewPrivs'].strip() == '1',
             'STAGE_NATIVE_CREDENTIAL_MISMATCH')
        need(actual.get('NoNewPrivileges') == 'yes' and actual.get('Delegate') == 'no' and
             actual.get('CapabilityBoundingSet', '') == '', 'UNIT_SECURITY_PROPERTIES')
        namespace = os.stat('/proc/' + str(identity['main_pid']) + '/ns/net')
        network = row.get('network') or {}
        need((namespace.st_dev, namespace.st_ino) == (network.get('netns_dev'), network.get('netns_ino')),
             'UNIT_NETWORK_NAMESPACE_MISMATCH')
    return {'identity': identity, 'properties': actual, 'live': live, 'missing': False,
            'exit': observation.get('exit')}


def native_unit_inventory(names, until, home):
    rc, raw, _ = command(['/usr/bin/systemctl', 'list-units', '--all', '--no-pager',
                          '--no-legend', '--plain', '--full'], until, home, cap=1 << 20, seconds=2)
    need(rc == 0, 'NATIVE_UNIT_INVENTORY_UNAVAILABLE')
    lines = raw.decode('utf-8').splitlines()
    need(len(lines) <= 8192, 'NATIVE_UNIT_INVENTORY_BOUND')
    matched = []
    for line in lines:
        fields = line.split(None, 4)
        need(len(fields) >= 4, 'NATIVE_UNIT_INVENTORY_FORMAT')
        if fields[0] in names:
            matched.append({'name': fields[0], 'load': fields[1], 'active': fields[2], 'sub': fields[3]})
    return {'observed_monotonic': time.monotonic(), 'unit_count': len(lines), 'matching_units': matched}


def native_job_inventory(names, recorded_job_id, until, home):
    rc, raw, _ = command(['/usr/bin/systemctl', 'list-jobs', '--no-pager', '--no-legend',
                          '--plain', '--full'], until, home, cap=512 << 10, seconds=2)
    need(rc == 0, 'NATIVE_JOB_INVENTORY_UNAVAILABLE')
    lines = raw.decode('utf-8').splitlines()
    need(len(lines) <= 4096, 'NATIVE_JOB_INVENTORY_BOUND')
    matched = []
    for line in lines:
        fields = line.split()
        need(len(fields) == 4 and fields[0].isascii() and fields[0].isdigit() and
             0 < int(fields[0]) <= 2**32 - 1, 'NATIVE_JOB_INVENTORY_FORMAT')
        identity = int(fields[0])
        if fields[1] in names or identity == recorded_job_id:
            matched.append({'id': identity, 'unit': fields[1], 'type': fields[2], 'state': fields[3]})
    return {'observed_monotonic': time.monotonic(), 'job_count': len(lines), 'matching_jobs': matched}


def observe_native_absence(row, worker, manager, until, home, evidence):
    """Bounded bookends, not an inference from an inactive unit or saved exit."""
    terminal = unit_exit_evidence(row)
    need(terminal['complete'], 'HISTORICAL_UNIT_EXIT_MISSING')
    identities = [row['unit']['unit'], worker, manager]
    need(all(isinstance(unit, dict) and unit.get('name') and
             INVOCATION.fullmatch(unit.get('invocation_id', '')) and unit.get('boot_id') == boot_identity()
             for unit in identities), 'NATIVE_ABSENCE_OWNERSHIP_BINDING')
    names = {unit['name'] for unit in identities}
    need(len(names) == len(identities), 'NATIVE_ABSENCE_AMBIGUOUS_UNITS')
    job_path = row['unit'].get('job_path', '')
    recorded_job_id = None
    if job_path not in ('', '/'):
        match = re.fullmatch(r'/org/freedesktop/systemd1/job/([1-9][0-9]{0,9})', job_path)
        need(match and int(match[1]) <= 2**32 - 1, 'RECORDED_JOB_IDENTITY_INVALID')
        recorded_job_id = int(match[1])
    stop = min(until, time.monotonic() + 10)
    boot = boot_identity()
    evidence.update(status='WAITING', deadline_monotonic=stop, max_attempts=16,
                    identities=identities, recorded_job_path=job_path, historical_exit=terminal)
    for attempt in range(16):
        check(stop)
        evidence['attempts'] = attempt + 1
        before = {name: unit_properties(name, stop, home) for name in sorted(names)}
        evidence['last_snapshot'] = {'properties_before': before}
        if all(value.get('Id') == name and value.get('LoadState') == 'not-found' for name, value in before.items()):
            jobs_before = native_job_inventory(names, recorded_job_id, stop, home)
            units_before = native_unit_inventory(names, stop, home)
            after = {name: unit_properties(name, stop, home) for name in sorted(names)}
            units_after = native_unit_inventory(names, stop, home)
            jobs_after = native_job_inventory(names, recorded_job_id, stop, home)
            evidence['last_snapshot'].update(properties_after=after, units_before=units_before,
                                             units_after=units_after, jobs_before=jobs_before, jobs_after=jobs_after)
            need(boot_identity() == boot, 'NATIVE_ABSENCE_BOOT_CHANGED')
            if (all(value.get('Id') == name and value.get('LoadState') == 'not-found' for name, value in after.items())
                    and not units_before['matching_units'] and not units_after['matching_units']
                    and not jobs_before['matching_jobs'] and not jobs_after['matching_jobs']):
                evidence.update(status='OBSERVED', boot_id=boot, complete=True,
                                observed_monotonic=time.monotonic())
                return
        time.sleep(min(.1, max(0, stop - time.monotonic())))
    evidence.update(status='UNPROVEN', complete=False)
    raise Fault('NATIVE_UNIT_OR_JOB_ABSENCE_UNPROVEN')


def unit_exit_evidence(row):
    observation = row.get('unit') or {}
    result = observation.get('exit')
    if result is None:
        return {'complete': False}
    return {'complete': True, 'identity': observation['unit'], 'exit': result,
            'exec_main_code': observation['exec_main_code'],
            'exec_main_status': observation['exec_main_status'], 'result': observation['result']}


def proc_start(pid):
    raw, _ = bounded_read(Path('/proc') / str(pid) / 'stat', 16384, pseudo=True)
    return int(raw.rsplit(b')', 1)[1].split()[19])


def runtime_identity(pid):
    raw, _ = bounded_read(Path('/proc') / str(pid) / 'status', 32768, pseudo=True)
    fields = {}
    for line in raw.decode('ascii').splitlines():
        key, _, value = line.partition(':')
        if key in ('Uid', 'Gid', 'Groups', 'NSpid', 'Threads', 'CapEff', 'NoNewPrivs'):
            fields[key] = value.split()
    need(fields.get('Uid') == [str(UID)] * 4 and fields.get('Gid') == [str(GID)] * 4
         and set(fields.get('Groups', [])) <= {str(GID)}, 'RUNTIME_CREDENTIAL_MISMATCH')
    return fields


def boot_identity():
    raw, _ = bounded_read(Path('/proc/sys/kernel/random/boot_id'), 128, pseudo=True)
    value = raw.decode('ascii').strip()
    need(str(uuid.UUID(value)) == value, 'BOOT_IDENTITY_FORMAT')
    return value


def pidfd_identity(text):
    """Only process/namespace identity, not descriptor-local flags or offsets."""
    need(isinstance(text, str) and len(text) <= 16384, 'PIDFD_IDENTITY_BOUND')
    fields = {}
    for line in text.splitlines():
        key, separator, value = line.partition(':')
        if key not in ('Pid', 'NSpid'):
            continue
        need(separator and key not in fields, 'PIDFD_IDENTITY_FORMAT')
        values = value.split()
        need(1 <= len(values) <= 16 and all(re.fullmatch(r'-?[0-9]+', x) for x in values),
             'PIDFD_IDENTITY_FORMAT')
        fields[key] = [int(x) for x in values]
    need(len(fields.get('Pid', [])) == 1, 'PIDFD_PROCESS_IDENTITY_MISSING')
    return fields


def held_pidfd_identity(fd):
    # Numeric /proc path avoids following the /proc/self symlink.
    raw, _ = bounded_read(Path('/proc') / str(os.getpid()) / 'fdinfo' / str(fd),
                          16384, pseudo=True)
    return pidfd_identity(raw.decode('ascii'))

class Cgroup:
    NAMES = ('cpu.max', 'cpu.stat', 'memory.max', 'memory.current', 'memory.peak',
             'memory.swap.max', 'memory.events', 'memory.events.local',
             'pids.max', 'pids.current', 'pids.peak', 'pids.events', 'cgroup.events')

    def __init__(self, info):
        pid = info['identity']['main_pid']
        need(type(pid) is int and pid > 1 and info['live'], 'NO_LIVE_CGROUP_PID')
        start = proc_start(pid)
        raw, _ = bounded_read(Path('/proc') / str(pid) / 'cgroup', 16384, pseudo=True)
        lines = [line[3:] for line in raw.decode('ascii').splitlines() if line.startswith('0::/')]
        need(len(lines) == 1 and '..' not in lines[0] and lines[0] != '/', 'CGROUP_MEMBERSHIP')
        self.path = Path('/sys/fs/cgroup') / lines[0].lstrip('/')
        self.fd = open_no_links(self.path, os.O_RDONLY | os.O_DIRECTORY)
        self.files = {}
        self.unsupported = {}
        self.process_pidfd = None
        directory = os.fstat(self.fd)
        self.identity = {'path': str(self.path), 'device': directory.st_dev, 'inode': directory.st_ino,
                         'unit': info['identity'], 'main_pid': pid, 'proc_start_ticks': start}
        need(lines[0] == info['identity']['cgroup_path'], 'CGROUP_UNIT_IDENTITY_MISMATCH')
        try:
            self.process_pidfd = os.pidfd_open(pid)
            self.identity['process_pidfd_identity'] = held_pidfd_identity(self.process_pidfd)
            need(self.identity['process_pidfd_identity']['Pid'] == [pid], 'CGROUP_PROCESS_PIDFD_IDENTITY_CHANGED')
            for name in self.NAMES:
                try:
                    self.files[name] = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.fd)
                except OSError as exc:
                    self.unsupported[name] = exc.errno
            need(proc_start(pid) == start, 'CGROUP_PID_IDENTITY_CHANGED')
            self.identity['pinned_files'] = sorted(self.files)
            first = self.read()
            need(first.get('memory.max') == RESOURCES['memory_bytes'] and first.get('memory.swap.max') == 0
                 and first.get('pids.max') == RESOURCES['pids'], 'CGROUP_EFFECTIVE_LIMIT_MISMATCH')
            cpu = str(first.get('cpu.max', '')).split()
            need(len(cpu) == 2 and int(cpu[0]) * 1000000000 // int(cpu[1]) == RESOURCES['nano_cpus'],
                 'CGROUP_CPU_LIMIT_MISMATCH')
            self.baseline = first
        except BaseException:
            self.close()
            raise

    def read(self):
        out = {'observed_monotonic': time.monotonic(), 'unavailable': dict(self.unsupported)}
        for name, fd in self.files.items():
            try:
                raw = os.pread(fd, 8193, 0)
                need(len(raw) <= 8192, 'CGROUP_READ_BOUND')
                text = raw.decode('ascii').strip()
                if name.endswith(('.stat', '.events', '.events.local')):
                    out[name] = {k: int(v) for k, v in (line.split() for line in text.splitlines())}
                elif text.isdigit():
                    out[name] = int(text)
                else:
                    out[name] = text
            except (OSError, ValueError) as exc:
                out['unavailable'][name] = getattr(exc, 'errno', None)
        if self.files and all(out['unavailable'].get(name) == errno.ENODEV and name not in out
                              for name in self.files):
            out['retirement'] = self.retirement_observation()
        return out

    def retirement_observation(self):
        proof = {'status': 'UNPROVEN', 'identity': copy.deepcopy(self.identity),
                 'pinned_files': sorted(self.files), 'all_pinned_files_enodev': True}
        try:
            directory = os.fstat(self.fd)
            proof['held_directory'] = {'device': directory.st_dev, 'inode': directory.st_ino,
                                       'nlink': directory.st_nlink}
            need(directory.st_dev == self.identity['device'] and directory.st_ino == self.identity['inode'],
                 'CGROUP_PINNED_DIRECTORY_IDENTITY_CHANGED')
            try:
                os.lstat(self.path)
                proof['path_absent'] = False
            except FileNotFoundError:
                proof['path_absent'] = True
            with selectors.DefaultSelector() as selector:
                selector.register(self.process_pidfd, selectors.EVENT_READ)
                proof['process_pidfd_exited'] = bool(selector.select(0))
            if proof['path_absent'] and proof['process_pidfd_exited']:
                proof['status'] = 'OBSERVED'
        except (OSError, Fault) as exc:
            proof['error'] = safe_errno(exc)
        proof['observed_monotonic'] = time.monotonic()
        return proof

    def close(self):
        for fd in self.files.values():
            os.close(fd)
        self.files.clear()
        if self.process_pidfd is not None:
            os.close(self.process_pidfd)
            self.process_pidfd = None
        os.close(self.fd)


def sentinel(path):
    try:
        raw, st = bounded_read(path / 'probe-state', 128)
        return {'exists': True, 'device': st.st_dev, 'inode': st.st_ino,
                'uid': st.st_uid, 'gid': st.st_gid, 'size': st.st_size,
                'sha256': hashlib.sha256(raw).hexdigest(),
                'valid': raw == b'flexmodule-sandbox-probe-v2\n'}
    except FileNotFoundError:
        return {'exists': False}


def fixture_records(path, names, until, archive=None):
    records, reports = [], []
    for name in sorted(names):
        check(until)
        if not REPORT_NAME.fullmatch(name):
            continue
        raw, st = bounded_read(path / name, REPORT_LIMIT)
        need(st.st_uid == MANIFEST['identities']['sandbox']['uid'] and
             st.st_gid == MANIFEST['identities']['sandbox']['gid'] and st.st_nlink == 1
             and st.st_mode & 0o077 == 0, 'FIXTURE_REPORT_NATIVE_IDENTITY')
        if archive is not None:
            fd = open_no_links(archive / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(raw)
        malformed = 0
        for line in raw.splitlines()[:128]:
            if len(line) >= 4096:
                malformed += 1
                continue
            try:
                v = json.loads(line)
                need(isinstance(v, dict) and 1 <= v['sequence'] <= 128
                     and isinstance(v['probe'], str) and len(v['probe']) <= 64
                     and isinstance(v['state'], str) and len(v['state']) <= 128
                     and v['outcome'] in {'syscall-or-operation-returned', 'syscall-error',
                         'cancelled', 'deadline', 'operation-error'}, 'FIXTURE_RECORD_FORMAT')
                records.append(v)
            except (ValueError, KeyError, TypeError, Fault):
                malformed += 1
        reports.append({'name': name, 'inode': st.st_ino, 'bytes': len(raw),
                        'sha256': hashlib.sha256(raw).hexdigest(), 'malformed_lines': malformed,
                        'ends_in_newline': not raw or raw.endswith(b'\n')})
    need(len(reports) <= 1, 'MULTIPLE_NEW_FIXTURE_REPORTS')
    return records, reports


def log_snapshot(path, until):
    try:
        names = scan_names(path, until, 16)
    except FileNotFoundError:
        return {'exists': False}
    entries = []
    for name in sorted(names):
        check(until)
        try:
            st = os.lstat(path / name)
        except FileNotFoundError:
            continue  # Rotation may unlink an old name during this read-only sample.
        need(stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode), 'LOG_ENTRY_TYPE')
        entries.append({'name': name, 'bytes': st.st_size, 'inode': st.st_ino})
    output = [x for x in entries if re.fullmatch(r'output\.[0-9]+', x['name'])]
    need(len(output) <= LIMITS['log_retained_files'] and all(x['bytes'] <= LIMITS['log_file_max_bytes'] for x in output), 'LOG_RETENTION_BOUND_EXCEEDED')
    return {'exists': True, 'files': entries, 'total_bytes': sum(x['bytes'] for x in entries),
            'retained_output_files': len(output), 'retained_output_bytes': sum(x['bytes'] for x in output)}




def cpu_limit_continuity(samples, required, identity=None):
    approved = RESOURCES['nano_cpus'] // 1000000
    checked = unpopulated = unavailable = drifted = retired = 0
    missing, violations = [], []
    for index, sample in enumerate(samples):
        evidence = {'sample_index': index, 'observed_monotonic': sample.get('observed_monotonic'),
                    'cpu.max': sample.get('cpu.max')}
        proof = sample.get('retirement', {})
        pinned = proof.get('pinned_files', [])
        directory = proof.get('held_directory', {})
        valid_retirement = (
            identity is not None and proof.get('status') == 'OBSERVED' and proof.get('identity') == identity
            and proof.get('all_pinned_files_enodev') is True and proof.get('path_absent') is True
            and proof.get('process_pidfd_exited') is True
            and directory.get('device') == identity.get('device') and directory.get('inode') == identity.get('inode')
            and identity.get('process_pidfd_identity', {}).get('Pid') == [identity.get('main_pid')]
            and INVOCATION.fullmatch(identity.get('unit', {}).get('invocation_id', ''))
            and isinstance(pinned, list) and len(pinned) == len(set(pinned))
            and pinned == identity.get('pinned_files')
            and {'cpu.max', 'cgroup.events', 'pids.current'} <= set(pinned) <= set(Cgroup.NAMES)
            and all(sample.get('unavailable', {}).get(name) == errno.ENODEV and name not in sample for name in pinned))
        if valid_retirement:
            retired += 1
            continue
        events = sample.get('cgroup.events', {})
        populated = events.get('populated') if isinstance(events, dict) else None
        tasks = sample.get('pids.current')
        live = populated == 1 or (type(tasks) is int and tasks > 0)
        empty = populated == 0 and type(tasks) is int and tasks == 0
        fields = str(sample.get('cpu.max', '')).split()
        valid = (len(fields) == 2 and fields[1].isdigit() and int(fields[1]) > 0
                 and (fields[0] == 'max' or (fields[0].isdigit() and int(fields[0]) > 0))
                 and 'cpu.max' not in sample.get('unavailable', {}))
        if not valid or not (live or empty):
            unavailable += 1
            if len(missing) < 8:
                missing.append(dict(evidence, reason='cpu.max_unreadable_or_malformed' if not valid else 'population_unproven'))
            continue
        if retired:
            unavailable += 1
            if len(missing) < 8:
                missing.append(dict(evidence, reason='readable_sample_after_verified_retirement'))
        if not live:
            unpopulated += 1
            continue
        checked += 1
        # Exact integer ratio comparison: no rounded-down effective CPU cap.
        if fields[0] == 'max' or int(fields[0]) * 1000 > approved * int(fields[1]):
            drifted += 1
            if len(violations) < 8:
                violations.append(evidence)
    status = ('FAIL' if drifted else 'INCONCLUSIVE' if unavailable or (required and not checked)
              else 'OBSERVED' if checked else 'NOT_APPLICABLE')
    return {'status': status, 'code': 'CPU_LIMIT_DRIFT' if drifted else
            ('CPU_LIMIT_CONTINUITY_UNPROVEN' if status == 'INCONCLUSIVE' else 'BOUNDED_CAPTURED_SAMPLES_ONLY'),
            'approved_cpu_millicores': approved, 'checked_populated_samples': checked,
            'unpopulated_samples_not_checked': unpopulated, 'retired_samples_not_measured': retired,
            'unavailable_samples': unavailable,
            'drifted_samples': drifted, 'unavailable_examples': missing, 'drift_examples': violations}


def assessment(case, result, records):
    """Facts are deliberately not an automatic policy verdict."""
    out = []
    def add(name, status, **facts):
        out.append({'measurement': name, 'status': status, **facts})
    quota_samples = result.get('quota_samples', [])
    unavailable = [q[k] for q in quota_samples for k in ('persistent', 'scratch', 'native_app')
                   if q[k]['status'] != 'MEASURED']
    add('read_only_project_accounting', 'UNSUPPORTED' if unavailable else ('OBSERVED' if quota_samples else 'INCONCLUSIVE'),
        unavailable=unavailable[:2], sample_count=len(quota_samples))
    samples = result.get('cgroup_samples', [])
    continuity = cpu_limit_continuity(samples, result.get('running_seen', False), result.get('cgroup_identity'))
    result['cpu_limit_continuity'] = continuity
    out.append(dict(continuity, measurement='observed_cgroup_cpu_limit_continuity'))
    first = samples[0] if samples else {}
    def delta(file, key):
        base = first.get(file, {}).get(key)
        values = [s.get(file, {}).get(key) for s in samples]
        values = [v for v in values if type(v) is int]
        return max(values) - base if type(base) is int and values else None
    states = {(r['probe'], r['state']) for r in records}
    triggered = any(state == 'triggered' for _, state in states)
    add('approved_start_gate', 'OBSERVED' if triggered else ('NOT_APPLICABLE' if result.get('scenario') is None or case == 'runtime-sigkill' else 'INCONCLUSIVE'),
        triggered_record=triggered, source='authenticated_installation_config')
    if case == 'cpu':
        usage, throttles, throttled = delta('cpu.stat', 'usage_usec'), delta('cpu.stat', 'nr_throttled'), delta('cpu.stat', 'throttled_usec')
        elapsed = (samples[-1]['observed_monotonic'] - first['observed_monotonic']) if samples else None
        add('real_cgroup_cpu_accounting', 'OBSERVED' if triggered and usage and throttles and throttled else 'INCONCLUSIVE',
            usage_usec_delta=usage, nr_throttled_delta=throttles, throttled_usec_delta=throttled,
            sampled_seconds=elapsed, average_cpu_cores=(usage / 1000000 / elapsed if usage is not None and elapsed and elapsed > 0 else None))
    elif case == 'memory-oom':
        oom, killed = delta('memory.events', 'oom'), delta('memory.events', 'oom_kill')
        terminal = (result.get('unit_exit') or {}).get('exit') or {}
        add('real_cgroup_memory_events', 'OBSERVED' if triggered and (killed or 0) > 0 and
            terminal.get('oom_killed') is True else 'INCONCLUSIVE',
            oom_delta=oom, oom_kill_delta=killed, max_delta=delta('memory.events', 'max'), unit_exit=terminal)
    elif case in ('fork', 'thread'):
        failures = [r for r in records if r.get('errno') in (errno.EAGAIN, errno.ENOMEM)]
        diagnostic = result.get('thread_diagnostic', {})
        fatal_exhaustion = (diagnostic.get('fatal_newosproc') is True
                            and diagnostic.get('errno') in (errno.EAGAIN, errno.ENOMEM))
        stress = [r.get('data', {}) for r in records if r['state'] in ('spawn-returned', 'locked-so-far', 'lock-returned')]
        exercised = any(x.get('children_started', x.get('locked_threads', 0)) > 0 for x in stress)
        host_samples = [s for s in samples if s.get('pids.max') == RESOURCES['pids'] and
                        type(s.get('pids.current')) is int and 0 < s['pids.current'] <= RESOURCES['pids']]
        add('native_task_ceiling_under_guest_stress', 'OBSERVED' if triggered and host_samples and
            (exercised or failures or fatal_exhaustion or (delta('pids.events', 'max') or 0) > 0) else 'INCONCLUSIVE',
            pids_max_events_delta=delta('pids.events', 'max'), guest_failure_records=failures,
            peak_native_tasks=max([s.get('pids.current', 0) for s in host_samples] or [0]),
            stress_operations=stress, thread_diagnostic=diagnostic,
            warning='Native task ceiling is not a virtual guest PID/thread-count guarantee')
    elif case == 'identity':
        obs = [r['data'] for r in records if r['state'] == 'child-syscall-observation']
        add('uid_rlimit_namespace_syscalls', 'OBSERVED' if len(obs) == 9 else 'INCONCLUSIVE', observations=obs,
            warning='Interpret each syscall separately; an already-infinite limit is unsupported, not denied')
    elif (result.get('scenario') or {}).get('kind') == 'quota':
        errors = [r for r in records if r.get('errno') in (errno.EDQUOT, errno.ENOSPC)]
        links = [r for r in records if r['state'] == 'hardlink-syscall-returned']
        add('quota_boundary_or_links', 'OBSERVED' if (len(links) == 6 if case == 'cross-project-link' else bool(errors)) else 'INCONCLUSIVE',
            boundary_records=errors, link_records=links, project_high_water=result.get('quota_high_water'),
            warning='ENOSPC alone is not proof of project enforcement; correlate exact project usage and hard limits. Persistent EDQUOT can suppress post-write NDJSON until reclamation.')
    elif case == 'flood':
        streams = [r['data'] for r in records if r['state'] == 'stream-write-returned']
        snapshots = result.get('log_snapshots', [])
        direct = len(streams) == 2 and all(s.get('transport') == 'process-fds' for s in streams)
        rotated = any(s.get('retained_output_files', 0) > 1 and
                      any(f['bytes'] == LIMITS['log_file_max_bytes'] for f in s.get('files', []) if re.fullmatch(r'output\.[0-9]+', f['name']))
                      for s in snapshots)
        add('bounded_stdout_stderr_flood', 'OBSERVED' if direct and rotated else 'INCONCLUSIVE', streams=streams,
            direct_process_descriptors=direct, rotation_exercised=rotated,
            log_snapshots=snapshots, warning='Require actual process-fd flood and rotation, not broker stream copies')
    elif case.endswith('-failure'):
        stage = case.removesuffix('-failure')
        add('deliberate_lifecycle_failure', 'OBSERVED' if (stage, 'deliberate-failure') in states and not result.get('running_seen') else 'INCONCLUSIVE',
            stage=stage, running_seen=result.get('running_seen'), warning='Instance failure does not require runtime-wide exit')
    elif case == 'startup-budget':
        add('cumulative_startup_budget', 'OBSERVED' if ('init', 'delay-completed') in states and ('start', 'delay-started') in states
            and ('start', 'delay-completed') not in states and not result.get('running_seen') else 'INCONCLUSIVE',
            configured_phase_delay_ms=30500, unchanged_startup_seconds=30,
            launch_to_final_seconds=result.get('elapsed_seconds'),
            warning='Parent must correlate timestamps/cancellation; failure before START is inconclusive for the cumulative multi-phase claim')
    elif case == 'module-crash':
        terminal = result.get('unit_exit', {})
        exact_exit = terminal.get('complete') and terminal['exit']['kind'] == 'exit' and terminal['exit']['value'] == 86
        add('module_crash', 'OBSERVED' if ('crash', 'intentional-exit-86-next') in states and exact_exit else 'INCONCLUSIVE',
            expected_exit=86, exact_exit_observed=exact_exit, unit_exit=terminal,
            warning='Intent alone is not exact exit proof; missing durable unit result remains inconclusive')
    elif case == 'runtime-sigkill':
        worker = result.get('worker_terminal', {})
        add('exact_worker_sigkill_recovery', 'OBSERVED' if result.get('runtime_sigkill_sent') and
            worker.get('kind') == 'signal' and worker.get('value') == 9 and
            (result.get('final_epoch') or {}).get('state') == 'DEAD' and result.get('cleanup_complete') else 'INCONCLUSIVE',
            worker_terminal=worker, epoch_state=(result.get('final_epoch') or {}).get('state'))
    return out


class CaseRun:
    def __init__(self, name, base, output, configs, journal, quotas, until, artifact=None):
        self.name, self.base, self.output, self.configs = name, base, output, configs
        self.artifact = artifact or name
        self.journal, self.quotas, self.until = journal, quotas, until
        self.work_until = until - 70
        self.proc = self.pidfd = self.reader = self.cg = None
        self.network_before = None
        self.held_allocation = None
        self.control_before = None
        self.logfd = None
        self.log_start = None
        self.started_wall = self.started_mono = None
        self.boot_id = self.initial_pidfd_identity = None
        self.row = self.epoch = None
        self.previous_row = None
        self.persistent = None
        self.baseline_names = set()
        self.config_path = None
        self.worker = self.workerfd = None
        self.records = []
        self.result = {'case': name, 'status': 'INCONCLUSIVE', 'journal_transitions': [],
                       'unit_observations': [], 'cgroup_samples': [], 'quota_samples': [],
                       'quota_high_water': {}, 'log_snapshots': [], 'errors': []}

    def observe(self, until, sample=True):
        check(until)
        if self.reader:
            self.reader.pump(0)
        if self.worker is None:
            worker = self.journal.worker()
            if worker:
                actual = unit_properties(worker['name'], until, self.output)
                need(actual.get('InvocationID') == worker['invocation_id'] and
                     int(actual['MainPID']) == worker['main_pid'] and
                     actual['ControlGroup'] == worker['cgroup_path'], 'WORKER_UNIT_BINDING')
                self.workerfd = os.pidfd_open(worker['main_pid'])
                need(proc_start(worker['main_pid']) == worker['start_time'], 'WORKER_PID_RACE')
                self.initial_pidfd_identity = held_pidfd_identity(self.workerfd)
                self.worker = worker
                self.result['worker_identity'] = worker
                self.result['worker_native_credentials'] = runtime_identity(worker['main_pid'])
        if self.worker is None:
            return None
        epoch, row = self.journal.owned(self.worker['main_pid'], self.started_wall,
                                       self.epoch['id'] if self.epoch else None)
        if epoch:
            self.correlate_epoch(epoch)
            self.epoch = epoch
        if row:
            if self.proc.poll() is None and 'manager_unit' not in self.result:
                owners = self.journal.rows("SELECT value FROM metadata WHERE key='lease_owner'", maximum=1)
                need(len(owners) == 1, 'MANAGER_LEASE_OWNER_MISSING')
                owner = json.loads(owners[0]['value'])
                need(owner['main_pid'] == self.proc.pid and owner['start_time'] == self.result['runtime_proc_start_ticks'],
                     'MANAGER_UNIT_PIDFD_BINDING')
                observed = unit_properties(owner['name'], until, self.output)
                need(observed.get('InvocationID') == owner['invocation_id'] and
                     observed.get('ControlGroup') == owner['cgroup_path'], 'MANAGER_INVOCATION_CHANGED')
                self.result['manager_unit'] = owner
            self.row = row
            if self.previous_row != row:
                self.result['journal_transitions'].append({'observed_monotonic': time.monotonic(),
                    'host_phase': 'cleanup' if row['cleanup'] != 'PENDING' or row['state'] in ('STOPPING', 'CLEANUP_PENDING', 'STOPPED') else
                        ('running-correlated' if self.reader.running() and row['state'] == 'READY' else 'provisional'),
                    'row': copy.deepcopy(row)})
                self.previous_row = copy.deepcopy(row)
            if self.persistent is None:
                self.persistent = Path(row['lease']['persistent_path'])
                # Pre-launch installation snapshots exist for the real reused lab module.
                if not self.result.get('installation_before'):
                    self.baseline_names = set()
            if row['cleanup'] == 'PENDING' and sample:
                self.capture_fixture(until)
            if sample:
                self.sample_quota(row)
        if self.cg and sample:
            samples = self.result['cgroup_samples']
            if len(samples) < 3400:
                samples.append(self.cg.read())
        return row

    def capture_fixture(self, until):
        if self.persistent is None:
            return
        try:
            names = scan_names(self.persistent, until, 65540) - self.baseline_names
            records, reports = fixture_records(self.persistent, names, until)
            if reports:
                self.records = records
                self.result['fixture_reports'], self.result['fixture_records'] = reports, records
            observed = sentinel(self.persistent)
            if observed.get('exists'):
                need(observed.get('valid'), 'PERSISTENT_SENTINEL_CORRUPTED')
                self.result['sentinel_after'] = observed
        except FileNotFoundError:
            # Owner may have detached backing; retain the last real observation.
            return

    def sample_quota(self, row):
        if row['cleanup'] != 'PENDING' or not row.get('unit') or row['state'] not in ('CREATED', 'STARTING', 'READY'):
            return
        now = time.monotonic()
        previous = self.result['quota_samples']
        if previous and now - previous[-1]['observed_monotonic'] < 0.4:
            return
        values = {'observed_monotonic': now}
        for kind in ('persistent', 'scratch'):
            q = self.quotas.read(row['lease'][kind + '_project'])
            values[kind] = q
            high = self.result['quota_high_water'].setdefault(kind, {})
            for key in ('bytes', 'inodes'):
                if key in q:
                    high[key] = max(high.get(key, 0), q[key])
        app_claim = native_app_claim(self.journal)
        need(app_claim == CURRENT_FIXTURE['app_claim'] and
             app_claim['project'] not in (row['lease']['persistent_project'], row['lease']['scratch_project']),
             'RETAINED_NATIVE_APP_CLAIM_CHANGED_OR_ALIASED')
        values['native_app'] = self.quotas.read(app_claim['project'])
        app_quota = values['native_app']
        if app_quota['status'] == 'MEASURED':
            need(app_quota['hard_bytes'] == app_quota['soft_bytes'] == app_claim['bytes'] and
                 app_quota['hard_inodes'] == app_quota['soft_inodes'] == app_claim['inodes'] and
                 app_quota['bytes'] <= app_claim['bytes'] and 4 <= app_quota['inodes'] <= app_claim['inodes'] and
                 app_quota['realtime_bytes'] == 0,
                 'NATIVE_APP_PROJECT_BOUND_MISMATCH')
        if 'native_app_identity' not in self.result:
            self.result['native_app_identity'] = native_app_identity(self.journal, app_claim)
        if len(previous) < 800:
            previous.append(values)

    def correlate_epoch(self, epoch, require_live=False):
        need(epoch is not None and self.boot_id is not None and self.initial_pidfd_identity is not None,
             'EPOCH_PIDFD_PREREQUISITE_MISSING')
        need(epoch['boot_id'] == self.boot_id, 'EPOCH_BOOT_IDENTITY_MISMATCH')
        saved = json.loads(epoch['start_identity'])
        need(saved == self.worker and saved['main_pid'] == epoch['pid'] and
             saved['boot_id'] == self.boot_id, 'EPOCH_UNIT_GENERATION_BINDING')
        if require_live:
            need(epoch['state'] == 'LIVE' and self.proc.poll() is None
                 and self.pidfd is not None and boot_identity() == self.boot_id,
                 'EPOCH_NOT_LIVE_FOR_CONTROL')
            need(held_pidfd_identity(self.workerfd) == self.initial_pidfd_identity
                 and proc_start(self.worker['main_pid']) == self.worker['start_time'],
                 'HELD_PIDFD_PROCESS_IDENTITY_CHANGED')
        self.result.setdefault('epoch_pidfd_correlation', {
            'epoch_id': epoch['id'], 'boot_id': self.boot_id,
            'durable_worker_unit': saved,
            'held_pidfd_identity_at_launch': self.initial_pidfd_identity,
            'proc_start_ticks': self.worker['start_time']})
        if require_live:
            self.result['last_live_epoch_pidfd_check_monotonic'] = time.monotonic()

    def inspect(self, until):
        row = self.observe(until, False)
        if not row:
            return None
        info = owned_unit(row, until, self.output)
        if info:
            observations = self.result['unit_observations']
            if not observations or observations[-1] != info:
                observations.append(info)
        return info

    def pin_thread_log(self):
        # Hold the exact host-owned inode before the sole trigger. Cleanup may
        # unlink it immediately after Go's fatal output; no path reopening race.
        self.logfd = open_no_links(Path(self.row['lease']['log_path']) / 'output.0')
        st = os.fstat(self.logfd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
             and st.st_mode & 0o077 == 0 and st.st_size <= LIMITS['log_file_max_bytes'], 'THREAD_LOG_IDENTITY')
        self.log_start = st.st_size

    def thread_diagnostic(self):
        # Retain allowlisted fatal markers/numbers only, never raw stack dumps.
        st = os.fstat(self.logfd)
        raw = os.pread(self.logfd, 65536, self.log_start)
        match = re.search(rb'runtime: failed to create new OS thread \(have ([0-9]{1,6}) already; errno=([0-9]{1,3})\)', raw)
        out = {'device': st.st_dev, 'inode': st.st_ino, 'initial_bytes': self.log_start,
               'final_bytes': st.st_size, 'scanned_bytes': len(raw),
               'scan_truncated': st.st_size > self.log_start + len(raw),
               'fatal_newosproc': b'fatal error: newosproc' in raw}
        if match:
            out.update(guest_threads=int(match[1]), errno=int(match[2]))
        return out

    def signal_runtime(self, sig):
        need(self.proc is not None, 'RUNTIME_HANDLE_MISSING')
        if self.proc.poll() is None:
            if self.pidfd is not None:
                signal.pidfd_send_signal(self.pidfd, sig)
            else:
                # Popen still owns this unreaped child if pidfd_open itself failed.
                self.proc.send_signal(sig)
            self.result.setdefault('runtime_signals', []).append({'signal': sig, 'pid': self.proc.pid,
                                                                  'observed_monotonic': time.monotonic()})
            return True
        return False

    def run(self):
        r = self.result
        records = []
        try:
            self.control_before = controls_snapshot(self.until, self.output)
            need(not self.journal.active(), 'INSTALLATION_ALREADY_ACTIVE')
            installation = self.journal.installation()
            r['installation_before'] = installation
            if installation:
                self.persistent = STORAGE / 'persistent' / installation['storage_key']
                if self.persistent.exists():
                    self.baseline_names = scan_names(self.persistent, self.work_until, 65540)
                    r['sentinel_before'] = sentinel(self.persistent)
                    need(not r['sentinel_before']['exists'] or r['sentinel_before'].get('valid'), 'EXISTING_SENTINEL_INVALID')
            config = CURRENT_FIXTURE['config']
            scenario = config['modules'][0]['config'].get('scenario')
            r['scenario'], r['lifecycle'] = scenario, config['modules'][0]['config']['lifecycle']
            r['original_resource_profile'], r['original_limits'] = self.base['resource_profiles'], self.base['limits']
            self.config_path = Path(CURRENT_FIXTURE['path'])
            r['config_sha256'] = CURRENT_FIXTURE['config_sha256']
            check(self.work_until)
            need(not INTERRUPTED, 'INTERRUPTED_BEFORE_LAUNCH')
            self.started_wall, self.started_mono = time.time_ns(), time.monotonic()
            argv = [str(RUNTIME), 'start', '--foreground', '--installation-id', MANIFEST['runtime_installation_id'],
                    '--config', str(self.config_path),
                    '--duration', '8s' if self.name == 'normal-exit' else str(int(self.work_until - self.started_mono)) + 's']
            self.proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'HOME': '/nonexistent'},
                cwd='/', start_new_session=True, close_fds=True)
            self.reader = RuntimeOutput(self.proc)
            r['runtime_pid'] = self.proc.pid
            self.pidfd = os.pidfd_open(self.proc.pid)
            self.boot_id = boot_identity()
            r['runtime_boot_id'] = self.boot_id
            r['runtime_proc_start_ticks'] = proc_start(self.proc.pid)
            startup_until = min(self.work_until, self.started_mono + 65)
            while time.monotonic() < startup_until:
                self.reader.pump()
                row = self.observe(startup_until)
                if self.reader.running():
                    r['running_seen'] = True
                    break
                if self.proc.poll() is not None or (row and (row['reason'] or row['cleanup'] == 'COMPLETE')) or INTERRUPTED:
                    break
            r.setdefault('running_seen', False)
            if scenario is None:
                # Expected failed instance: do not wait for runtime-wide process exit.
                need(not r['running_seen'], 'UNEXPECTED_RUNNING_FOR_STARTUP_FAILURE')
                need(self.row is not None, 'NO_DURABLE_INSTANCE')
            else:
                need(r['running_seen'], 'NO_RUNTIME_RUNNING_OBSERVATION')
                info = self.inspect(self.work_until)
                need(info and info['live'] and self.row['state'] == 'READY'
                     and self.row['cleanup'] == 'PENDING', 'NO_OWNED_RUNNING_UNIT')
                r['root_confirmation'] = root_confirmation(self.row)
                r['transport_before'] = worker_transport(self.row, self.worker)
                self.cg = Cgroup(info)
                r['project_identity'] = project_identity(self.row)
                r['cgroup_identity'] = self.cg.identity
                r['cgroup_samples'].append(self.cg.baseline)
                r['sentinel_running'] = sentinel(self.persistent)
                if self.name in NETWORK_CASES:
                    r['network_controls'] = network_controls(self.name, self.work_until)
                    if is_public(self.name):
                        r['network_start_barrier'] = {}
                        self.network_before = network_start_barrier(
                            self.row, info, self.work_until, self.output, r['network_start_barrier'])
                    else:
                        self.network_before = firewall_snapshot(self.row, info, self.work_until, self.output)
                if self.name == 'runtime-sigkill':
                    self.correlate_epoch(self.epoch, require_live=True)
                    signal.pidfd_send_signal(self.workerfd, signal.SIGKILL)
                    r['runtime_sigkill_sent'] = True
                if self.name == 'thread':
                    self.pin_thread_log()
                triggered_at = time.monotonic()
                workload_until = min(self.work_until, triggered_at + scenario['timeout_seconds'] +
                                     scenario.get('trigger_delay_ms', 0) / 1000 + 12)
                if self.name == 'normal-exit':
                    workload_until = min(workload_until, self.started_mono + 9)
                next_journal = next_inspect = next_report = 0
                done_seen = None
                while time.monotonic() < workload_until and not INTERRUPTED:
                    self.reader.pump(0.05)
                    now = time.monotonic()
                    if self.cg and len(r['cgroup_samples']) < 3400:
                        r['cgroup_samples'].append(self.cg.read())
                    if now >= next_journal:
                        row = self.observe(workload_until)
                        next_journal = now + 0.25
                        if row and row['cleanup'] == 'COMPLETE':
                            break
                    if now >= next_report and self.persistent:
                        self.capture_fixture(workload_until)
                        records = self.records
                        if any(x['state'] == 'returned-not-policy-proof' for x in records):
                            done_seen = done_seen or now
                        next_report = now + 0.5
                        if self.name == 'ipc-race':
                            r['transport_after'] = worker_transport(self.row, self.worker)
                            need(r['transport_before'] == r['transport_after'], 'PINNED_NATIVE_TRANSPORT_CHANGED')
                        if self.name == 'cleanup-crash' and any(x['state'] == 'holding-owned-allocation' for x in records):
                            self.pin_cleanup_allocation(records)
                            break
                        if self.name == 'ipc-held-unlinked' and any(x['state'] == 'holding-owned-allocation' and x.get('data', {}).get('unlink_held') for x in records):
                            self.observe(workload_until)
                            claims = {x['kind']: x['state'] for x in self.row['claims']}
                            quota = self.quotas.read(self.row['lease']['scratch_project'])
                            r['held_ipc_accounting'] = {'claims': claims, 'quota': quota, 'instance': self.row['id']}
                            need('scratch' in claims and 'ipc' in claims and claims['scratch'] != 'RELEASED' and claims['ipc'] != 'RELEASED'
                                 and quota.get('status') == 'MEASURED' and quota.get('bytes', 0) >= 1 << 20,
                                 'UNLINKED_IPC_ALLOCATION_RELEASED_EARLY')
                            reused = self.journal.rows("SELECT instance FROM resource_claims WHERE kind='scratch' AND identity=? AND instance!=? AND state!='RELEASED'",
                                                       (str(self.row['lease']['scratch_project']), self.row['id']), maximum=1)
                            need(not reused, 'HELD_IPC_PROJECT_REUSED')
                            break
                    if now >= next_inspect and self.row and self.row.get('unit'):
                        self.inspect(workload_until)
                        if self.name == 'flood':
                            r['log_snapshots'].append(log_snapshot(Path(self.row['lease']['log_path']), workload_until))
                        next_inspect = now + 2
                    if done_seen and now - done_seen >= 0.6:
                        if self.name != 'normal-exit':
                            break
                    if self.proc.poll() is not None:
                        # Reaper/instance failure is enough, not a demand to keep runtime alive.
                        row = self.observe(workload_until)
                        if row and row['cleanup'] == 'COMPLETE':
                            break
                if self.name == 'flood':
                    # Sample after the completion record, before SIGTERM deletes
                    # the logs; a fast flood may finish between periodic samples.
                    r['log_snapshots'].append(log_snapshot(Path(self.row['lease']['log_path']), self.work_until))
            if self.logfd is not None:
                r['thread_diagnostic'] = self.thread_diagnostic()
                os.close(self.logfd)
                self.logfd = None
            if self.persistent and self.persistent.exists():
                records = self.archive_and_reclaim()
                self.records = records
            if self.name in NETWORK_CASES and self.network_before is not None:
                info = self.inspect(self.work_until)
                r['firewall_before'] = self.network_before
                try:
                    r['firewall_after'] = firewall_snapshot(self.row, info, self.work_until, self.output)
                    r['firewall_delta'] = firewall_delta(self.network_before, r['firewall_after'])
                except Fault as exc:
                    r['network_counter_error'] = safe_errno(exc)
            r['status'] = 'OBSERVED'
        except (Fault, OSError, ValueError, KeyError, TypeError, sqlite3.Error, subprocess.SubprocessError) as exc:
            r['errors'].append(safe_errno(exc))
            violations = {'UNIT_GENERATION_CHANGED', 'STAGE_NATIVE_CREDENTIAL_MISMATCH',
                          'CGROUP_EFFECTIVE_LIMIT_MISMATCH', 'CGROUP_CPU_LIMIT_MISMATCH',
                          'LOG_RETENTION_BOUND_EXCEEDED', 'PINNED_NATIVE_TRANSPORT_CHANGED',
                          'UNLINKED_IPC_ALLOCATION_RELEASED_EARLY', 'HELD_IPC_PROJECT_REUSED'}
            r['status'] = 'FAIL' if isinstance(exc, Fault) and exc.code in violations else 'INCONCLUSIVE'
        finally:
            try:
                self.finish()
            except (Fault, OSError, ValueError, KeyError, TypeError, sqlite3.Error, subprocess.SubprocessError) as exc:
                r['errors'].append(safe_errno(exc))
                r['status'] = 'FAIL'
            finally:
                # Always reap own runtime, even if evidence collection/cleanup observation failed.
                if self.proc is not None and self.proc.poll() is None:
                    try:
                        self.signal_runtime(signal.SIGKILL)
                        self.proc.wait(timeout=2)
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        r['errors'].append(safe_errno(exc))
                        r['status'] = 'FAIL'
                if self.reader:
                    self.reader.pump(0)
                    r['runtime_observations'] = self.reader.events
                    r['runtime_output_bytes'] = self.reader.bytes
                    r['discarded_nonallowlisted_lines'] = self.reader.discarded
                    self.reader.close()
                if self.proc:
                    r['runtime_returncode'] = self.proc.poll()
                try:
                    if self.logfd is not None and self.log_start is not None:
                        r['thread_diagnostic'] = self.thread_diagnostic()
                    if self.row:
                        r['unit_exit'] = unit_exit_evidence(self.row)
                except (Fault, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
                    r['errors'].append(safe_errno(exc))
                    if r['status'] == 'OBSERVED':
                        r['status'] = 'INCONCLUSIVE'
                finally:
                    if self.logfd is not None:
                        os.close(self.logfd)
                    if self.held_allocation is not None:
                        os.close(self.held_allocation)
                        self.held_allocation = None
                if self.pidfd is not None:
                    os.close(self.pidfd)
                if self.workerfd is not None:
                    os.close(self.workerfd)
                if self.cg:
                    self.cg.close()
            try:
                if self.control_before is not None:
                    after = controls_snapshot(self.until, self.output)
                    r['unrelated_controls_preserved'] = self.control_before == after
                    need(r['unrelated_controls_preserved'], 'UNRELATED_CONTROL_CHANGED')
            except (Fault, OSError, ValueError, KeyError, TypeError) as exc:
                r['errors'].append(safe_errno(exc))
                r['status'] = 'FAIL'
            if self.started_mono:
                r['elapsed_seconds'] = time.monotonic() - self.started_mono
            records = self.records or records
            r['assessments'] = assessment(self.name, r, records)
            if any(x['status'] in ('INCONCLUSIVE', 'UNSUPPORTED') for x in r['assessments']) and r['status'] == 'OBSERVED':
                r['status'] = 'INCONCLUSIVE'
            r['status'], r['verdict_reason'] = verdict(self.name, r, records)
            if isinstance(r.get('scenario'), dict) and 'network' in r['scenario']:
                r['scenario']['network'] = {'expected_egress': r['scenario']['network']['expected_egress'], 'details': 'trusted_operator_plan_not_copied_to_report'}
            private_json(self.output / (self.artifact + '.json'), r)
        return r


    def pin_cleanup_allocation(self, records):
        allocations = [x['data'] for x in records if x['probe'] == 'quota'
                       and x['state'] == 'allocation-returned-not-project-accounting'
                       and x.get('outcome') == 'syscall-or-operation-returned'
                       and x.get('data', {}).get('target') == 'ipc']
        need(len(allocations) == 1 and self.held_allocation is None, 'ONE_EXACT_OWNED_ALLOCATION_REQUIRED')
        guest = canonical(allocations[0]['owned_directory'])
        parts = guest.parts
        need(len(parts) == 4 and parts[:2] == ('/', 'tmp')
             and re.fullmatch(r'plugin-dir[0-9]+', parts[2]) and QUOTA_NAME.fullmatch(parts[3]) is not None,
             'OWNED_GUEST_TMP_ALLOCATION_PATH_INVALID')
        host = Path(self.row['lease']['scratch_path']).parent / 'tmp' / parts[2] / parts[3] / 'allocation'
        fd = open_no_links(host)
        try:
            st = os.fstat(fd)
            need(stat.S_ISREG(st.st_mode) and st.st_uid == MANIFEST['identities']['sandbox']['uid'] and st.st_gid == MANIFEST['identities']['sandbox']['gid']
                 and st.st_nlink == 1 and st.st_size == 1 << 20 and st.st_blocks * 512 >= 1 << 20,
                 'OWNED_HELD_ALLOCATION_IDENTITY')
            value = bytearray(28)
            fcntl.ioctl(fd, 0x801c581f, value, True)
            _, _, _, project, _, _ = struct.unpack('=IIIII8s', value)
            need(project == self.row['lease']['scratch_project']
                 and st.st_dev == self.result['project_identity']['ipc']['device'], 'OWNED_HELD_ALLOCATION_PROJECT')
            self.result['cleanup_allocation_held'] = {'device': st.st_dev, 'inode': st.st_ino,
                'project': project, 'allocated_bytes': st.st_blocks * 512, 'instance': self.row['id']}
            self.held_allocation = fd
        except BaseException:
            os.close(fd)
            raise

    def finish(self):
        if self.proc is None:
            return
        if self.proc.poll() is None and self.name not in ('runtime-sigkill', 'normal-exit'):
            self.signal_runtime(signal.SIGINT if self.name == 'sigint' else signal.SIGTERM)
        graceful = min(self.until - 30, time.monotonic() + 35)
        while self.proc.poll() is None and time.monotonic() < graceful:
            self.reader.pump(.05)
            row = self.observe(graceful)
            if row and self.cg:
                info = self.inspect(graceful)
                if info and not info['live'] and row['cleanup'] != 'COMPLETE':
                    quota = self.quotas.read(row['lease']['scratch_project'])
                    if quota.get('status') == 'MEASURED':
                        self.result['pre_reclaim_quota'] = quota
                    if self.name == 'cleanup-crash' and self.held_allocation is not None:
                        held = os.fstat(self.held_allocation)
                        claims = {x['kind']: x['state'] for x in row['claims']}
                        if unit_exit_evidence(row)['complete']:
                            need(quota.get('bytes', 0) >= 1 << 20 and
                                 all(claims.get(k) not in (None, 'RELEASED') for k in ('scratch', 'ipc')),
                                 'OPEN_ALLOCATION_RELEASED_EARLY')
                            self.result['cleanup_crash_witness'] = {'claims': claims, 'quota': quota,
                                'device': held.st_dev, 'inode': held.st_ino, 'links': held.st_nlink}
                            self.correlate_epoch(self.epoch, require_live=True)
                            signal.pidfd_send_signal(self.workerfd, signal.SIGKILL)
                            self.result['cleanup_crash_sigkill_sent'] = True
                            break
            if row and row['cleanup'] == 'COMPLETE' and self.cg:
                q = self.quotas.read(row['lease']['scratch_project'])
                if q.get('status') == 'MEASURED':
                    self.result['last_mounted_quotas'] = {'scratch': q}
        if self.proc.poll() is None:
            self.result['cleanup_runtime_sigkill_sent'] = self.signal_runtime(signal.SIGKILL)
        self.proc.wait(timeout=2)
        if self.logfd is not None:
            self.result['thread_diagnostic'] = self.thread_diagnostic()
            os.close(self.logfd)
            self.logfd = None
        if self.held_allocation is not None:
            os.close(self.held_allocation)
            self.held_allocation = None
        # Explicit Stop recovers the old epoch; never adopt pipes or raw-reclaim.
        rc, raw, _ = command([str(RUNTIME), 'stop', '--installation-id', MANIFEST['runtime_installation_id']],
                              self.until, self.output, cap=65536, seconds=60)
        report = json.loads(raw)
        self.result['owner_cleanup_report'] = report
        need(rc == 0 and report.get('complete') is True, 'SUPPORTED_STOP_RECOVERY_INCOMPLETE')
        self.observe(self.until, False)
        self.result['final_epoch'], self.result['final_instance'] = self.epoch, self.row
        need(self.row and self.row['cleanup'] == 'COMPLETE', 'DURABLE_CLEANUP_NOT_COMPLETE')
        info = owned_unit(self.row, self.until, self.output)
        need(info and unit_exit_evidence(self.row)['complete'], 'UNIT_TERMINAL_EVIDENCE_MISSING')
        need(self.row['unit']['cgroup_empty'] is True, 'DURABLE_CGROUP_EMPTY_MISSING')
        if self.cg:
            final = self.cg.read()
            self.result['cgroup_samples'].append(final)
            need((final.get('cgroup.events', {}).get('populated') == 0 and final.get('pids.current') == 0)
                 or final.get('retirement', {}).get('status') == 'OBSERVED', 'CGROUP_ABSENCE_UNPROVEN')
        self.result['native_unit_absence'] = {'status': 'UNPROVEN', 'complete': False}
        try:
            observe_native_absence(self.row, self.worker, self.result.get('manager_unit'), self.until,
                                   self.output, self.result['native_unit_absence'])
        except (Fault, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
            self.result['native_unit_absence'].update(status='UNPROVEN', complete=False, error=safe_errno(exc))
            raise
        owned_network_absent(self.row, self.network_before, self.until, self.output)
        lease = self.row['lease']
        paths = {'scratch_instance': str(Path(lease['scratch_path']).parent), 'ipc': lease['ipc_path'], 'logs': lease['log_path']}
        self.result['final_path_absence'] = {k: not os.path.lexists(v) for k, v in paths.items()}
        need(all(self.result['final_path_absence'].values()), 'EPHEMERAL_PATH_REMAINS')
        claims = self.row['claims']
        need({x['kind'] for x in claims} == {'persistent', 'scratch', 'ipc', 'service', 'network', 'logs'}, 'CLAIM_SET_INCOMPLETE')
        need(all(x['state'] == ('RETAINED' if x['kind'] == 'persistent' else 'RELEASED') for x in claims), 'CLAIM_RELEASE_INCOMPLETE')
        need(not any(x['state'] == 'SUBMITTED' for x in self.row['creates']), 'CREATE_UNCERTAINTY_DISCARDED')
        transfer = self.row.get('endpoint_transfer') or {}
        need(transfer.get('transports_closed') == 1, 'ENDPOINT_TRANSPORT_CLOSURE_UNPROVEN')
        self.result['cleanup_complete'] = True
        self.result['owned_unit_absent'] = self.result['native_unit_absence']['complete']
        self.result['owned_jobs_absent'] = self.result['native_unit_absence']['complete']
        self.result['final_quotas'] = self.result.get('last_mounted_quotas', {})
        self.result['durable_reclaim'] = {'authority': 'root_store_after_kernel_reclaim',
            'instance_cleanup': self.row['cleanup'], 'scratch_project': lease['scratch_project'],
            'claims': claims, 'independent_final_counters': bool(self.result['final_quotas'])}
        app_claim = native_app_claim(self.journal)
        need(app_claim == CURRENT_FIXTURE['app_claim'], 'NATIVE_APP_CLAIM_NOT_RETAINED')
        storage = self.journal.rows('SELECT id,kind,bytes,inodes,project,state FROM storage_claims WHERE id IN (?,?)',
                                    (lease['ownership']['installation_id'], self.row['id']), maximum=2)
        by_kind = {claim['kind']: claim for claim in storage}
        need(set(by_kind) == {'persistent', 'scratch'} and by_kind['persistent']['state'] == 'RESERVED' and
             by_kind['scratch']['state'] == 'RELEASED' and
             by_kind['persistent']['project'] == lease['persistent_project'] and
             by_kind['scratch']['project'] == lease['scratch_project'] and
             app_claim['project'] not in (lease['persistent_project'], lease['scratch_project']),
             'SCOPED_STORAGE_RETAIN_AND_RELEASE_UNPROVEN')
        self.result['native_app_retained'] = {'claim': app_claim, 'scope': 'persistent_data_subreservation',
            'independent_final_counters': False, 'mounted_identity': self.result.get('native_app_identity')}
        self.result['storage_claim_settlement'] = storage
        if self.worker:
            records = self.journal.rows("SELECT record FROM provisioning_ledger WHERE kind='unit' AND identity=?",
                                        (self.worker['name'],), maximum=1)
            if records:
                import base64
                properties = json.loads(base64.b64decode(json.loads(records[0]['record'])['observed']['attributes'], validate=True))
                self.result['worker_terminal'] = properties.get('exit')

    def archive_and_reclaim(self):
        # Archive before owner detaches backing. Never edit hostfs .gvx_meta or
        # unlink guest files from root; isolated fixtures retain data for purge.
        names = scan_names(self.persistent, self.until, 65540) - self.baseline_names
        archive = self.output / (self.artifact + '-fixture')
        os.mkdir(archive, 0o700)
        records, reports = fixture_records(self.persistent, names, self.until, archive)
        self.result['fixture_reports'], self.result['fixture_records'] = reports, records
        after = sentinel(self.persistent)
        before = self.result.get('sentinel_before', {})
        if before.get('exists'):
            need(after.get('valid') and all(before.get(k) == after.get(k) for k in ('device', 'inode', 'sha256')),
                 'PERSISTENT_SENTINEL_CHANGED')
        else:
            need(after.get('valid') or (self.name == 'init-failure' and not after['exists']), 'SENTINEL_NOT_CREATED')
        self.result['sentinel_after'] = after
        self.result['persistent_reclamation_status'] = 'PRESERVED_FOR_APPROVED_PURGE'
        return records

def owned_network_absent(row, before, until, home):
    record = row.get('network')
    need(record and record['state'] == 'CLEANED', 'DURABLE_NETWORK_CLEANUP_MISSING')
    need(not os.path.lexists(record['netns_path']), 'OWNED_NETNS_REMAINS')
    links = inspect_ip([], ['link', 'show'], until, home, maximum=4096)
    need(not any(x.get('ifname') in {record['host_interface'], record['peer_interface']} for x in links
                 if record['host_interface']), 'OWNED_VETH_REMAINS')
    if record['profile'] != 'NONE':
        chains = network_chains(record)
        for family in (4, 6):
            for table in ('filter', 'nat'):
                rc, raw, _ = command([table_binary(family), '-w', '2', '-t', table, '-S'], until, home, 1 << 20)
                need(rc == 0 and not any(chain in raw.decode('ascii').split() for chain in chains),
                     'OWNED_FIREWALL_REMAINS')




def controls_snapshot(until, home):
    out = []
    for identity in PLAN['controls']:
        need(isinstance(identity, dict) and set(identity) == {'name', 'invocation_id'}
             and INVOCATION.fullmatch(identity['invocation_id']), 'EXACT_CONTROL_UNIT_REQUIRED')
        info = unit_properties(identity['name'], until, home)
        need(info.get('InvocationID') == identity['invocation_id'] and
             info.get('ActiveState') == 'active' and int(info['MainPID']) > 1, 'LIVE_UNRELATED_CONTROL_REQUIRED')
        out.append({key: info.get(key) for key in ('Id', 'InvocationID', 'MainPID', 'ControlGroup', 'ActiveState')})
    return out


def project_identity(row):
    out = {}
    lease = row['lease']
    roots = {kind: Path(lease[kind + '_path']) for kind in ('persistent', 'scratch', 'ipc', 'log', 'bootstrap')}
    roots.update({kind: Path(lease['scratch_path']).parent / kind for kind in ('tmp', 'work')})
    for kind, path in roots.items():
        fd = open_no_links(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            value = bytearray(28)
            fcntl.ioctl(fd, 0x801c581f, value, True)  # FS_IOC_FSGETXATTR, read-only.
            flags, _, _, project, _, _ = struct.unpack('=IIIII8s', value)
            out[kind] = {'device': os.fstat(fd).st_dev, 'project': project, 'inherit': bool(flags & 0x200)}
            expected = lease['persistent_project' if kind == 'persistent' else 'scratch_project']
            need(project == expected and flags & 0x200, 'PROJECT_ASSIGNMENT_OR_INHERITANCE_MISMATCH')
        finally:
            os.close(fd)
    need(all(out[k]['device'] == out['scratch']['device'] and out[k]['project'] == out['scratch']['project']
             for k in ('ipc', 'log', 'bootstrap', 'tmp', 'work')) and
         out['persistent']['project'] != out['scratch']['project'], 'SHARED_NATIVE_AND_GUEST_TMP_PROJECT_MISMATCH')
    return out


def root_confirmation(row):
    import base64
    intent = row.get('roots')
    need(intent and intent['confirmed'] is True and intent.get('result'), 'ROOTS_NOT_DURABLY_CONFIRMED')
    manifest, result = intent['manifest'], intent['result']
    payload = base64.b64decode(manifest['payload'], validate=True)
    need(manifest['digest'] == 'sha256:' + hashlib.sha256(b'chatanium-root-init-v1\0' + payload).hexdigest(),
         'ROOT_MANIFEST_EXACT_DIGEST')
    declaration = json.loads(payload)
    owner = row['lease']['ownership']
    need(all(declaration[key] == owner[key] for key in ('runtime_installation_id', 'epoch_id', 'instance_id')) and
         declaration['version'] == 1 and result['digest'] == manifest['digest'] and
         result['nonce'] == declaration['nonce'], 'ROOT_RESULT_BINDING')
    targets = {root['root_id']: root['target'] for root in declaration['roots']}
    observed = {step['root_id']: step for step in result['results']}
    need(set(targets) == set(observed) == {'persistent', 'scratch', 'tmp'} and
         len(targets) == len(declaration['roots']) == len(result['results']) and
         all(observed[key]['step'] == 2 and observed[key]['observed'] == target for key, target in targets.items()),
         'ROOT_RESULT_STEP_OR_TARGET')
    for root in intent['native']:
        native = root['native']
        fd = open_no_links(native['host_path'], os.O_RDONLY | os.O_DIRECTORY)
        try:
            st = os.fstat(fd)
            need((st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) ==
                 (native['dev'], native['ino'], native['uid'], native['gid'], native['mode']) and
                 st.st_uid == row['lease']['sandbox_uid'] and st.st_gid == row['lease']['sandbox_gid'],
                 'NATIVE_GUEST_ROOT_IDENTITY_CHANGED')
        finally:
            os.close(fd)
    return {'digest': manifest['digest'], 'intent_id': declaration['intent_id'], 'confirmed': True,
            'roots': sorted(targets), 'native_guest_identities_separate': True}


def worker_transport(row, worker):
    """Read actual transferred pipe ends and the runner-local pathname pin."""
    endpoint = row.get('endpoint')
    need(endpoint is not None, 'ENDPOINT_RECORD_MISSING')
    st = os.lstat(endpoint['path'])
    directory = os.lstat(endpoint['directory'])
    need(stat.S_ISSOCK(st.st_mode) and
         (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) ==
         (endpoint['socket_dev'], endpoint['socket_ino'], endpoint['uid'], endpoint['gid'], endpoint['mode']) and
         (directory.st_dev, directory.st_ino) == (endpoint['directory_dev'], endpoint['directory_ino']),
         'NATIVE_ENDPOINT_IDENTITY')
    pid = worker['main_pid']
    need(proc_start(pid) == worker['start_time'], 'TRANSPORT_WORKER_IDENTITY')
    pipe_expected = {}
    for n, access in ((0, os.O_WRONLY), (1, os.O_RDONLY), (2, os.O_RDONLY)):
        stage = os.stat('/proc/' + str(row['unit']['unit']['main_pid']) + '/fd/' + str(n))
        need(stat.S_ISFIFO(stage.st_mode), 'STAGE_STDIO_NOT_PIPE')
        pipe_expected[(stage.st_dev, stage.st_ino)] = access
    pipes, pins, sockets = {}, [], []
    names = os.listdir('/proc/' + str(pid) + '/fd')
    need(len(names) <= 4096, 'WORKER_FD_BOUND')
    for name in names:
        if not name.isdigit():
            continue
        path = '/proc/' + str(pid) + '/fd/' + name
        try:
            native = os.stat(path)
            raw, _ = bounded_read(Path('/proc') / str(pid) / 'fdinfo' / name, 16384, pseudo=True)
            fields = dict(line.split(':', 1) for line in raw.decode('ascii').splitlines() if ':' in line)
            flags = int(fields['flags'].strip(), 8)
            key = (native.st_dev, native.st_ino)
            if key in pipe_expected and flags & os.O_ACCMODE == pipe_expected[key]:
                pipes[str(pipe_expected[key]) + ':' + str(native.st_ino)] = int(name)
            if key == (st.st_dev, st.st_ino):
                need(flags & os.O_PATH and flags & os.O_CLOEXEC and os.readlink(path) == endpoint['path'],
                     'WORKER_ENDPOINT_NOT_LOCAL_OPATH')
                pins.append(int(name))
            if stat.S_ISSOCK(native.st_mode):
                sockets.append(native.st_ino)
        except FileNotFoundError:
            continue
    raw, _ = bounded_read(Path('/proc') / str(os.getpid()) / 'net' / 'unix', 1 << 20, pseudo=True)
    listeners = [line.split() for line in raw.decode('ascii').splitlines()[1:]
                 if line.split()[-1:] == [endpoint['path']]]
    need(len(listeners) == 1 and int(listeners[0][3], 16) & 0x10000 and
         int(listeners[0][4], 16) == 1 and int(listeners[0][6]) in sockets,
         'TRANSFERRED_LISTENER_MISSING')
    need(len(pipes) == 3 and len(pins) == 1, 'FIVE_FD_TRANSPORT_NOT_OBSERVED')
    return {'pipes': sorted(pipes), 'opath_fd': pins[0], 'device': st.st_dev, 'inode': st.st_ino,
            'listener_inode': int(listeners[0][6]), 'worker_invocation': worker['invocation_id']}


def endpoint(raw):
    if raw.startswith('['):
        host, port = raw[1:].split(']:')
    else:
        host, port = raw.rsplit(':', 1)
    ip = ipaddress.ip_address(host)
    need(1 <= int(port) <= 65535, 'INVALID_NUMERIC_ENDPOINT')
    return str(ip), int(port)


def dns_control(query, until):
    host, port = endpoint(query['resolver'])
    labels = query['name'].rstrip('.').split('.')
    question = b''.join(bytes([len(label)]) + label.encode('ascii') for label in labels) + b'\0'
    question += struct.pack('!HH', 28 if query['type'] == 'AAAA' else 1, 1)
    ident = int.from_bytes(os.urandom(2), 'big')
    packet = struct.pack('!HHHHHH', ident, 0x100, 1, 0, 0, 0) + question
    result = {'endpoint': query['resolver'], 'transport': query['transport'], 'connected': False, 'operation': 'matching_host_dns_question'}
    stop = min(until, time.monotonic() + 3)
    try:
        kind = socket.SOCK_STREAM if query['transport'] == 'tcp' else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, kind) as s:
            s.settimeout(max(.001, stop - time.monotonic()))
            s.connect((host, port))
            s.sendall((struct.pack('!H', len(packet)) if kind == socket.SOCK_STREAM else b'') + packet)
            def receive(n):
                value = bytearray()
                while len(value) < n:
                    check(stop)
                    s.settimeout(max(.001, stop - time.monotonic()))
                    part = s.recv(n - len(value))
                    need(part, 'DNS_CONTROL_SHORT_READ')
                    value.extend(part)
                return bytes(value)
            if kind == socket.SOCK_STREAM:
                size = struct.unpack('!H', receive(2))[0]
                need(12 <= size <= 4096, 'DNS_CONTROL_RESPONSE_BOUND')
                response = receive(size)
            else:
                response = s.recv(4097)
            if 12 <= len(response) <= 4096:
                got, flags, count, _, _, _ = struct.unpack('!HHHHHH', response[:12])
                result['connected'] = got == ident and bool(flags & 0x8000) and count == 1 and response[12:12 + len(question)].lower() == question.lower()
    except (OSError, Fault) as exc:
        result['errno'] = getattr(exc, 'errno', None)
    return result


def network_controls(case, until):
    observations = []
    for raw in PLAN.get('network_controls', {}).get(case, []):
        check(until)
        host, port = endpoint(raw)
        try:
            with socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((host, port))
                observations.append({'endpoint': raw, 'connected': True})
        except OSError as exc:
            observations.append({'endpoint': raw, 'connected': False, 'errno': exc.errno})
    for query in (ACTIVE_NETWORK_SPEC or {}).get('dns_queries', []):
        observations.append(dns_control(query, until))
    return observations


def table_binary(family):
    return '/usr/sbin/iptables' if family == 4 else '/usr/sbin/ip6tables'


def inspect_ip(prefix, args, until, home, maximum=64):
    rc, raw, _ = command(['/usr/sbin/ip'] + prefix + ['-j', '-d'] + args, until, home, 1 << 20)
    need(rc == 0, 'NETWORK_INSPECTION_FAILED')
    value = json.loads(raw)
    need(isinstance(value, list) and len(value) <= maximum, 'NETWORK_INSPECTION_BOUND')
    return value


def network_chains(record):
    token = hashlib.sha256(('filter\0' + record['generation']).encode('ascii')).hexdigest()[:16]
    return ('CTF' + token, 'CTI' + token, 'CTN' + token)


def owned_network_readiness(row, info, until, home):
    record = row.get('network')
    need(record and record['generation'] == row['lease']['network_generation'] and
         record['profile'] == row['lease']['topology'], 'NETWORK_GENERATION_IDENTITY')
    ns = os.stat(record['netns_path'])
    need((ns.st_dev, ns.st_ino) == (record['netns_dev'], record['netns_ino']), 'NETNS_INODE_CHANGED')
    prefix = ['-n', Path(record['netns_path']).name]
    peerlinks = inspect_ip(prefix, ['link', 'show'], until, home)
    if record['profile'] == 'NONE':
        need(len(peerlinks) == 1 and peerlinks[0]['ifname'] == 'lo' and
             not record['host_interface'] and not record['peer_interface'], 'NONE_TOPOLOGY_MISMATCH')
        return {'network_id': record['generation'], 'profile': 'NONE', 'ready': True}
    need(record['state'] == 'OPEN', 'NETWORK_NOT_DURABLY_OPEN')
    hostlinks = inspect_ip([], ['link', 'show', 'dev', record['host_interface']], until, home)
    peerlinks = [x for x in peerlinks if x['ifname'] == record['peer_interface']]
    need(len(hostlinks) == len(peerlinks) == 1, 'DEDICATED_VETH_PAIR_MISSING')
    topology = {'network_id': record['generation'], 'profile': record['profile'], 'links': [], 'routes': [], 'neighbors': [], 'ready': True}
    for scope, link, name, index, mac, local4, local6, remote4, remote6, remotemac in (
            ([], hostlinks[0], record['host_interface'], record['host_if_index'], record['host_mac'],
             record['host_ipv4'], record['host_ipv6'], record['peer_ipv4'], record['peer_ipv6'], record['peer_mac']),
            (prefix, peerlinks[0], record['peer_interface'], record['peer_if_index'], record['peer_mac'],
             record['peer_ipv4'], record['peer_ipv6'], record['host_ipv4'], record['host_ipv6'], record['host_mac'])):
        need(link['ifindex'] == index and link['address'].lower() == mac.lower() and
             link.get('linkinfo', {}).get('info_kind') == 'veth' and 'UP' in link.get('flags', []),
             'VETH_IDENTITY_OR_LINK_BARRIER')
        addresses = inspect_ip(scope, ['address', 'show', 'dev', name], until, home)
        need(len(addresses) == 1 and addresses[0]['ifindex'] == index, 'ADDRESS_LINK_IDENTITY')
        ips = addresses[0].get('addr_info', [])
        need({a['local'] for a in ips if a['family'] in ('inet', 'inet6')} == {x for x in (local4, local6) if x},
             'EXACT_ENDPOINT_ADDRESS_SET')
        need(not any(a.get('tentative') or a.get('dadfailed') or
                     set(a.get('flags', [])) & {'tentative', 'dadfailed'} for a in ips), 'DAD_NOT_COMPLETE')
        topology['links'].append({'ifindex': index, 'name': name, 'mac': mac, 'addresses': ips})
        for family, remote in ((4, remote4), (6, remote6)):
            if not remote:
                continue
            neighbors = inspect_ip(scope, ['-' + str(family), 'neigh', 'show', 'dev', name], until, home)
            need(len(neighbors) == 1 and neighbors[0]['dst'] == remote and
                 neighbors[0]['lladdr'].lower() == remotemac.lower() and
                 'PERMANENT' in neighbors[0].get('state', []), 'PERMANENT_NEIGHBOR_IDENTITY')
            topology['neighbors'].append(neighbors[0])
            routes = inspect_ip(scope, ['-' + str(family), 'route', 'show', 'dev', name], until, home)
            if scope:
                need(any(x.get('dst') == 'default' and x.get('gateway') == remote for x in routes),
                     'PEER_DEFAULT_ROUTE_MISSING')
            else:
                connected = record['ipv4_prefix' if family == 4 else 'ipv6_prefix']
                need(any(x.get('dst') == connected and x.get('scope') == 'link' for x in routes),
                     'HOST_CONNECTED_ROUTE_MISSING')
            topology['routes'].append(routes)
    return topology


def firewall_generations(snapshot, active=False):
    if snapshot.get('topology') == 'none':
        return []
    identity = snapshot['identity']
    need(identity['state'] == ('OPEN' if active else identity['state']) and identity['filter_generation']
         and identity['nat_generation'] and identity['inventory_digest'], 'POLICY_NOT_DURABLY_ACTIVE')
    f, _, nat = network_chains(identity)
    for family in (4, 6):
        rules = [x for x in snapshot['rules'] if x['family'] == family and x['chain'] == f]
        need(rules and identity['filter_generation'] in rules[-1]['rule'] and
             rules[-1]['rule'].split()[0] == 'DROP', 'TERMINAL_FILTER_GENERATION_MISSING')
        if family == 4 or identity['profile'] == 'PUBLIC-dual':
            snat = [x for x in snapshot['rules'] if x['family'] == family and x['chain'] == nat]
            need(len(snat) == 1 and identity['nat_generation'] in snat[0]['rule'] and
                 snat[0]['rule'].split()[0] == 'SNAT', 'EXACT_SNAT_GENERATION_MISSING')
            source = identity['source4' if family == 4 else 'source6']
            need('to:' + source in snat[0]['rule'].split(), 'EXACT_SNAT_SOURCE_MISMATCH')
    return [(identity[k]) for k in ('generation', 'filter_generation', 'nat_generation', 'inventory_digest', 'state')]


def network_start_barrier(row, info, until, home, observation):
    topology = owned_network_readiness(row, info, until, home)
    before = firewall_snapshot(row, info, until, home)
    confirmed = owned_network_readiness(row, info, until, home)
    after = firewall_snapshot(row, info, until, home)
    need(topology == confirmed, 'NETWORK_START_TOPOLOGY_CHANGED')
    firewall_delta(before, after)
    firewall_generations(after, active=True)
    records, _ = fixture_records(Path(row['lease']['persistent_path']),
                                 scan_names(Path(row['lease']['persistent_path']), until), until)
    need(not any(r['state'] == 'triggered' for r in records), 'NETWORK_PROBE_PRECEDED_OBSERVATION_BARRIER')
    observation.update(status='READY', bookend_topology=confirmed, bookend_before=before, bookend_after=after)
    return after


def firewall_snapshot(row, info, until, home):
    record = row['network']
    if record['profile'] == 'NONE':
        owned_network_readiness(row, info, until, home)
        return {'rules': [], 'topology': 'none'}
    chains = network_chains(record)
    rows, hooks = [], []
    for family in (4, 6):
        for table, chain in (('filter', chains[0]), ('filter', chains[1]), ('nat', chains[2])):
            if table == 'nat' and family == 6 and record['profile'] != 'PUBLIC-dual':
                continue
            rc, raw, _ = command([table_binary(family), '-w', '2', '-t', table, '-L', chain,
                                   '-n', '-v', '-x', '--line-numbers'], until, home, 65536)
            need(rc == 0, 'OWNED_FIREWALL_UNAVAILABLE')
            for line in raw.decode('ascii').splitlines():
                parts = line.split()
                if parts and parts[0].isdigit():
                    need(len(rows) < 1024 and len(parts) >= 10 and parts[1].isdigit() and parts[2].isdigit(), 'COUNTER_FORMAT')
                    rows.append({'family': family, 'table': table, 'chain': chain, 'index': int(parts[0]),
                                 'packets': int(parts[1]), 'bytes': int(parts[2]), 'rule': ' '.join(parts[3:])})
            rc, raw, _ = command([table_binary(family), '-w', '2', '-t', table, '-S'], until, home, 1 << 20)
            need(rc == 0, 'HOOK_INVENTORY_UNAVAILABLE')
            hooks.append({'family': family, 'table': table, 'sha256': hashlib.sha256(raw).hexdigest()})
    return {'rules': rows, 'hooks': hooks, 'identity': copy.deepcopy(record),
            'network_id': record['generation'], 'observed_monotonic': time.monotonic()}


def firewall_delta(before, after):
    if before.get('topology') == 'none' or after.get('topology') == 'none':
        need(before.get('topology') == after.get('topology') == 'none', 'NONE_TOPOLOGY_CHANGED')
        return []
    need(firewall_generations(before) == firewall_generations(after) and
         before['hooks'] == after['hooks'] and len(before['rules']) == len(after['rules']), 'POLICY_GENERATION_CHANGED')
    out = []
    for old, new in zip(before['rules'], after['rules']):
        need(all(old[k] == new[k] for k in ('family', 'table', 'chain', 'index', 'rule')) and
             new['packets'] >= old['packets'] and new['bytes'] >= old['bytes'], 'COUNTER_IDENTITY_CHANGED')
        out.append(dict(new, packet_delta=new['packets'] - old['packets']))
    return out


def isolated_dns_drop_evidence(result, records, operations):
    """Attribute a generic raw DNS drop only to one isolated numeric question."""
    spec = ACTIVE_NETWORK_SPEC or {}
    queries = spec.get('dns_queries', [])
    if (len(queries) != 1 or len(operations) != 1 or
            any(spec.get(k) for k in ('tcp_targets', 'http_requests', 'fresh_resolutions'))):
        return False
    query, rec = queries[0], operations[0]
    data = rec.get('data', {})
    if (rec['probe'] != 'network-dns' or rec['state'] != 'query-returned' or
            query.get('expect') != 'deny' or data.get('expected') != 'deny' or
            data.get('query_index') != 0 or data.get('resolver') != query.get('resolver') or
            data.get('transport') != query.get('transport') or data.get('query_type') != query.get('type') or
            data.get('received_response') is not False or data.get('received_bytes', 0) > 0):
        return False
    if query.get('transport') == 'udp' and data.get('sent_bytes', 0) <= 0:
        return False
    triggers = [x for x in records if x['probe'] == 'network' and x['state'] == 'triggered']
    completions = [x for x in records if x['probe'] == 'network' and x['state'] == 'returned-not-policy-proof']
    if (len(triggers) != 1 or len(completions) != 1 or
            not triggers[0]['sequence'] < rec['sequence'] < completions[0]['sequence'] or
            not any(x.get('operation') == 'matching_host_dns_question' and
                    x.get('endpoint') == query['resolver'] and x.get('transport') == query['transport'] and
                    x.get('connected') is True for x in result.get('network_controls', []))):
        return False
    barrier = result.get('network_start_barrier', {})
    if result.get('network_counter_error') or barrier.get('status') != 'READY':
        return False
    try:
        host, port = endpoint(query['resolver'])
        ip = ipaddress.ip_address(host)
        if port != 53 or ip in [ipaddress.ip_address(x) for x in CURRENT_FIXTURE['config']['host']['network']['resolvers']]:
            return False
        before, after = result['firewall_before'], result['firewall_after']
        if barrier.get('bookend_topology', {}).get('network_id') != before['network_id']:
            return False
        firewall_generations(before, active=True)
        stable = firewall_delta(before, after)
        if stable != result.get('firewall_delta'):
            return False
        positive = [(old, new) for old, new in zip(before['rules'], stable) if new['packet_delta'] > 0]
        if len(positive) != 1:
            return False  # Never attribute ambiguous shared or ambient traffic.
        old, drop = positive[0]
        protocol = query['transport']
        parts = drop['rule'].split()
        return (protocol in ('udp', 'tcp') and drop['family'] == ip.version and drop['table'] == 'filter'
                and parts[0] == 'DROP' and parts[1] == protocol and 'dpt:53' in parts
                and drop['bytes'] > old['bytes'])
    except (Fault, KeyError, TypeError, ValueError):
        return False


def rebinding_tcp_expectation(rec):
    """The actual destination, never its round number, determines egress policy."""
    try:
        ip = ipaddress.ip_address(endpoint(rec.get('data', {}).get('address', ''))[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        network = CURRENT_FIXTURE['config']['host']['network']
        blocked = [ipaddress.ip_network(raw, strict=False)
                   for key in ('host_public_addresses', 'internal_prefixes', 'metadata_prefixes')
                   for raw in network.get(key, [])]
        allowed = ip.is_global and not ip.is_multicast and not any(ip in prefix for prefix in blocked)
        return 'connect' if allowed else 'deny'
    except (Fault, TypeError, ValueError):
        return None


def rebinding_transition_witnessed(operations):
    fresh = (ACTIVE_NETWORK_SPEC or {}).get('fresh_resolutions', [])
    if len(fresh) != 1:
        return False
    query = fresh[0]
    dns = [x for x in operations if x['probe'] == 'network-dns'
           and x.get('data', {}).get('fresh_index') == 0
           and x['data'].get('resolver') == query.get('resolver')
           and x['data'].get('transport') == query.get('transport')
           and x['data'].get('query_type') == query.get('type')
           and x['data'].get('received_response') is True]
    public, private = [], []
    for rec in operations:
        if rec['probe'] != 'network-tcp' or rec.get('data', {}).get('fresh_index') != 0:
            continue
        data = rec['data']
        try:
            host, port = endpoint(data.get('address', ''))
        except (Fault, TypeError, ValueError):
            continue
        round_number = data.get('round')
        if (port != query.get('port') or type(round_number) is not int or
                not 0 <= round_number < query.get('rounds', 0) or
                not any(x['data'].get('round') == round_number and x['sequence'] < rec['sequence']
                        and host in x['data'].get('selected_addresses', []) for x in dns)):
            continue
        policy = rebinding_tcp_expectation(rec)
        if (round_number == 0 and policy == 'connect' and data.get('connected') is True
                and data.get('address') in PLAN['network_controls']['dns-rebinding']):
            public.append(rec)
        if (round_number > 0 and policy == 'deny' and data.get('connected') is False
                and data.get('address') in PLAN['network_controls']['dns-rebinding']):
            private.append(rec)
    return any(a['sequence'] < b['sequence'] for a in public for b in private)


def network_verdict(case, result, records):
    operations = [x for x in records if x['probe'] in ('network-tcp', 'network-dns') or
                  (x['probe'] == 'network-http' and x['state'] == 'actual-dial-returned')]
    if case == 'dns-rebinding' and any(
            x['probe'] == 'network-tcp' and x.get('data', {}).get('connected') is True
            and rebinding_tcp_expectation(x) == 'deny' for x in operations):
        return 'FAIL', 'forbidden_operation_succeeded'
    if not operations:
        if case == 'network-redirect' and any(
                x['probe'] == 'network-http' and x['state'] == 'response-returned' and
                x.get('data', {}).get('hop') == 0 and x['data'].get('error_category') == 'dns'
                for x in records):
            return 'INCONCLUSIVE', 'http_first_hop_dns_resolution_failed'
        return 'INCONCLUSIVE', 'no_actual_network_operation'
    controls = result.get('network_controls', [])
    if not controls or not all(x['connected'] for x in controls):
        return 'INCONCLUSIVE', 'positive_control_unavailable'
    if is_public(case) and (result.get('network_counter_error') or 'firewall_delta' not in result):
        return 'INCONCLUSIVE', 'unstable_or_missing_owned_policy_counter_evidence'
    conclusions = []
    for rec in operations:
        data = rec.get('data', {})
        positive = data.get('connected', data.get('received_response', False))
        expected = data.get('expected', 'deny' if data.get('hop', 0) else 'connect')
        if case == 'dns-rebinding' and rec['probe'] == 'network-tcp':
            expected = rebinding_tcp_expectation(rec)
            if expected is None:
                conclusions.append('INCONCLUSIVE')
                continue
        if expected in ('connect', 'response'):
            conclusions.append('PASS' if positive else 'FAIL')
            continue
        if positive:
            return 'FAIL', 'forbidden_operation_succeeded'
        if case == 'network-none' and result.get('firewall_before', {}).get('topology') == 'none':
            conclusions.append('PASS')  # Explicitly network isolation, not firewall-counter proof.
            continue
        try:
            host, _ = endpoint(data.get('address', data.get('resolver', data.get('actual_address', ''))))
            ip = ipaddress.ip_address(host)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
        except (ValueError, Fault):
            conclusions.append('INCONCLUSIVE')
            continue
        matched = False
        for drop in result.get('firewall_delta', []):
            parts = drop['rule'].split()
            if drop['packet_delta'] <= 0 or len(parts) < 7 or parts[0] != 'DROP' or drop['family'] != ip.version:
                continue
            protocol = data.get('transport', 'tcp')
            if parts[1] not in (protocol, 'all'):
                continue
            try:
                prefix = ipaddress.ip_network(parts[6], strict=False)
                matched |= prefix.prefixlen > 0 and ip in prefix
            except ValueError:
                continue
        if not matched and case == 'network-dns':
            matched = isolated_dns_drop_evidence(result, records, operations)
        conclusions.append('PASS' if matched else 'INCONCLUSIVE')
    if case == 'network-redirect':
        queries = (ACTIVE_NETWORK_SPEC or {}).get('http_requests', [])
        expected_url = queries[0].get('expected_redirect_url', '') if len(queries) == 1 else ''
        if not expected_url:
            return 'INCONCLUSIVE', 'actual_redirect_and_exact_controlled_second_hop_required'
        expected_hash = hashlib.sha256(expected_url.encode('ascii')).hexdigest()
        expected_endpoint = expected_redirect_endpoint(expected_url)
        hops = [x for x in operations if x['probe'] == 'network-http']
        first = [x for x in hops if x.get('data', {}).get('hop') == 0
                 and x['data'].get('request_index') == 0 and x['data'].get('connected') is True]
        redirects = [x for x in records if x['probe'] == 'network-http' and x['state'] == 'response-returned'
                     and x.get('data', {}).get('hop') == 0 and x['data'].get('request_index') == 0
                     and x['data'].get('received_response') is True
                     and x['data'].get('status') in (301, 302, 303, 307, 308)
                     and x['data'].get('has_redirect_location') is True
                     and x['data'].get('redirect_url_sha256') == expected_hash
                     and re.fullmatch(r'[0-9a-f]{64}', x['data'].get('request_url_sha256', ''))]
        second = [x for x in hops if x.get('data', {}).get('hop', 0) > 0]
        linked = any(a['sequence'] < b['sequence'] and
                     a['data'].get('request_url_sha256') == b['data']['request_url_sha256'] and
                     all(b['sequence'] < c['sequence'] for c in second)
                     for a in first for b in redirects)
        if (not linked or not second or expected_endpoint not in PLAN['network_controls'][case] or
                not all(x['data'].get('hop') == 1 and x['data'].get('request_index') == 0 and
                        x['data'].get('request_url_sha256') == expected_hash and
                        x['data'].get('actual_address') == expected_endpoint for x in second)):
            return 'INCONCLUSIVE', 'actual_redirect_and_exact_controlled_second_hop_required'
    if case == 'dns-rebinding' and not rebinding_transition_witnessed(operations):
        return 'INCONCLUSIVE', 'public_then_controlled_private_fresh_connections_not_witnessed'
    if 'FAIL' in conclusions:
        return 'FAIL', 'approved_positive_operation_failed'
    return ('PASS', 'actual_operations_and_owned_destination_evidence') if all(x == 'PASS' for x in conclusions) else ('INCONCLUSIVE', 'missing_stable_destination_specific_counter_evidence')



def verdict(case, result, records):
    continuity = result.get('cpu_limit_continuity')
    if continuity is None:
        continuity = cpu_limit_continuity(result.get('cgroup_samples', []), result.get('running_seen', False),
                                          result.get('cgroup_identity'))
    if continuity['status'] == 'FAIL':
        return 'FAIL', 'CPU_LIMIT_DRIFT'
    outcome = case_policy_verdict(case, result, records)
    if outcome[0] == 'PASS' and continuity['status'] == 'INCONCLUSIVE':
        return 'INCONCLUSIVE', 'CPU_LIMIT_CONTINUITY_UNPROVEN'
    return outcome


def case_policy_verdict(case, result, records):
    if result['status'] == 'FAIL':
        return 'FAIL', 'cleanup_or_safety_failure'
    for rec in records if case in NETWORK_CASES else []:
        data = rec.get('data', {})
        forbidden = data.get('expected') == 'deny' or (rec['probe'] == 'network-http' and rec['state'] == 'actual-dial-returned' and data.get('hop', 0) > 0)
        if case == 'dns-rebinding' and rec['probe'] == 'network-tcp':
            forbidden = rebinding_tcp_expectation(rec) == 'deny'
        if forbidden and data.get('connected', data.get('received_response', False)):
            return 'FAIL', 'forbidden_operation_succeeded'
    if result.get('errors') or result.get('discarded_nonallowlisted_lines'):
        return 'INCONCLUSIVE', 'observation_error_or_unexpected_runtime_output'
    absence = result.get('native_unit_absence') or {}
    if not (result.get('cleanup_complete') and result.get('owned_unit_absent') and result.get('owned_jobs_absent') and
            absence.get('complete') is True and absence.get('status') == 'OBSERVED' and
            result.get('unrelated_controls_preserved') and all(result.get('final_path_absence', {}).values())):
        return 'INCONCLUSIVE', 'terminal_host_ownership_evidence_missing'
    scratch = result.get('final_quotas', {}).get('scratch', {})
    if scratch.get('status') == 'MEASURED':
        if any(scratch.get(k) != 0 for k in ('bytes', 'inodes', 'realtime_bytes')):
            return 'FAIL', 'independently_observed_shared_project_usage_remains'
    elif not result.get('durable_reclaim'):
        return 'INCONCLUSIVE', 'root_scoped_project_reclamation_unproven'
    retained_app = result.get('native_app_retained') or {}
    if not retained_app.get('mounted_identity') or retained_app.get('claim', {}).get('state') != 'RESERVED':
        return 'INCONCLUSIVE', 'retained_native_app_reservation_or_observed_inode_missing'
    reports = result.get('fixture_reports', [])
    if len(reports) != 1 or any(x['malformed_lines'] or not x['ends_in_newline'] for x in reports):
        return 'INCONCLUSIVE', 'complete_bounded_fixture_transcript_missing'
    for sample in result.get('cgroup_samples', []):
        if max(sample.get('memory.current', 0), sample.get('memory.peak', 0)) > RESOURCES['memory_bytes'] or max(sample.get('pids.current', 0), sample.get('pids.peak', 0)) > RESOURCES['pids']:
            return 'FAIL', 'observed_cgroup_resource_bound_exceeded'
    if case == 'ipc-held-unlinked':
        if result.get('held_ipc_accounting'):
            return 'PASS', 'unlinked_open_ipc_allocation_remained_charged_until_owned_teardown'
        return 'INCONCLUSIVE', 'unlinked_open_ipc_accounting_not_observed'
    if case in NETWORK_CASES:
        return network_verdict(case, result, records)
    if case == 'ipc-race':
        fixture = [x for x in records if x['probe'] == 'ipc-component']
        facts = {x['state']: x.get('data', {}) for x in fixture}
        if facts.get('replacement-connect', {}).get('outside_accepted'):
            return 'FAIL', 'replacement_endpoint_connected'
        before, after = result.get('transport_before'), result.get('transport_after')
        if not (before and before == after and facts.get('pin-opened', {}).get('opath') is True and
                facts.get('pathname-replaced', {}).get('replacement_symlink') is True and
                facts.get('retained-connect', {}).get('peer_pid') == facts.get('pin-opened', {}).get('pid') and
                facts.get('fresh-path-inspection', {}).get('is_symlink') is True and
                facts.get('core-rpc-after-replacement', {}).get('response_received') is True):
            return 'INCONCLUSIVE', 'ordered_guest_pin_race_and_original_hook_transport_unproven'
        return 'PASS', 'real_five_fd_transport_and_guest_opath_survive_pathname_replacement'
    if case == 'cleanup-crash':
        terminal = result.get('worker_terminal') or {}
        if not (result.get('cleanup_crash_witness') and result.get('cleanup_crash_sigkill_sent') and
                terminal.get('kind') == 'signal' and terminal.get('value') == 9 and
                (result.get('final_epoch') or {}).get('state') == 'DEAD'):
            return 'INCONCLUSIVE', 'cleanup_window_not_witnessed_no_crash_claim'
        return 'PASS', 'witnessed_cleanup_crash_and_external_reconciliation'
    if case in ('normal-exit', 'sigterm', 'sigint'):
        wanted = signal.SIGINT if case == 'sigint' else signal.SIGTERM
        delivered = any(x['signal'] == wanted for x in result.get('runtime_signals', []))
        if result.get('runtime_returncode') != 0 or (case == 'normal-exit' and result.get('runtime_signals')) or (case != 'normal-exit' and not delivered):
            return 'FAIL', 'requested_termination_did_not_complete_normally'
    facts = result.get('assessments', [])
    if any(x['status'] in ('INCONCLUSIVE', 'UNSUPPORTED') for x in facts):
        return 'INCONCLUSIVE', 'required_positive_enforcement_measurement_missing'
    if case == 'identity':
        observations = {x.get('data', {}).get('operation'): x.get('data', {}) for x in records
                        if x['state'] == 'child-syscall-observation'}
        if len(observations) != 9:
            return 'INCONCLUSIVE', 'all_nine_identity_syscalls_not_observed'
        required = ('uid-root', 'gid-root', 'user-namespace', 'mount-namespace', 'pid-namespace', 'network-namespace')
        if any(observations[key].get('outcome') == 'syscall-or-operation-returned' for key in required):
            return 'FAIL', 'guest_privilege_or_namespace_escape_succeeded'
        if any(observations[key].get('outcome') != 'syscall-error' or observations[key].get('errno') not in (1, 13)
               for key in required):
            return 'INCONCLUSIVE', 'guest_privilege_denial_not_proven'
        for key in ('nproc-hard', 'nofile-hard'):
            value = observations[key]
            if value.get('outcome') == 'syscall-or-operation-returned':
                return 'FAIL', 'finite_guest_hard_limit_raise_succeeded'
            if value.get('outcome') not in ('already-infinite-no-raise-attempt', 'syscall-error'):
                return 'INCONCLUSIVE', 'guest_hard_limit_observation_missing'
        # RLIMIT_NPROC is not the native cgroup TasksMax contract. A permitted
        # soft-limit increase within an existing hard limit grants no host tasks.
    if case.endswith('-failure') or case == 'startup-budget':
        reasons = {x.get('stop_failure', {}).get('failure_reason') for x in result.get('runtime_observations', [])}
        expected = 'STARTUP_DEADLINE_EXCEEDED' if case == 'startup-budget' else 'MODULE_REPORTED_FAILURE' if case == 'readiness-failure' else 'HOOK_FAILED'
        if expected not in reasons or result.get('running_seen'):
            return 'INCONCLUSIVE', 'expected_runtime_failure_reason_not_observed'
    if (result.get('scenario') or {}).get('kind') == 'quota':
        samples = result.get('quota_samples', [])
        for sample in samples:
            for kind in ('persistent', 'scratch'):
                q = sample[kind]
                if q.get('status') != 'MEASURED' or q['hard_bytes'] != RESOURCES[kind + '_bytes'] or q['hard_inodes'] != LIMITS[kind + '_inode_limit']:
                    return 'INCONCLUSIVE', 'exact_project_enforcement_limits_missing'
                if q['bytes'] > q['hard_bytes'] or q['inodes'] > q['hard_inodes']:
                    return 'FAIL', 'project_hard_limit_exceeded'
        if case == 'cross-project-link':
            links = [x for x in records if x['state'] == 'hardlink-syscall-returned']
            if len(links) != 6 or any(x.get('errno') != errno.EXDEV for x in links):
                return 'FAIL', 'cross_project_link_not_denied'
        else:
            kind = 'persistent' if case.startswith('persistent-') else 'scratch'
            high = result.get('quota_high_water', {}).get(kind, {})
            metric = 'inodes' if case.endswith('inodes') else 'bytes'
            bound = LIMITS[kind + '_inode_limit'] if metric == 'inodes' else RESOURCES[kind + '_bytes']
            # Positive near-bound host accounting plus matching denial required;
            # free-space ENOSPC far from the project limit is not quota PASS.
            margin = 16 if metric == 'inodes' else 2 << 20
            if high.get(metric, 0) < bound - margin:
                return 'INCONCLUSIVE', 'denial_without_near_limit_project_accounting'
            if case.startswith('combined-'):
                allocations = [x.get('data', {}) for x in records if x['probe'].startswith('quota')]
                text = json.dumps(allocations)
                if 'scratch' not in text or 'ipc' not in text:
                    return 'INCONCLUSIVE', 'both_shared_mount_allocations_not_observed'
    return 'PASS', 'positive_case_evidence_and_exact_owned_cleanup'


def read_json(path):
    trusted(path)
    raw, _ = bounded_read(path, 262144)
    def unique(pairs):
        out = {}
        for k, v in pairs:
            need(k not in out, 'DUPLICATE_JSON_FIELD')
            out[k] = v
        return out
    return json.loads(raw, object_pairs_hook=unique), raw


def aggregate_status(items):
    statuses = [x['status'] for x in items]
    if 'FAIL' in statuses:
        return 'FAIL'
    if statuses and all(x == 'PASS' for x in statuses):
        return 'PASS'
    if statuses and all(x == 'NOT_RUN' for x in statuses):
        return 'NOT_RUN'
    return 'INCONCLUSIVE'


def expected_redirect_endpoint(raw):
    need(isinstance(raw, str) and 0 < len(raw) <= 2048 and raw.isascii()
         and re.fullmatch(r"[A-Za-z0-9._~!$&'()*+,;=:@/%?\[\]-]+", raw)
         and not re.search(r'%(?![0-9A-Fa-f]{2})', raw), 'CANONICAL_EXPECTED_REDIRECT_URL_REQUIRED')
    parsed = urlsplit(raw)
    need(parsed.scheme in ('http', 'https') and parsed.username is None and parsed.password is None
         and not parsed.fragment and re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@/%-]*", parsed.path)
         and urlunsplit(parsed) == raw,
         'CANONICAL_EXPECTED_REDIRECT_URL_REQUIRED')
    host, port = endpoint(parsed.netloc)
    address = ('[' + host + ']' if ':' in host else host) + ':' + str(port)
    need('%' not in host and parsed.netloc == address, 'CANONICAL_EXPECTED_REDIRECT_URL_REQUIRED')
    return address


def validate_network_spec(case, spec):
    need(isinstance(spec, dict) and set(spec) <= {'expected_egress', 'operation_timeout_ms', 'tcp_targets', 'dns_queries', 'http_requests', 'fresh_resolutions'},
         'NETWORK_SPEC_FIELDS')
    count = sum(len(spec.get(k, [])) for k in ('tcp_targets', 'dns_queries', 'http_requests', 'fresh_resolutions'))
    need(count == 1 and 1 <= spec.get('operation_timeout_ms', 0) <= 10000, 'ONE_FINITE_NETWORK_OPERATION_PER_INSTANCE_REQUIRED')
    need(spec.get('expected_egress') == ('PUBLIC_INTERNET' if is_public(case) else 'NONE'), 'NETWORK_GRANT_EXPECTATION_MISMATCH')
    controls = PLAN.get('network_controls', {}).get(case, [])
    need(isinstance(controls, list) and 1 <= len(controls) <= 16, 'BOUNDED_NUMERIC_CONTROLS_REQUIRED')
    for control in controls:
        endpoint(control)
    if case == 'ipv6-public':
        targets = spec.get('tcp_targets', [])
        need(len(targets) == 1 and ipaddress.ip_address(endpoint(targets[0]['address'])[0]).version == 6
             and ipaddress.ip_address(endpoint(targets[0]['address'])[0]).is_global
             and targets[0]['expect'] == 'connect', 'REAL_PUBLIC_IPV6_POSITIVE_TARGET_REQUIRED')
    if case == 'dns-rebinding':
        fresh = spec.get('fresh_resolutions', [])
        need(len(fresh) == 1 and fresh[0]['expect'] == 'connect_then_deny' and fresh[0]['rounds'] >= 2,
             'CONTROLLED_FRESH_REBINDING_REQUIRED')
    if case == 'network-redirect':
        requests = spec.get('http_requests', [])
        need(len(requests) == 1 and requests[0].get('expect') == 'deny'
             and 1 <= requests[0].get('max_redirects', 0) <= 3,
             'EXPLICIT_DENIED_REDIRECT_OPERATION_REQUIRED')
        address = expected_redirect_endpoint(requests[0].get('expected_redirect_url'))
        need(address in controls, 'EXACT_REDIRECT_ENDPOINT_CONTROL_REQUIRED')
    for query in spec.get('dns_queries', []):
        labels = query['name'].rstrip('.').split('.')
        need(0 < len(query['name']) <= 253 and all(0 < len(x) <= 63 and re.fullmatch(r'[A-Za-z0-9_-]+', x) for x in labels)
             and query['transport'] in ('udp', 'tcp') and query['type'] in ('A', 'AAAA'), 'DNS_CONTROL_FIELDS')
        endpoint(query['resolver'])


def load_fixture(case, descriptor, until, output):
    global MANAGEMENT, CONTROL, STORAGE, IPC, MANIFEST, CURRENT_FIXTURE, UID, GID, IMAGE, MODULE, GUEST_UID, GUEST_GID
    need(isinstance(descriptor, dict) and set(descriptor) == {'config', 'config_sha256'}, 'FIXTURE_DESCRIPTOR_FIELDS')
    path = canonical(descriptor['config'])
    config, raw = read_json(path)
    need(hashlib.sha256(raw).hexdigest() == descriptor['config_sha256'], 'FIXTURE_CONFIG_HASH_MISMATCH')
    need(config['schema_version'] == 2 and config['backends'] == {} and len(config['modules']) == 1 and
         config['limits'] == BASE_CONFIG['limits'] and config['resource_profiles'] == BASE_CONFIG['resource_profiles'],
         'FIXTURE_RESOURCE_OR_BACKEND_DRIFT')
    module, reference = config['modules'][0], BASE_CONFIG['modules'][0]
    need(all(module[k] == reference[k] for k in ('module_id', 'image', 'uid', 'gid', 'entrypoint', 'args'))
         and not module.get('credential_bindings'), 'FIXTURE_MODULE_IDENTITY_DRIFT')
    expected, _ = config_for(BASE_CONFIG, case)
    need(module['config'] == expected['modules'][0]['config'], 'FIXTURE_CASE_CONTROLS_MISMATCH')
    approval = module['approval']
    need(approval['resourceClass'] == reference['approval']['resourceClass'] and
         approval['resourceLimits'] == reference['approval']['resourceLimits'] and
         approval['egressPolicy'] == ('EGRESS_POLICY_PUBLIC_INTERNET' if is_public(case) else 'EGRESS_POLICY_NONE'),
         'FIXTURE_APPROVAL_MISMATCH')
    if is_public(case):
        need(any(x['name'] == 'core.network.public_egress' for x in approval['coreCapabilities']),
             'EXPLICIT_PUBLIC_APPROVAL_REQUIRED')
    host = config['host']
    need(ID.fullmatch(host['runtime_installation_id']), 'INSTALLATION_ID_FORMAT')
    MANAGEMENT, STORAGE, IPC = (canonical(host[k]) for k in ('management_directory', 'storage_root', 'ipc_root'))
    need(MANAGEMENT == STORAGE / 'app', 'CANONICAL_QUOTA_BACKED_APP_ROOT_REQUIRED')
    CONTROL = Path('/var/lib/chatanium/installations') / host['runtime_installation_id'] / 'control'
    CURRENT_FIXTURE = {'path': str(path), 'config': config, 'config_sha256': descriptor['config_sha256']}
    journal = Journal()
    try:
        markers = {r['key']: r['value'] for r in journal.rows('SELECT key,value FROM metadata', maximum=16)}
        need(markers.get('format') == 'chatanium-gvx' and markers.get('format_version') == markers.get('schema_version') == '1',
             'JOURNAL_FORMAT_MIGRATION_REQUIRED')
        rows = journal.rows('SELECT manifest FROM runtime_installations WHERE id=?', (host['runtime_installation_id'],), maximum=1)
        need(len(rows) == 1, 'INSTALLATION_RECORD_MISSING')
        MANIFEST = json.loads(rows[0]['manifest'])
        need(MANIFEST['state'] == 'READY' and MANIFEST['bundle_digest'] == host['bundle_digest'] and
             MANIFEST['paths']['config'] == str(path) and MANIFEST['paths']['launcher'] == str(RUNTIME) and
             MANIFEST['paths']['control'] == str(CONTROL) and MANIFEST['paths']['storage_root'] == str(STORAGE),
             'INSTALLED_APPROVAL_IDENTITY')
        budget = MANIFEST['budget']
        need(type(budget['app_bytes']) is int and type(budget['app_inodes']) is int and
             0 < budget['app_bytes'] <= budget['data_bytes'] and
             4 <= budget['app_inodes'] <= budget['data_inodes'], 'EXPLICIT_APP_DATA_SUBRESERVATION_REQUIRED')
        need(budget['app_bytes'] + RESOURCES['persistent_bytes'] + RESOURCES['scratch_bytes'] <= budget['data_bytes'] and
             budget['app_inodes'] + RESOURCES['persistent_inodes'] + RESOURCES['scratch_inodes'] <= budget['data_inodes'],
             'APP_AND_MODULE_DATA_BUDGET_OVERCOMMITTED')
        backing_bytes = sum(budget[key] for key in ('data_bytes', 'source_bytes', 'cache_bytes',
                                                   'preparation_bytes', 'metadata_headroom_bytes'))
        need(all(budget[key] > 0 for key in ('data_bytes', 'source_bytes', 'cache_bytes',
                                            'preparation_bytes', 'metadata_headroom_bytes')) and
             backing_bytes == MANIFEST['backing']['size_bytes'], 'APP_ALLOWANCE_MUST_NOT_ADD_BACKING_CAPACITY')
        CURRENT_FIXTURE['app_claim'] = native_app_claim(journal)
        rows = journal.rows('SELECT record FROM revisions WHERE id=?', (MANIFEST['active_revision'],), maximum=1)
        need(len(rows) == 1, 'ACTIVE_REVISION_MISSING')
        revision = json.loads(rows[0]['record'])
        need(revision['config_digest'] == 'sha256:' + descriptor['config_sha256'], 'ACTIVE_CONFIG_DIGEST_MISMATCH')
        import base64
        need(base64.b64decode(revision['config'], validate=True) == raw, 'ACTIVE_CONFIG_BYTES_MISMATCH')
        need(not journal.active(), 'FIXTURE_ACTIVE_OR_UNCERTAIN')
        # Fresh per-operation product identities prevent data/epoch/prefix reuse.
        need(not journal.rows('SELECT id FROM instances', maximum=1), 'FRESH_ISOLATED_FIXTURE_REQUIRED')
        UID, GID = MANIFEST['identities']['app']['uid'], MANIFEST['identities']['app']['gid']
        IMAGE, MODULE, GUEST_UID, GUEST_GID = module['image'], module['module_id'], module['uid'], module['gid']
        need(UID > 0 and GID > 0 and UID != GUEST_UID, 'DISTINCT_APP_GUEST_IDENTITIES')
        rc, checked, _ = command([str(CHECKER), 'sandbox', '--image-check-only', '--config', str(path),
                                  '--runtime', str(RUNTIME), '--deadline', '8s', '--observe', '1s'],
                                 until, output, cap=8192)
        need(rc == 0 and not checked.strip(), 'COMMITTED_CANONICAL_FIXTURE_CHECK_FAILED')
        return journal
    except BaseException:
        journal.db.close()
        raise


def main():
    global BASE, RUNTIME, IMAGE, MODULE, LIMITS, RESOURCES, PLAN, BASE_CONFIG, PUBLIC_CONFIG
    global CURRENT_CASE, ACTIVE_NETWORK_SPEC, CHECKER
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for name in ('plan', 'output', 'config', 'runtime', 'image-checker'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--overall-seconds', type=int, required=True)
    args = parser.parse_args()
    need(os.geteuid() == 0, 'ROOT_REQUIRED')
    need(180 <= args.overall_seconds <= 14400, 'FINITE_OVERALL_DEADLINE_REQUIRED')
    need(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'PIDFD_PYTHON_REQUIRED')
    os.umask(0o077)
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    started = time.monotonic()
    until = started + args.overall_seconds
    trusted(canonical(__file__))
    PLAN, _ = read_json(canonical(args.plan))
    need(set(PLAN) == {'schema_version', 'base_sha256', 'cases', 'controls', 'case_seconds',
                       'fixtures', 'network_cases', 'network_controls'} and PLAN['schema_version'] == 2,
         'STRICT_PLAN_V2_REQUIRED')
    selected = PLAN['cases']
    need(isinstance(selected, list) and selected and len(selected) <= len(CASES) and
         len(set(selected)) == len(selected) and all(c in CASES for c in selected), 'EXPLICIT_UNIQUE_CASES_REQUIRED')
    need(isinstance(PLAN['controls'], list) and 1 <= len(PLAN['controls']) <= 16, 'UNRELATED_CONTROLS_REQUIRED')
    need(set(PLAN['fixtures']) == set(selected), 'EXACT_SELECTED_FIXTURE_SET_REQUIRED')
    seconds = PLAN['case_seconds']
    need(type(seconds) is int and 180 <= seconds <= 300, 'FINITE_CASE_DEADLINE')
    BASE, RUNTIME, CHECKER = canonical(args.config), canonical(args.runtime), canonical(args.image_checker)
    for path in (RUNTIME, CHECKER, Path('/usr/bin/systemctl'), Path('/usr/sbin/ip'),
                 Path('/usr/sbin/iptables'), Path('/usr/sbin/ip6tables')):
        trusted(path)
    BASE_CONFIG, raw = read_json(BASE)
    need(hashlib.sha256(raw).hexdigest() == PLAN['base_sha256'], 'APPROVED_BASE_HASH_MISMATCH')
    validate_base(BASE_CONFIG)
    PUBLIC_CONFIG = BASE_CONFIG # Per-fixture PUBLIC approval is verified independently.
    reference = BASE_CONFIG['modules'][0]
    IMAGE, MODULE = reference['image'], reference['module_id']
    LIMITS = BASE_CONFIG['limits']
    approved = reference['approval']['resourceLimits']
    RESOURCES = {'nano_cpus': int(approved['cpuMillicores']) * 1000000, 'memory_bytes': int(approved['memoryBytes']),
                 'pids': int(approved['maxPids']), 'persistent_bytes': int(approved['persistentBytes']),
                 'scratch_bytes': int(approved['scratchBytes']), 'persistent_inodes': LIMITS['persistent_inode_limit'],
                 'scratch_inodes': LIMITS['scratch_inode_limit']}
    for key in ('control_message_max_bytes', 'log_buffer_bytes', 'log_file_max_bytes', 'log_retained_files'):
        RESOURCES[key] = LIMITS[key]
    outroot = canonical(args.output)
    trusted(outroot, directory=True, private=True)
    need(os.lstat(outroot).st_gid == 0, 'ROOT_PRIVATE_EVIDENCE_REQUIRED')
    lockfd = open_no_links(outroot / 'sandbox-policy.lock', os.O_RDWR | os.O_CREAT)
    st = os.fstat(lockfd)
    need(st.st_uid == 0 and st.st_nlink == 1 and not st.st_mode & 0o077, 'LOCK_IDENTITY')
    fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    output = outroot / ('sandbox-policy-' + uuid.uuid4().hex)
    os.mkdir(output, 0o700)
    summary = {'schema_version': 2, 'image': IMAGE, 'module_id': MODULE, 'selected_cases': selected,
               'base_sha256': PLAN['base_sha256'], 'cases': []}
    used = set()
    unsafe = False
    try:
        for case in selected:
            CURRENT_CASE = case
            specs = PLAN['network_cases'].get(case, [None]) if case in NETWORK_CASES else [None]
            specs = specs if isinstance(specs, list) else [specs]
            fixtures = PLAN['fixtures'][case]
            need(isinstance(fixtures, list) and 1 <= len(fixtures) == len(specs) <= 32, 'ONE_ISOLATED_FIXTURE_PER_OPERATION')
            jobs = []
            for index, (single, descriptor) in enumerate(zip(specs, fixtures)):
                artifact = case if len(specs) == 1 else case + '-' + str(index)
                journal = quotas = None
                if unsafe or INTERRUPTED or until - time.monotonic() < 180:
                    item = {'status': 'NOT_RUN', 'reason': 'PRIOR_UNCERTAINTY_OR_DEADLINE', 'artifact': artifact + '.json'}
                    private_json(output / (artifact + '.json'), item)
                    jobs.append(item)
                    continue
                ACTIVE_NETWORK_SPEC = single
                if case in NETWORK_CASES:
                    validate_network_spec(case, single)
                try:
                    journal = load_fixture(case, descriptor, until, output)
                    identity = MANIFEST['runtime_installation_id']
                    paths = {str(STORAGE), str(CONTROL), str(MANAGEMENT), MANIFEST['paths']['run_root'], MANIFEST['paths']['backing_file']}
                    need(identity not in used and not (paths & used), 'FIXTURE_INSTALLATION_PATH_REUSED')
                    used.add(identity)
                    used.update(paths)
                    quotas = Quotas()
                    observed = CaseRun(case, BASE_CONFIG, output, None, journal, quotas,
                                       min(until, time.monotonic() + seconds), artifact=artifact).run()
                    jobs.append({'status': observed['status'], 'reason': observed['verdict_reason'], 'artifact': artifact + '.json'})
                    unsafe = bool(observed.get('runtime_pid') and (not observed.get('cleanup_complete') or observed['status'] == 'FAIL'))
                finally:
                    # Quotas holds no mount descriptor between observations.
                    if journal:
                        journal.db.close()
            item = {'case': case, 'status': aggregate_status(jobs), 'jobs': jobs}
            summary['cases'].append(item)
            print(json.dumps(item, separators=(',', ':')), flush=True)
    except (Fault, OSError, ValueError, KeyError, TypeError, sqlite3.Error, subprocess.SubprocessError) as exc:
        summary['error'] = safe_errno(exc)
    finally:
        completed = {item['case'] for item in summary['cases']}
        for case in selected:
            if case not in completed:
                summary['cases'].append({'case': case, 'status': 'NOT_RUN', 'reason': 'OPERATOR_PREREQUISITE_OR_OBSERVATION_FAILURE'})
        os.close(lockfd)
        summary['elapsed_seconds'] = time.monotonic() - started
        summary['status'] = aggregate_status(summary['cases'])
        private_json(output / 'summary.json', summary)
        print(json.dumps({'scenario': 'sandbox.full_policy', 'status': summary['status'],
                          'scope': 'explicit_selected_cases_only', 'artifact_directory': str(output)}, separators=(',', ':')), flush=True)
    return 0 if summary['status'] == 'PASS' and not summary.get('error') else 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Fault, OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        print(json.dumps({'scenario': 'sandbox.full_policy', 'status': 'NOT_RUN', **safe_errno(exc)}, separators=(',', ':')), flush=True)
        sys.exit(2)
