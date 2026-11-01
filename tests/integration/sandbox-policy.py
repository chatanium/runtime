#!/usr/bin/env python3
"""Permanent, finite, root-side sandbox acceptance observer (Python 3.9+).

Run through the Go integration runner's sandbox --policy-plan path. Before any
case, its installed --image-check-only path compares the canonical embedded
manifest through the supervisor as the configured NON-root runtime UID/GID.
Install this source, Go runner, runtime, config and plan in root-owned,
non-writable paths. Never execute privileged code from a writable checkout.
No .tools import, evidence import, daemon cleanup or policy edit.

Plan JSON v1 fields (unknown fields rejected):
  schema_version: 1; base_sha256: approved base-config SHA256;
  runtime_uid/runtime_gid: non-root host runtime identity;
  docker: absolute trusted Docker CLI; config_directory: existing root-owned
  runtime-group-traversable directory (0750), for exclusive temporary configs;
  cases: explicit unique names from CASES; controls: exact unrelated container IDs;
  case_seconds: 180..300 (default 240); public_config: optional trusted config with
  SAME image/module/host/limits, explicitly approved PUBLIC_INTERNET grant;
  network_cases: map case -> fixture networkConfig OR list of networkConfigs.
  Exactly one TCP, DNS, HTTP or fresh-resolution operation per dedicated instance.
  network_controls[case]: 1..16 approved numeric TCP host:port controls. Redirect
  controls MUST include the exact owned denied second-hop endpoint and a public
  positive endpoint. DNS queries also receive an independent matching host query.
  network-redirect HTTP spec MUST set expected_redirect_url to the exact denied
  absolute numeric HTTP(S) URL, with explicit port and a "/" path if empty.
  Use ASCII URI spelling (percent-encode non-ASCII), no userinfo or fragment,
  canonical numeric host/port, and no empty trailing "?". Preserve escaped path
  and query spelling, including case/order. SHA-256 covers UTF-8 bytes of Go
  net/url serialization after fragment removal and empty-path-to-"/"; fixture
  validation requires expected_redirect_url to already have that spelling.
  Reports retain URL hashes only, never raw URLs, Location or HTTP error text.
  PUBLIC probes also require one fm-generation:<26 uppercase base32 characters>
  terminal-rule marker per enabled-family/table owned chain. Before USR1, bounded
  inspections require the owned bridge's sole owned host port and all available
  IPv6 addresses to have completed DAD, bookended by identical active policies.
  This is a start condition, not a promise of future quiet: any policy-generation
  change through the final counter snapshot remains INCONCLUSIVE.
  A generic raw protocol/port-53 DROP is attributable only to a completed sole
  unauthorized numeric DNS question, matching successful host control, ready
  owned topology, unchanged full generations/rules, and exactly one positive
  owned-rule delta with increased packet and byte counters. Shared/ambient
  traffic, zero counters, resets, or operation timeout alone are not proof.
  Missing ipv6-public / dns-rebinding infrastructure => NOT_RUN, never PASS.

CLI: --config ABS --runtime ABS --supervisor-socket ABS --supervisor-uid UID
 --supervisor-max-bytes N --plan ABS --output ABS --overall-seconds N --image-checker ABS
Output: private unique child under existing root:root 0700 evidence directory;
stdout contains sanitized per-case PASS/FAIL/INCONCLUSIVE/NOT_RUN and aggregate.
Each selected case must pass its own evidence AND terminal ownership cleanup,
zero shared quota usage, preserved persistent sentinel and unchanged controls.
CPU continuity is bounded to captured populated-cgroup samples: every readable
cpu.max quota/period must remain at or below approved CPU millicores. Missing
samples or teardown read errors are not successful continuity observations.
PUBLIC infrastructure and IPv6 routes/rebinding DNS are operator prerequisites;
this observer never provisions endpoints, routes, DNS, firewall or services.
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
DATA = MANAGEMENT = STORAGE = IPC = BASE = RUNTIME = DOCKER = IMAGE = MODULE = None
UID = GID = GUEST_UID = GUEST_GID = None
PROFILE = LIMITS = RESOURCES = PLAN = BASE_CONFIG = PUBLIC_CONFIG = None
SOCKET = SUPERVISOR_UID = SUPERVISOR_MAX_BYTES = CURRENT_CASE = None
ACTIVE_NETWORK_SPEC = None
NETWORK_CASES = ('network-none', 'network-public', 'network-dns', 'network-redirect', 'ipv6-public', 'dns-rebinding')
REPORT_LIMIT = 128 * 4096
ID = re.compile(r'[0-9a-f]{32}\Z')
CONTAINER_ID = re.compile(r'[0-9a-f]{64}\Z')
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
    s = {'kind': case, 'timeout_seconds': 25}
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
        c['modules'][0]['args'] = ['--fixture-ipc-component']
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
         re.fullmatch(r'.+@sha256:[0-9a-f]{64}', m['image']), 'CANONICAL_NONROOT_DIGEST_REQUIRED')
    need(m['approval']['egressPolicy'] == 'EGRESS_POLICY_NONE', 'NONE_BASE_APPROVAL_REQUIRED')
    need('scenario' not in m['config'] and 'lifecycle' not in m['config'], 'BASE_FIXTURE_CONTROLS_PRESENT')
    need(base['host']['quota_backend'] == 'xfs-project' and
         base['host']['docker_endpoint'].startswith('unix:///'), 'LOCAL_XFS_HOST_REQUIRED')



class Journal:
    def __init__(self):
        path = MANAGEMENT / 'supervisor.sqlite'
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
        return self.rows("SELECT id,epoch,state,cleanup FROM instances WHERE module_id=? AND cleanup!='COMPLETE'", (MODULE,))

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
        need(r['module_id'] == MODULE and ID.fullmatch(r['id']), 'INSTANCE_IDENTITY')
        o, s = lease['ownership'], lease['spec']
        need(o['instance_id'] == r['id'] == s['instance_id'] and o['epoch_id'] == e['id']
             and ID.fullmatch(o['installation_id']) and s['module_id'] == MODULE
             and s['image_digest'] == IMAGE and s['uid'] == GUEST_UID and s['gid'] == GUEST_GID,
             'LEASE_IDENTITY')
        paths = {'persistent_path': STORAGE / 'persistent' / o['installation_id'],
                 'scratch_path': STORAGE / 'instances' / r['id'] / 'scratch',
                 'ipc_path': IPC / r['id'], 'log_path': MANAGEMENT / 'logs' / r['id']}
        need(all(lease[k] == str(v) for k, v in paths.items()), 'LEASE_PATH_IDENTITY')
        need(not o['container_id'] or CONTAINER_ID.fullmatch(o['container_id']), 'CONTAINER_IDENTITY')
        expected = config_for(BASE_CONFIG, CURRENT_CASE)[0]['modules'][0]
        need(s['entrypoint'] == expected['entrypoint'] and (s['args'] or []) == (expected['args'] or [])
             and s['initial_egress'] == ('PUBLIC_INTERNET' if is_public(CURRENT_CASE) else 'NONE')
             and s['resources'] == RESOURCES, 'LEASE_PROFILE_MISMATCH')
        installation = self.installation()
        need(installation and installation['storage_key'] == o['installation_id']
             and installation['project'] == lease['persistent_project'], 'INSTALLATION_LEASE_MISMATCH')
        r['lease'] = lease
        r['claims'] = self.rows('SELECT kind,identity,state FROM resource_claims WHERE instance=? ORDER BY kind', (r['id'],))
        r['creates'] = self.rows('SELECT kind,identity,state,object_id FROM create_submissions WHERE instance=? ORDER BY kind', (r['id'],))
        return e, r


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
        self.fd = open_no_links(STORAGE, os.O_RDONLY | os.O_DIRECTORY)
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.syscall.restype = ctypes.c_long

    def read(self, project):
        d = DiskQuota(version=1, flags=2, id=project)
        # Linux x86_64 quotactl_fd(443), XFS Q_XGETQUOTA / PRJQUOTA; READ ONLY.
        rc = self.libc.syscall(ctypes.c_long(443), ctypes.c_int(self.fd),
                               ctypes.c_uint(((ord('X') << 8 | 3) << 8) | 2),
                               ctypes.c_uint(project), ctypes.byref(d))
        if rc != 0:
            return {'project': project, 'status': 'UNSUPPORTED', 'errno': ctypes.get_errno()}
        return {'project': project, 'status': 'MEASURED', 'bytes': d.blocks * 512,
                'inodes': d.inodes, 'hard_bytes': d.block_hard * 512, 'soft_bytes': d.block_soft * 512,
                'hard_inodes': d.inode_hard, 'soft_inodes': d.inode_soft,
                'realtime_bytes': d.rtblocks * 512}

    def close(self):
        os.close(self.fd)


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
                    if v.get('integration') == 'runtime-return-hold':
                        need(set(v) == {'integration', 'phase', 'pid', 'class', 'exit_code'}
                             and v['phase'] == 'returned' and v['pid'] == self.proc.pid
                             and v['class'] in ('ok', 'error') and v['exit_code'] == (0 if v['class'] == 'ok' else 1),
                             'INVALID_RUNTIME_RETURN_MARKER')
                        self.events.append(dict(v, observed_monotonic=time.monotonic()))
                        continue
                    if v.get('phase') == 'IPC_COMPONENT':
                        need(v.get('pid') == self.proc.pid and v.get('modules') == 1 and v.get('voice') is False
                             and ID.fullmatch(v.get('instance_id', '')) and ID.fullmatch(v.get('epoch_id', ''))
                             and ID.fullmatch(v.get('installation_id', ''))
                             and v.get('order') == ['captured', 'replacement-ack', 'held-dial-original', 'fresh-capture-rejected', 'complete-ack']
                             and v.get('original_reached') is True and v.get('fresh_capture_rejected') is True
                             and type(v.get('inode')) is int and v['inode'] > 0 and type(v.get('device')) is int,
                             'INVALID_IPC_COMPONENT_EVIDENCE')
                        self.events.append(dict(v, observed_monotonic=time.monotonic()))
                        continue
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


def command(argv, until, home, cap=262144, runtime_peer=False):
    """Bound both command time and captured bytes; never expose raw stderr."""
    check(until)
    stop = min(until, time.monotonic() + 5)
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': str(home), 'LANG': 'C',
           'DOCKER_HOST': BASE_CONFIG['host']['docker_endpoint'], 'DOCKER_CONFIG': str(home)}
    identity = {'user': UID, 'group': GID, 'extra_groups': []} if runtime_peer else {}
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


INSPECT = ('{"ID":{{json .Id}},"Image":{{json .Config.Image}},"User":{{json .Config.User}},'
           '"Labels":{{json .Config.Labels}},"HostConfig":{{json .HostConfig}},'
           '"Mounts":{{json .Mounts}},"State":{"Running":{{json .State.Running}},'
           '"OOMKilled":{{json .State.OOMKilled}},"ExitCode":{{json .State.ExitCode}},'
           '"Pid":{{json .State.Pid}}}}')


def docker_owned(row, until, home, inspect=True):
    o = row['lease']['ownership']
    cid = o['container_id']
    if not cid:
        return None
    labels = {'io.chatanium.flexmodule.owner': 'v2',
              'io.chatanium.flexmodule.installation': o['installation_id'],
              'io.chatanium.flexmodule.epoch': o['epoch_id'],
              'io.chatanium.flexmodule.instance': o['instance_id']}
    argv = [DOCKER, 'container', 'ls', '--all', '--no-trunc', '--filter', 'id=' + cid]
    for k, v in labels.items():
        argv += ['--filter', 'label=' + k + '=' + v]
    rc, raw, _ = command(argv + ['--format', '{{.ID}}'], until, home)
    need(rc == 0, 'DOCKER_OWNERSHIP_LIST_FAILED')
    listed = raw.decode('ascii').splitlines()
    need(not listed or listed == [cid], 'DOCKER_OWNERSHIP_LIST_MISMATCH')
    if not listed:
        # Label mismatch is not absence. Probe ID existence without inspecting it.
        rc, raw, _ = command([DOCKER, 'container', 'ls', '--all', '--no-trunc',
                             '--filter', 'id=' + cid, '--format', '{{.ID}}'], until, home)
        need(rc == 0 and not raw.strip(), 'UNLABELLED_OR_UNVERIFIABLE_CONTAINER_REMAINS')
        return None
    if not inspect:
        return {'ID': cid, 'labels_verified': True}
    rc, raw, _ = command([DOCKER, 'container', 'inspect', '--format', INSPECT, cid], until, home)
    if rc != 0:
        raise Fault('OWNED_INSPECT_RACED_OR_FAILED')
    info = json.loads(raw)
    need(info['ID'] == cid and info['Image'] == IMAGE and info['User'] == f'{GUEST_UID}:{GUEST_GID}'
         and all(info['Labels'].get(k) == v for k, v in labels.items()), 'DOCKER_METADATA_MISMATCH')
    return info


def container_exit_events(row, started_ns, until, home):
    """Read finite daemon history, including exits removed before inspect.

    Missing/evicted history is inconclusive, never an inferred exit. No live
    subscription or extra child survives the existing cumulative deadline.
    """
    o = row['lease']['ownership']
    cid = o['container_id']
    need(CONTAINER_ID.fullmatch(cid), 'EXIT_EVENT_CONTAINER_IDENTITY')
    ended_ns = time.time_ns()
    need(ended_ns >= started_ns, 'EXIT_EVENT_CLOCK_REVERSED')
    def timestamp(ns):
        return f'{ns // 1000000000}.{ns % 1000000000:09d}'
    rc, raw, discarded = command(
        [DOCKER, 'events', '--since', timestamp(started_ns), '--until', timestamp(ended_ns),
         '--filter', 'type=container', '--filter', 'container=' + cid,
         '--filter', 'event=die', '--format', '{{json .}}'], until, home, cap=32768)
    need(rc == 0, 'EXIT_EVENT_HISTORY_FAILED')
    labels = {'io.chatanium.flexmodule.owner': 'v2',
              'io.chatanium.flexmodule.installation': o['installation_id'],
              'io.chatanium.flexmodule.epoch': o['epoch_id'],
              'io.chatanium.flexmodule.instance': o['instance_id']}
    events = []
    for line in raw.splitlines():
        need(len(events) < 8 and len(line) <= 8192, 'EXIT_EVENT_BOUND')
        event = json.loads(line)
        actor = event['Actor']
        attrs = actor['Attributes']
        when = event['timeNano']
        need(event['Type'] == 'container' and event['Action'] == 'die' and actor['ID'] == cid
             and all(attrs.get(k) == v for k, v in labels.items())
             and type(when) is int and started_ns <= when <= ended_ns, 'EXIT_EVENT_OWNERSHIP')
        code = attrs.get('exitCode', '')
        need(isinstance(code, str) and re.fullmatch(r'[0-9]{1,3}', code)
             and 0 <= int(code) <= 255, 'EXIT_EVENT_CODE')
        events.append({'container_id': cid, 'time_ns': when, 'exit_code': int(code),
                       'ownership_verified': True})
    return {'events': events, 'stderr_bytes_discarded': discarded,
            'history_complete': False,
            'warning': 'Daemon history is finite; absence is not proof of no exit'}


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
         and fields.get('Groups') == [], 'RUNTIME_CREDENTIAL_MISMATCH')
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
        pid = info['State']['Pid']
        need(type(pid) is int and pid > 1 and info['State']['Running'], 'NO_LIVE_CGROUP_PID')
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
                         'container_id': info['ID'], 'container_pid': pid, 'proc_start_ticks': start}
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
        need(st.st_uid == GUEST_UID and st.st_gid == GUEST_GID and st.st_nlink == 1
             and st.st_mode & 0o077 == 0, 'FIXTURE_REPORT_IDENTITY')
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


def reclaim_persistent(path, new_names, until):
    """No recursive blanket removal: exact new fixture dirs and known leaf names."""
    removed = []
    root = open_no_links(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in sorted(new_names):
            check(until)
            if not QUOTA_NAME.fullmatch(name):
                continue
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
            try:
                st = os.fstat(fd)
                need(st.st_uid == GUEST_UID and st.st_gid == GUEST_GID and st.st_dev == os.fstat(root).st_dev,
                     'RECLAIM_DIRECTORY_IDENTITY')
                count = 0
                # Validate each exact leaf; no symlinks, directories, or foreign names.
                with os.scandir(fd) as entries:
                    for entry in entries:
                        check(until)
                        count += 1
                        need(count <= 65540 and QUOTA_FILE.fullmatch(entry.name), 'RECLAIM_LEAF_BOUND')
                        leaf = entry.stat(follow_symlinks=False)
                        need(stat.S_ISREG(leaf.st_mode) and leaf.st_uid == GUEST_UID
                             and leaf.st_gid == GUEST_GID and leaf.st_dev == st.st_dev, 'RECLAIM_LEAF_IDENTITY')
                        os.unlink(entry.name, dir_fd=fd)
                removed.append({'directory': name, 'leaf_files': count, 'inode': st.st_ino})
            finally:
                os.close(fd)
            os.rmdir(name, dir_fd=root)
    finally:
        os.close(root)
    return removed


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
            and identity.get('process_pidfd_identity', {}).get('Pid') == [identity.get('container_pid')]
            and CONTAINER_ID.fullmatch(identity.get('container_id', ''))
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
    unavailable = [q[k] for q in quota_samples for k in ('persistent', 'scratch')
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
    add('signal_gate', 'OBSERVED' if triggered else ('NOT_APPLICABLE' if result.get('scenario') is None or case in ('runtime-sigkill', 'ipc-race') else 'INCONCLUSIVE'),
        triggered_record=triggered, usr1_sent=result.get('usr1_sent', False))
    if case == 'cpu':
        usage, throttles, throttled = delta('cpu.stat', 'usage_usec'), delta('cpu.stat', 'nr_throttled'), delta('cpu.stat', 'throttled_usec')
        elapsed = (samples[-1]['observed_monotonic'] - first['observed_monotonic']) if samples else None
        add('real_cgroup_cpu_accounting', 'OBSERVED' if triggered and usage and throttles and throttled else 'INCONCLUSIVE',
            usage_usec_delta=usage, nr_throttled_delta=throttles, throttled_usec_delta=throttled,
            sampled_seconds=elapsed, average_cpu_cores=(usage / 1000000 / elapsed if usage is not None and elapsed and elapsed > 0 else None))
    elif case == 'memory-oom':
        oom, killed = delta('memory.events', 'oom'), delta('memory.events', 'oom_kill')
        exits = [x['State'] for x in result.get('container_observations', []) if not x['State']['Running']]
        add('real_cgroup_memory_events', 'OBSERVED' if triggered and ((oom or 0) > 0 or (killed or 0) > 0) else 'INCONCLUSIVE',
            oom_delta=oom, oom_kill_delta=killed, max_delta=delta('memory.events', 'max'), observed_exits=exits)
    elif case in ('fork', 'thread'):
        failures = [r for r in records if r.get('errno') in (errno.EAGAIN, errno.ENOMEM)]
        diagnostic = result.get('thread_diagnostic', {})
        fatal_exhaustion = (diagnostic.get('fatal_newosproc') is True
                            and diagnostic.get('errno') in (errno.EAGAIN, errno.ENOMEM))
        add('guest_task_exhaustion', 'OBSERVED' if triggered and (failures or fatal_exhaustion or (delta('pids.events', 'max') or 0) > 0) else 'INCONCLUSIVE',
            pids_max_events_delta=delta('pids.events', 'max'), guest_failure_records=failures,
            peak_tasks=max([s.get('pids.current', 0) for s in samples] or [0]),
            thread_diagnostic=diagnostic,
            warning='Host tasks are not guest threads under runsc; missing/truncated fatal diagnostics remain inconclusive')
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
            log_snapshots=snapshots, warning='Broker stream writes do not exercise Docker attach; retention alone is not rotation proof')
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
        exits = [x['State'] for x in result.get('container_observations', []) if not x['State']['Running']]
        events = result.get('container_exit_history', {}).get('events', [])
        exact_exit = any(x['ExitCode'] == 86 for x in exits) or any(x['exit_code'] == 86 for x in events)
        add('module_crash', 'OBSERVED' if ('crash', 'intentional-exit-86-next') in states and exact_exit else 'INCONCLUSIVE',
            expected_exit=86, exact_exit_observed=exact_exit, container_states=exits, exit_events=events,
            warning='Intent alone is not exact exit proof; absent inspect/history remains inconclusive')
    elif case == 'runtime-sigkill':
        add('exact_runtime_sigkill_reaper', 'OBSERVED' if result.get('runtime_sigkill_sent') and result.get('runtime_returncode') == -9
            and (result.get('final_epoch') or {}).get('state') == 'DEAD' and result.get('cleanup_complete') else 'INCONCLUSIVE',
            runtime_returncode=result.get('runtime_returncode'), epoch_state=(result.get('final_epoch') or {}).get('state'))
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
        self.result = {'case': name, 'status': 'INCONCLUSIVE', 'journal_transitions': [],
                       'container_observations': [], 'cgroup_samples': [], 'quota_samples': [],
                       'quota_high_water': {}, 'log_snapshots': [], 'errors': []}

    def observe(self, until, sample=True):
        check(until)
        if self.reader:
            self.reader.pump(0)
        epoch, row = self.journal.owned(self.proc.pid, self.started_wall,
                                        self.epoch['id'] if self.epoch else None)
        if epoch:
            self.correlate_epoch(epoch)
            self.epoch = epoch
        if row:
            self.row = row
            if self.previous_row != row:
                self.result['journal_transitions'].append({'observed_monotonic': time.monotonic(),
                    'host_phase': 'cleanup' if row['cleanup'] != 'PENDING' or row['state'] in ('FAILED', 'STOPPED') else
                        ('running-correlated' if self.reader.running() and row['state'] == 'STARTED' else 'provisional'),
                    'row': copy.deepcopy(row)})
                self.previous_row = copy.deepcopy(row)
            if self.persistent is None:
                self.persistent = Path(row['lease']['persistent_path'])
                # Pre-launch installation snapshots exist for the real reused lab module.
                if not self.result.get('installation_before'):
                    self.baseline_names = set()
            if sample:
                self.sample_quota(row)
        if self.cg and sample:
            samples = self.result['cgroup_samples']
            if len(samples) < 3400:
                samples.append(self.cg.read())
        return row

    def sample_quota(self, row):
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
        if len(previous) < 800:
            previous.append(values)

    def correlate_epoch(self, epoch, require_live=False):
        need(epoch is not None and self.boot_id is not None and self.initial_pidfd_identity is not None,
             'EPOCH_PIDFD_PREREQUISITE_MISSING')
        need(epoch['boot_id'] == self.boot_id, 'EPOCH_BOOT_IDENTITY_MISMATCH')
        # Supervisor journals fdinfo from a duplicate of the runtime's self-pidfd.
        # Our independently opened pidfd must describe that same live process.
        # Pid/NSpid are comparable in the shared host PID namespace; pos/flags
        # describe different open descriptions. ino/mnt_id are not treated as
        # cross-open process identities on this lab's pre-pidfs Linux kernel.
        saved = pidfd_identity(epoch['start_identity'])
        need(saved == self.initial_pidfd_identity and saved['Pid'] == [self.proc.pid],
             'EPOCH_HELD_PIDFD_IDENTITY_MISMATCH')
        if require_live:
            need(epoch['state'] == 'LIVE' and self.proc.poll() is None
                 and self.pidfd is not None and boot_identity() == self.boot_id,
                 'EPOCH_NOT_LIVE_FOR_CONTROL')
            need(held_pidfd_identity(self.pidfd) == self.initial_pidfd_identity
                 and proc_start(self.proc.pid) == self.result['runtime_proc_start_ticks'],
                 'HELD_PIDFD_PROCESS_IDENTITY_CHANGED')
        self.result.setdefault('epoch_pidfd_correlation', {
            'epoch_id': epoch['id'], 'boot_id': self.boot_id,
            'durable_pidfd_identity': saved,
            'held_pidfd_identity_at_launch': self.initial_pidfd_identity,
            'proc_start_ticks': self.result['runtime_proc_start_ticks']})
        if require_live:
            self.result['last_live_epoch_pidfd_check_monotonic'] = time.monotonic()

    def inspect(self, until):
        row = self.observe(until, False)
        if not row:
            return None
        info = docker_owned(row, until, self.output)
        if info:
            observations = self.result['container_observations']
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
                self.baseline_names = scan_names(self.persistent, self.work_until)
                r['sentinel_before'] = sentinel(self.persistent)
                need(not r['sentinel_before']['exists'] or r['sentinel_before'].get('valid'), 'EXISTING_SENTINEL_INVALID')
            config, scenario = config_for(self.base, self.name)
            r['scenario'] = scenario
            r['lifecycle'] = config['modules'][0]['config']['lifecycle']
            r['original_resource_profile'] = self.base['resource_profiles']
            r['original_limits'] = self.base['limits']
            self.config_path = self.configs / (self.artifact + '.json')
            private_json(self.config_path, config)
            os.chown(self.config_path, 0, GID)
            os.chmod(self.config_path, 0o640)
            config_raw, _ = bounded_read(self.config_path, 262144)
            r['config_sha256'] = hashlib.sha256(config_raw).hexdigest()
            check(self.work_until)
            need(not INTERRUPTED, 'INTERRUPTED_BEFORE_LAUNCH')
            self.started_wall, self.started_mono = time.time_ns(), time.monotonic()
            argv = [str(RUNTIME), 'start', '--config', str(self.config_path),
                    '--supervisor-socket', str(SOCKET), '--supervisor-uid', str(SUPERVISOR_UID),
                    '--supervisor-max-bytes', str(SUPERVISOR_MAX_BYTES), '--duration', ('8s' if self.name == 'normal-exit' else str(int(self.work_until - self.started_mono)) + 's')]
            if self.name == 'cleanup-crash':
                argv = [str(RETURN_HOLDER), '--integration-runtime-return-hold', '60', '--'] + argv[1:]
            elif self.name == 'ipc-race':
                argv = [str(IPC_DRIVER), 'sandbox', '--ipc-component-only', '--config', str(self.config_path),
                        '--runtime', str(RUNTIME), '--supervisor-socket', str(SOCKET),
                        '--supervisor-uid', str(SUPERVISOR_UID), '--supervisor-max-bytes', str(SUPERVISOR_MAX_BYTES),
                        '--deadline', str(int(self.work_until - self.started_mono)) + 's', '--observe', '1s']
            self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE if self.name == 'ipc-race' else subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'HOME': '/nonexistent'},
                cwd='/', user=UID, group=GID, extra_groups=[], start_new_session=True, close_fds=True)
            self.reader = RuntimeOutput(self.proc)
            r['runtime_pid'] = self.proc.pid
            self.pidfd = os.pidfd_open(self.proc.pid)
            self.boot_id = boot_identity()
            self.initial_pidfd_identity = held_pidfd_identity(self.pidfd)
            need(self.initial_pidfd_identity['Pid'] == [self.proc.pid], 'INITIAL_HELD_PIDFD_IDENTITY_MISMATCH')
            r['runtime_boot_id'] = self.boot_id
            r['runtime_pidfd_identity'] = self.initial_pidfd_identity
            r['runtime_proc_start_ticks'] = proc_start(self.proc.pid)
            r['runtime_identity'] = runtime_identity(self.proc.pid)
            startup_until = min(self.work_until, self.started_mono + 65)
            while time.monotonic() < startup_until:
                self.reader.pump()
                row = self.observe(startup_until)
                if self.reader.running():
                    r['running_seen'] = True
                    break
                if self.proc.poll() is not None or (row and (row['state'] == 'FAILED' or row['cleanup'] == 'COMPLETE')) or INTERRUPTED:
                    break
            r.setdefault('running_seen', False)
            if scenario is None:
                # Expected failed instance: do not wait for runtime-wide process exit.
                need(not r['running_seen'], 'UNEXPECTED_RUNNING_FOR_STARTUP_FAILURE')
                need(self.row is not None, 'NO_DURABLE_INSTANCE')
            else:
                need(r['running_seen'], 'NO_RUNTIME_RUNNING_OBSERVATION')
                info = self.inspect(self.work_until)
                need(info and info['State']['Running'] and self.row['state'] == 'STARTED'
                     and self.row['cleanup'] == 'PENDING', 'NO_OWNED_RUNNING_CONTAINER')
                h = info['HostConfig']
                need(h.get('NanoCpus') == RESOURCES['nano_cpus'] and h.get('Memory') == RESOURCES['memory_bytes']
                     and h.get('MemorySwap') == RESOURCES['memory_bytes'] and h.get('PidsLimit') == RESOURCES['pids']
                     and h.get('Runtime') == self.base['host']['runsc_runtime_name']
                     and h.get('ReadonlyRootfs') is True and ((h.get('NetworkMode') == 'none') == (not is_public(self.name)))
                     and h.get('IpcMode') == 'none' and h.get('CgroupnsMode') == 'private'
                     and h.get('CapDrop') == ['ALL']
                     and bool({'no-new-privileges=true', 'no-new-privileges'} & set(h.get('SecurityOpt') or []))
                     and h.get('Ulimits') == [{'Name': 'nproc', 'Hard': RESOURCES['pids'], 'Soft': RESOURCES['pids']}], 'HOSTCONFIG_LIMIT_MISMATCH')
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
                need(h.get('LogConfig', {}).get('Type') == 'none', 'DAEMON_LOG_COPY_ENABLED')
                if self.name == 'runtime-sigkill':
                    # PIDFD pins exactly our child. No supervisor/group/name signals.
                    self.correlate_epoch(self.epoch, require_live=True)
                    r['runtime_sigkill_sent'] = self.signal_runtime(signal.SIGKILL)
                elif self.name == 'ipc-race':
                    self.correlate_epoch(self.epoch, require_live=True)
                    self.proc.stdin.write(b'exercise\n')
                    self.proc.stdin.flush()
                    self.proc.stdin.close()
                else:
                    # Fresh durable identity and matching list/inspect labels before the sole mutation.
                    latest = self.inspect(self.work_until)
                    need(latest and latest['State']['Running'] and self.row['cleanup'] == 'PENDING'
                         and self.row['state'] == 'STARTED', 'SIGNAL_OWNERSHIP_CHANGED')
                    cid = self.row['lease']['ownership']['container_id']
                    if self.name == 'thread':
                        self.pin_thread_log()
                    self.correlate_epoch(self.epoch, require_live=True)
                    rc, _, discarded = command([DOCKER, 'kill', '--signal=USR1', cid], self.work_until, self.output)
                    r['usr1_sent'] = rc == 0
                    r['signal_stderr_bytes_discarded'] = discarded
                    need(rc == 0, 'USR1_SIGNAL_FAILED_NO_RETRY')
                triggered_at = time.monotonic()
                workload_until = min(self.work_until, triggered_at + scenario['timeout_seconds'] + 12)
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
                        names = scan_names(self.persistent, workload_until) - self.baseline_names
                        records, _ = fixture_records(self.persistent, names, workload_until)
                        if any(x['state'] == 'returned-not-policy-proof' for x in records):
                            done_seen = done_seen or now
                        next_report = now + 0.5
                        if self.name == 'ipc-race':
                            component = [x for x in self.reader.events if x['phase'] == 'IPC_COMPONENT']
                            if component:
                                need(len(component) == 1 and component[0]['pid'] == self.proc.pid
                                     and component[0]['instance_id'] == self.row['id'] and component[0]['epoch_id'] == self.epoch['id']
                                     and component[0]['installation_id'] == self.row['lease']['ownership']['installation_id'],
                                     'IPC_COMPONENT_LEASE_IDENTITY_MISMATCH')
                                r['ipc_component'] = component[0]
                                self.correlate_ipc_component(component[0])
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
                    if now >= next_inspect and self.row and self.row['lease']['ownership']['container_id']:
                        try:
                            self.inspect(workload_until)
                        except Fault as exc:
                            if exc.code != 'OWNED_INSPECT_RACED_OR_FAILED':
                                raise
                            r['errors'].append(safe_errno(exc))
                        if self.name == 'flood':
                            r['log_snapshots'].append(log_snapshot(Path(self.row['lease']['log_path']), workload_until))
                        next_inspect = now + 2
                    if done_seen and now - done_seen >= 0.6 and (self.name != 'ipc-race' or r.get('ipc_component')):
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
            violations = {'HOSTCONFIG_LIMIT_MISMATCH', 'CGROUP_EFFECTIVE_LIMIT_MISMATCH', 'CGROUP_CPU_LIMIT_MISMATCH',
                          'LOG_RETENTION_BOUND_EXCEEDED', 'DAEMON_LOG_COPY_ENABLED',
                          'PROJECT_ASSIGNMENT_OR_INHERITANCE_MISMATCH', 'SHARED_IPC_PROJECT_MISMATCH',
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
                    if self.name in ('thread', 'module-crash') and self.row:
                        r['container_exit_history'] = container_exit_events(
                            self.row, self.started_wall, self.until, self.output)
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
                if self.cg:
                    self.cg.close()
                if self.config_path and self.config_path.exists():
                    self.config_path.unlink()  # Only the exact root-created input; not module data.
            if self.persistent and self.row:
                try:
                    records = self.archive_and_reclaim()
                except (Fault, OSError, ValueError, KeyError, TypeError) as exc:
                    r['errors'].append(safe_errno(exc))
                    r['status'] = 'FAIL'
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
            r['assessments'] = assessment(self.name, r, records)
            if any(x['status'] in ('INCONCLUSIVE', 'UNSUPPORTED') for x in r['assessments']) and r['status'] == 'OBSERVED':
                r['status'] = 'INCONCLUSIVE'
            r['status'], r['verdict_reason'] = verdict(self.name, r, records)
            if isinstance(r.get('scenario'), dict) and 'network' in r['scenario']:
                r['scenario']['network'] = {'expected_egress': r['scenario']['network']['expected_egress'], 'details': 'trusted_operator_plan_not_copied_to_report'}
            private_json(self.output / (self.artifact + '.json'), r)
        return r

    def correlate_ipc_component(self, component):
        root = Path(self.row['lease']['ipc_path'])
        directories = [x for x in scan_names(root, self.work_until, 16) if re.fullmatch(r'plugin-dir[0-9]+', x)]
        need(len(directories) == 1, 'IPC_COMPONENT_DIRECTORY_IDENTITY')
        directory = root / directories[0]
        original = directory / 'original'
        retained = os.lstat(directory / 'original.retained')
        outside = os.lstat(Path(self.row['lease']['scratch_path']) / 'outside')
        need(stat.S_ISLNK(os.lstat(original).st_mode)
             and os.readlink(original) == str(Path(self.row['lease']['scratch_path']) / 'outside')
             and stat.S_ISSOCK(retained.st_mode) and stat.S_ISSOCK(outside.st_mode)
             and retained.st_dev == component['device'] and retained.st_ino == component['inode']
             and (retained.st_dev, retained.st_ino) != (outside.st_dev, outside.st_ino)
             and retained.st_uid == outside.st_uid == GUEST_UID and retained.st_gid == self.row['lease']['socket_gid']
             and stat.S_IMODE(retained.st_mode) == 0o660, 'IPC_COMPONENT_PHYSICAL_IDENTITY_MISMATCH')
        self.result['ipc_component_host_identity'] = {'device': retained.st_dev, 'inode': retained.st_ino,
            'outside_device': outside.st_dev, 'outside_inode': outside.st_ino, 'replacement_symlink_verified': True}

    def pin_cleanup_allocation(self, records):
        allocations = [x['data'] for x in records if x['probe'] == 'quota'
                       and x['state'] == 'allocation-returned-not-project-accounting'
                       and x.get('outcome') == 'syscall-or-operation-returned'
                       and x.get('data', {}).get('target') == 'ipc']
        need(len(allocations) == 1 and self.held_allocation is None, 'ONE_EXACT_OWNED_ALLOCATION_REQUIRED')
        guest = canonical(allocations[0]['owned_directory'])
        parts = guest.parts
        need(len(parts) == 6 and parts[:4] == ('/', 'run', 'flexmodule', 'ipc')
             and re.fullmatch(r'plugin-dir[0-9]+', parts[4]) and QUOTA_NAME.fullmatch(parts[5]) is not None,
             'OWNED_IPC_ALLOCATION_PATH_INVALID')
        # Convert only the known guest mount suffix into this exact lease.
        host = Path(self.row['lease']['ipc_path']) / parts[4] / parts[5] / 'allocation'
        fd = open_no_links(host)
        try:
            st = os.fstat(fd)
            need(stat.S_ISREG(st.st_mode) and st.st_uid == GUEST_UID and st.st_gid == GUEST_GID
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
        if INTERRUPTED:
            self.until = min(self.until, time.monotonic() + 65)
        # Preserve one finite shutdown window, then let the independent supervisor reap.
        if self.proc.poll() is None and self.name not in ('runtime-sigkill', 'normal-exit'):
            self.correlate_epoch(self.epoch, require_live=True)
            self.signal_runtime(signal.SIGINT if self.name == 'sigint' else signal.SIGTERM)
        graceful_until = min(self.until - 30, time.monotonic() + (60 if self.name == 'cleanup-crash' else 35))
        while self.proc.poll() is None and time.monotonic() < graceful_until:
            self.reader.pump(0.05)
            row = self.observe(graceful_until)
            # runCLI must have returned while this exact runtime PID is alive.
            # A held unlinked inode is the allocation; its pathname may be gone.
            returned = [x for x in self.reader.events if x['phase'] == 'returned']
            if self.name == 'cleanup-crash' and returned and self.held_allocation is not None and row:
                self.correlate_epoch(self.epoch, require_live=True)
                held = os.fstat(self.held_allocation)
                claims = {x['kind']: x['state'] for x in row['claims']}
                quota = self.quotas.read(row['lease']['scratch_project'])
                need(len(returned) == 1 and returned[0]['pid'] == self.proc.pid, 'RETURN_HOLD_IDENTITY_MISMATCH')
                need(row['cleanup'] != 'COMPLETE' and {'scratch', 'ipc'} <= claims.keys()
                     and claims['scratch'] != 'RELEASED' and claims['ipc'] != 'RELEASED'
                     and quota.get('status') == 'MEASURED' and quota.get('bytes', 0) >= 1 << 20
                     and held.st_nlink == 0 and held.st_blocks * 512 >= 1 << 20,
                     'RETURNED_RUNTIME_RETAINED_ALLOCATION_NOT_WITNESSED')
                reused = self.journal.rows("SELECT instance FROM resource_claims WHERE kind='scratch' AND identity=? AND instance!=? AND state!='RELEASED'",
                                           (str(row['lease']['scratch_project']), row['id']), maximum=1)
                need(not reused, 'HELD_IPC_PROJECT_REUSED')
                info = docker_owned(row, graceful_until, self.output, inspect=False)
                need(info is None, 'RETURNED_RUNTIME_CONTAINER_REMAINS')
                self.result['cleanup_crash_witness'] = {'state': row['cleanup'], 'instance': row['id'],
                    'returned': returned[0], 'claims': claims, 'quota': quota, 'device': held.st_dev,
                    'inode': held.st_ino, 'links': held.st_nlink, 'allocated_bytes': held.st_blocks * 512,
                    'owned_container_absent': True}
                self.result['cleanup_crash_sigkill_sent'] = self.signal_runtime(signal.SIGKILL)
                break
        if self.proc.poll() is None:
            self.result['cleanup_runtime_sigkill_sent'] = self.signal_runtime(signal.SIGKILL)
        self.proc.wait(timeout=min(2, max(0.01, self.until - time.monotonic())))
        if self.held_allocation is not None:
            os.close(self.held_allocation)
            self.held_allocation = None
        while time.monotonic() < self.until - 5:
            self.reader.pump(0.05)
            row = self.observe(self.until - 5)
            if row and row['cleanup'] == 'COMPLETE' and (self.name not in ('runtime-sigkill', 'cleanup-crash') or self.epoch['state'] == 'DEAD'):
                break
            if row is None and self.epoch is None:
                break
        self.result['final_epoch'] = self.epoch
        self.result['final_instance'] = self.row
        complete = bool(self.row and self.row['cleanup'] == 'COMPLETE')
        self.result['cleanup_complete'] = complete
        need(complete, 'DURABLE_CLEANUP_NOT_COMPLETE')
        lease = self.row['lease']
        info = docker_owned(self.row, self.until, self.output, inspect=False)
        self.result['owned_container_absent'] = info is None
        need(info is None, 'OWNED_CONTAINER_STILL_PRESENT')
        if is_public(self.name):
            owned_network_absent(self.row, self.network_before, self.until, self.output)
            self.result['owned_network_absent'] = True
        paths = {'scratch_instance': str(Path(lease['scratch_path']).parent), 'ipc': lease['ipc_path'], 'logs': lease['log_path']}
        self.result['final_path_absence'] = {k: not os.path.lexists(v) for k, v in paths.items()}
        need(all(self.result['final_path_absence'].values()), 'EPHEMERAL_PATH_REMAINS')
        claims = self.row['claims']
        need({x['kind'] for x in claims} == {'persistent', 'scratch', 'ipc', 'container', 'network', 'logs'}, 'CLAIM_SET_INCOMPLETE')
        need(all(x['state'] == ('RETAINED' if x['kind'] == 'persistent' else 'RELEASED') for x in claims), 'CLAIM_RELEASE_INCOMPLETE')
        self.result['final_quotas'] = {k: self.quotas.read(lease[k + '_project']) for k in ('persistent', 'scratch')}
        scratch = self.result['final_quotas']['scratch']
        if scratch['status'] == 'MEASURED':
            need(scratch['bytes'] == scratch['inodes'] == scratch['realtime_bytes'] == 0, 'SCRATCH_QUOTA_USAGE_REMAINS')
        else:
            self.result['status'] = 'INCONCLUSIVE'

    def archive_and_reclaim(self):
        # Archive bounded diagnostics even on failed cleanup. Reclamation requires
        # all terminal ownership fences below; it never repairs a live instance.
        names = scan_names(self.persistent, self.until) - self.baseline_names
        archive = self.output / (self.artifact + '-fixture')
        os.mkdir(archive, 0o700)
        records, reports = fixture_records(self.persistent, names, self.until, archive)
        self.result['fixture_reports'] = reports
        self.result['fixture_records'] = records
        terminal = (self.result.get('cleanup_complete') and self.result.get('owned_container_absent')
                    and all(self.result.get('final_path_absence', {}).values())
                    and not self.journal.active())
        if not terminal:
            self.result['persistent_reclamation_status'] = 'NOT_RUN_NONTERMINAL_OWNER'
            return records
        self.result['persistent_reclamation_status'] = 'TERMINAL_OWNER_VERIFIED'
        self.result['persistent_owned_reclamation'] = reclaim_persistent(self.persistent, names, self.until)
        self.result['sentinel_after'] = sentinel(self.persistent)
        before = self.result.get('sentinel_before', self.result.get('sentinel_running', {}))
        after = self.result['sentinel_after']
        if before.get('exists'):
            need(after.get('valid') and all(before.get(k) == after.get(k) for k in ('device', 'inode', 'sha256')),
                 'SENTINEL_CHANGED')
        else:
            need(after.get('valid') or (self.name == 'init-failure' and not after['exists']),
                 'SENTINEL_NOT_CREATED_BY_BASELINE')
        removed_reports = []
        for report in reports:
            check(self.until)
            name = report['name']
            raw, st = bounded_read(self.persistent / name, REPORT_LIMIT)
            need(st.st_ino == report['inode'] and hashlib.sha256(raw).hexdigest() == report['sha256'], 'REPORT_CHANGED_AFTER_ARCHIVE')
            os.unlink(self.persistent / name)
            removed_reports.append(name)
        self.result['archived_then_reclaimed_reports'] = removed_reports
        remaining = scan_names(self.persistent, self.until) - self.baseline_names - {'probe-state'}
        self.result['persistent_new_names_remaining'] = sorted(remaining)
        need(not remaining, 'PROBE_OWNED_PERSISTENT_FILES_REMAIN')
        self.result['persistent_quota_after_probe_reclamation'] = self.quotas.read(self.row['lease']['persistent_project'])
        if not reports:
            self.result['status'] = 'INCONCLUSIVE'
        return records

def owned_network_absent(row, before, until, home):
    o = row['lease']['ownership']
    argv = [DOCKER, 'network', 'ls', '--no-trunc']
    for key, value in {'owner': 'v2', 'installation': o['installation_id'], 'epoch': o['epoch_id'], 'instance': o['instance_id']}.items():
        argv += ['--filter', 'label=io.chatanium.flexmodule.' + key + '=' + value]
    rc, raw, _ = command(argv + ['--format', '{{.ID}}'], until, home, 8192)
    need(rc == 0 and not raw.strip(), 'OWNED_NETWORK_REMAINS_OR_UNVERIFIABLE')
    known = {x['object_id'] for x in row['creates'] if x['kind'] == 'network' and x['object_id']}
    if before and before.get('network_id'):
        known.add(before['network_id'])
    need(len(known) <= 1, 'AMBIGUOUS_OWNED_NETWORK')
    for nid in known:
        need(CONTAINER_ID.fullmatch(nid), 'EXACT_NETWORK_ID_REQUIRED')
        rc, raw, _ = command([DOCKER, 'network', 'ls', '--no-trunc', '--filter', 'id=' + nid, '--format', '{{.ID}}'], until, home, 8192)
        need(rc == 0 and not raw.strip(), 'RELABELLED_OR_REMAINING_NETWORK')




def controls_snapshot(until, home):
    out = []
    for cid in PLAN['controls']:
        need(CONTAINER_ID.fullmatch(cid), 'EXACT_CONTROL_CONTAINER_REQUIRED')
        rc, raw, _ = command([DOCKER, 'container', 'inspect', '--format',
            '{"id":{{json .Id}},"image":{{json .Image}},"pid":{{json .State.Pid}},"running":{{json .State.Running}},"started":{{json .State.StartedAt}},"labels":{{json .Config.Labels}}}', cid], until, home, 16384)
        need(rc == 0, 'CONTROL_UNAVAILABLE')
        info = json.loads(raw)
        need(info['id'] == cid and info['running'] and info['pid'] > 1 and
             (info.get('labels') or {}).get('io.chatanium.flexmodule.instance') !=
             (globals().get('CURRENT_INSTANCE') or ''), 'LIVE_UNRELATED_CONTROL_REQUIRED')
        # Retain no arbitrary workload labels, names, env, args or logs.
        out.append({k: info[k] for k in ('id', 'image', 'pid', 'running', 'started')})
    return out


def project_identity(row):
    out = {}
    lease = row['lease']
    for kind in ('persistent', 'scratch', 'ipc'):
        fd = open_no_links(Path(lease[kind + '_path']), os.O_RDONLY | os.O_DIRECTORY)
        try:
            value = bytearray(28)
            fcntl.ioctl(fd, 0x801c581f, value, True)  # FS_IOC_FSGETXATTR, read-only.
            flags, _, _, project, _, _ = struct.unpack('=IIIII8s', value)
            out[kind] = {'device': os.fstat(fd).st_dev, 'project': project, 'inherit': bool(flags & 0x200)}
            expected = lease['persistent_project' if kind == 'persistent' else 'scratch_project']
            need(project == expected and flags & 0x200, 'PROJECT_ASSIGNMENT_OR_INHERITANCE_MISMATCH')
        finally:
            os.close(fd)
    need(out['scratch']['device'] == out['ipc']['device'] and out['scratch']['project'] == out['ipc']['project']
         and out['persistent']['project'] != out['scratch']['project'], 'SHARED_IPC_PROJECT_MISMATCH')
    return out


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


def owned_network_coordinates(row, info):
    o = row['lease']['ownership']
    digest = hashlib.sha256(('\0'.join(o[k] for k in ('installation_id', 'epoch_id', 'instance_id'))).encode()).hexdigest()
    networks = [x for x in row['creates'] if x['kind'] == 'network']
    need(len(networks) == 1 and networks[0]['state'] == 'OBSERVED' and CONTAINER_ID.fullmatch(networks[0]['object_id']),
         'EXACT_NETWORK_OWNERSHIP_REQUIRED')
    nid = networks[0]['object_id']
    need(info['HostConfig']['NetworkMode'] == nid, 'DEDICATED_NETWORK_REQUIRED')
    return o, nid, 'FM' + digest[:12], 'fm' + digest[:12]


def owned_network_readiness(row, info, until, home):
    o, nid, _, bridge = owned_network_coordinates(row, info)
    rc, raw, _ = command([DOCKER, 'network', 'inspect', nid], until, home, 65536)
    need(rc == 0, 'OWNED_NETWORK_INSPECTION_FAILED')
    networks = json.loads(raw)
    need(isinstance(networks, list) and len(networks) == 1, 'OWNED_NETWORK_INSPECTION_FORMAT')
    network = networks[0]
    labels = {'owner': 'v2', 'installation': o['installation_id'], 'epoch': o['epoch_id'], 'instance': o['instance_id']}
    need(network.get('Id') == nid and network.get('Driver') == 'bridge'
         and network.get('Options', {}).get('com.docker.network.bridge.name') == bridge
         and all(network.get('Labels', {}).get('io.chatanium.flexmodule.' + k) == v for k, v in labels.items()),
         'OWNED_NETWORK_BRIDGE_IDENTITY_CHANGED')
    endpoints = network.get('Containers', {})
    need(set(endpoints) == {o['container_id']}, 'SOLE_OWNED_NETWORK_ENDPOINT_REQUIRED')
    endpoint_identity = endpoints[o['container_id']]
    need(CONTAINER_ID.fullmatch(endpoint_identity.get('EndpointID', '')), 'OWNED_NETWORK_ENDPOINT_IDENTITY_REQUIRED')
    ip_binary = Path('/usr/sbin/ip')
    trusted(ip_binary)

    def inspect_ip(args):
        rc, raw, _ = command([str(ip_binary), '-j', '-d'] + args, until, home, 65536)
        need(rc == 0, 'OWNED_LINK_INSPECTION_FAILED')
        data = json.loads(raw)
        need(isinstance(data, list) and len(data) <= 16, 'OWNED_LINK_INSPECTION_FORMAT')
        return data

    bridges = inspect_ip(['link', 'show', 'dev', bridge])
    need(len(bridges) == 1 and bridges[0].get('ifname') == bridge
         and bridges[0].get('linkinfo', {}).get('info_kind') == 'bridge'
         and type(bridges[0].get('ifindex')) is int and bridges[0]['ifindex'] > 0,
         'OWNED_BRIDGE_LINK_IDENTITY_REQUIRED')
    ports = inspect_ip(['link', 'show', 'master', bridge])
    need(len(ports) == 1, 'SOLE_OWNED_BRIDGE_HOST_PORT_REQUIRED')
    port = ports[0]
    name = port.get('ifname', '')
    need(re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', name)
         and port.get('master') == bridge and port.get('linkinfo', {}).get('info_kind') == 'veth'
         and type(port.get('ifindex')) is int and port['ifindex'] > 0,
         'OWNED_BRIDGE_HOST_PORT_IDENTITY_REQUIRED')
    addresses, pending = [], False
    for link in (bridges[0], port):
        data = inspect_ip(['address', 'show', 'dev', link['ifname']])
        need(len(data) == 1 and data[0].get('ifname') == link['ifname']
             and data[0].get('ifindex') == link['ifindex'], 'OWNED_LINK_ADDRESS_IDENTITY_CHANGED')
        pending |= 'UP' not in data[0].get('flags', [])
        available = data[0].get('addr_info', [])
        need(isinstance(available, list) and len(available) <= 64, 'OWNED_LINK_ADDRESS_BOUND')
        ipv6 = []
        for address in available:
            if address.get('family') != 'inet6':
                continue
            flags = address.get('flags', [])
            failed = address.get('dadfailed', False) or 'dadfailed' in flags
            tentative = address.get('tentative', False) or 'tentative' in flags
            need(not failed, 'OWNED_LINK_IPV6_DAD_FAILED')
            pending |= bool(tentative)
            ipv6.append({'local': str(ipaddress.IPv6Address(address['local'])),
                         'prefixlen': address['prefixlen'], 'tentative': bool(tentative)})
        addresses.append({'ifname': link['ifname'], 'ifindex': link['ifindex'], 'ipv6': ipv6})
    return {'network_id': nid, 'container_id': o['container_id'], 'endpoint_id': endpoint_identity['EndpointID'],
            'bridge': bridge, 'host_port': name, 'addresses': addresses, 'ready': not pending}


def firewall_generations(snapshot, active=False):
    expected = {(family, table) for family in (4, 6)
                if BASE_CONFIG['host']['network']['ipv4' if family == 4 else 'ipv6']
                for table in ('raw', 'mangle', 'filter')}
    groups = {}
    for rule in snapshot['rules']:
        groups.setdefault((rule['family'], rule['table']), []).append(rule)
    need(set(groups) == expected, 'POLICY_GENERATION_CHAIN_SET_MISMATCH')
    identity = []
    for key in sorted(groups):
        rules = groups[key]
        need([x['index'] for x in rules] == list(range(1, len(rules) + 1))
             and len({x['chain'] for x in rules}) == 1, 'POLICY_GENERATION_CHAIN_IDENTITY_INVALID')
        markers = [x for x in rules if 'fm-generation:' in x['rule']]
        need(len(markers) == 1 and markers[0]['index'] == rules[-1]['index'],
             'EXACTLY_ONE_TERMINAL_POLICY_GENERATION_REQUIRED')
        marker = markers[0]
        tokens = re.findall(r'/\* fm-generation:([A-Z2-7]{26}) \*/', marker['rule'])
        need(len(tokens) == 1 and marker['rule'].count('fm-generation:') == 1
             and marker['rule'].split()[0] in ('RETURN', 'DROP'), 'POLICY_GENERATION_MARKER_INVALID')
        if active:
            need(marker['rule'].split()[0] == 'RETURN', 'OWNED_POLICY_NOT_ACTIVE')
        identity.append((key[0], key[1], marker['chain'], marker['index'], tokens[0], marker['rule']))
    return identity


def network_start_barrier(row, info, until, home, observation):
    stop = min(until, time.monotonic() + 30)
    observation.update(status='WAITING', max_inspections=128, deadline_monotonic=stop)
    for attempt in range(128):
        check(stop)
        need(not INTERRUPTED, 'INTERRUPTED_BEFORE_NETWORK_PROBE')
        observation['inspections'] = attempt + 1
        latest = docker_owned(row, stop, home)
        need(latest and latest['State']['Running'] and
             latest['HostConfig']['NetworkMode'] == info['HostConfig']['NetworkMode'],
             'NETWORK_START_OWNERSHIP_CHANGED')
        topology = owned_network_readiness(row, latest, stop, home)
        observation['last_topology'] = topology
        if not topology['ready']:
            continue
        before = firewall_snapshot(row, latest, stop, home)
        observation['bookend_before'] = before
        firewall_generations(before)
        if any(x['rule'].split()[0] != 'RETURN' for x in before['rules'] if 'fm-generation:' in x['rule']):
            continue
        confirmed = owned_network_readiness(row, latest, stop, home)
        observation['bookend_topology'] = confirmed
        after = firewall_snapshot(row, latest, stop, home)
        observation['bookend_after'] = after
        firewall_delta(before, after)
        firewall_generations(after, active=True)
        need(confirmed == topology, 'NETWORK_START_TOPOLOGY_CHANGED')
        observation.update(status='READY', ready_monotonic=time.monotonic(),
                           condition='owned_links_DAD_complete_and_active_policy_identity_bookended')
        return after
    raise Fault('NETWORK_START_CONDITION_INSPECTION_BOUND')


def firewall_snapshot(row, info, until, home):
    if not is_public(CURRENT_CASE):
        need(info['HostConfig']['NetworkMode'] == 'none' and not any(x['kind'] == 'network' for x in row['creates']),
             'NONE_TOPOLOGY_MISMATCH')
        return {'rules': [], 'topology': 'none'}
    o, nid, chain, _ = owned_network_coordinates(row, info)
    argv = [DOCKER, 'network', 'ls', '--no-trunc', '--filter', 'id=' + nid]
    labels = {'owner': 'v2', 'installation': o['installation_id'], 'epoch': o['epoch_id'], 'instance': o['instance_id']}
    for k, v in labels.items():
        argv += ['--filter', 'label=io.chatanium.flexmodule.' + k + '=' + v]
    rc, raw, _ = command(argv + ['--format', '{{.ID}}'], until, home, 256)
    need(rc == 0 and raw.decode().strip() == nid, 'NETWORK_LABEL_MISMATCH')
    rows = []
    for family, binary in ((4, '/usr/sbin/iptables'), (6, '/usr/sbin/ip6tables')):
        if not BASE_CONFIG['host']['network']['ipv4' if family == 4 else 'ipv6']:
            continue
        for table in ('raw', 'mangle', 'filter'):
            rc, raw, _ = command([binary, '-w', '2', '-t', table, '-L', chain, '-n', '-v', '-x', '--line-numbers'], until, home, 65536)
            need(rc == 0, 'OWNED_FIREWALL_UNAVAILABLE')
            for line in raw.decode('ascii').splitlines():
                parts = line.split()
                if parts and parts[0].isdigit():
                    need(len(rows) < 1024 and len(parts) >= 10 and parts[1].isdigit() and parts[2].isdigit(), 'COUNTER_FORMAT')
                    rows.append({'family': family, 'table': table, 'chain': chain, 'index': int(parts[0]),
                                 'packets': int(parts[1]), 'bytes': int(parts[2]), 'rule': ' '.join(parts[3:])})
    need(rows, 'NO_OWNED_FIREWALL_RULES')
    return {'rules': rows, 'network_id': nid, 'observed_monotonic': time.monotonic()}


def firewall_delta(before, after):
    if before.get('topology') == 'none' or after.get('topology') == 'none':
        need(before.get('topology') == after.get('topology') == 'none'
             and not before['rules'] and not after['rules'], 'NONE_COUNTER_TOPOLOGY_CHANGED')
        return []
    need(before['network_id'] == after['network_id'], 'COUNTER_NETWORK_IDENTITY_CHANGED')
    need(firewall_generations(before) == firewall_generations(after), 'POLICY_GENERATION_CHANGED')
    need(len(before['rules']) == len(after['rules']), 'COUNTER_RULE_SET_CHANGED')
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
        if port != 53 or ip in [ipaddress.ip_address(x) for x in BASE_CONFIG['host']['network']['resolvers']]:
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
        zero = '0.0.0.0/0' if ip.version == 4 else '::/0'
        expected_rule = 'DROP ' + protocol + ' -- * * ' + zero + ' ' + zero + ' ' + protocol + ' dpt:53'
        return (protocol in ('udp', 'tcp') and drop['family'] == ip.version and drop['table'] == 'raw'
                and drop['rule'] == expected_rule and drop['bytes'] > old['bytes'])
    except (Fault, KeyError, TypeError, ValueError):
        return False


def rebinding_tcp_expectation(rec):
    """The actual destination, never its round number, determines egress policy."""
    try:
        ip = ipaddress.ip_address(endpoint(rec.get('data', {}).get('address', ''))[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        network = BASE_CONFIG['host']['network']
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
    if not (result.get('cleanup_complete') and result.get('owned_container_absent') and
            result.get('unrelated_controls_preserved') and all(result.get('final_path_absence', {}).values())):
        return 'INCONCLUSIVE', 'terminal_host_ownership_evidence_missing'
    scratch = result.get('final_quotas', {}).get('scratch', {})
    if scratch.get('status') != 'MEASURED' or any(scratch.get(k) != 0 for k in ('bytes', 'inodes', 'realtime_bytes')):
        return 'INCONCLUSIVE', 'shared_project_reclamation_unproven'
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
        component = result.get('ipc_component', {})
        fixture = [(x['state'], x.get('data', {}).get('endpoint')) for x in records if x['probe'] == 'ipc-component']
        if any(state == 'endpoint-accepted' and endpoint == 'outside' for state, endpoint in fixture):
            return 'FAIL', 'out_of_ipc_fixture_endpoint_connected'
        if not (component.get('original_reached') and component.get('fresh_capture_rejected')
                and result.get('ipc_component_host_identity', {}).get('replacement_symlink_verified')
                and result.get('runtime_returncode') == 0
                and ('pathname-replaced', None) in fixture and ('endpoint-accepted', 'original') in fixture
                and ('returned-not-policy-proof', None) in fixture):
            return 'INCONCLUSIVE', 'ordered_component_and_fixture_evidence_missing'
        return 'PASS', 'actual_capture_ordered_replacement_retained_dial_and_fresh_capture_rejection'
    if case == 'cleanup-crash':
        if not (result.get('cleanup_crash_witness') and result.get('cleanup_crash_sigkill_sent')
                and result.get('runtime_returncode') == -9 and (result.get('final_epoch') or {}).get('state') == 'DEAD'):
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
        obs = [x.get('data', {}) for x in records if x['state'] == 'child-syscall-observation']
        if any(x.get('outcome') == 'syscall-or-operation-returned' for x in obs):
            return 'FAIL', 'identity_namespace_or_hard_limit_raise_succeeded'
        if len(obs) != 9 or any(x.get('outcome') != 'syscall-error' or
            x.get('errno') not in ((1, 13, 22) if x.get('operation') == 'nproc-soft' else (1, 13)) for x in obs):
            return 'INCONCLUSIVE', 'identity_or_fd_limit_raise_denial_not_proven'
        snapshots = [x.get('data', {}) for x in records if x['state'] == 'before-workload']
        if not snapshots or not all(0 < x.get('nofile_soft', 0) <= x.get('nofile_hard', 0) < 2**64 - 1 for x in snapshots):
            return 'INCONCLUSIVE', 'finite_guest_fd_limits_not_measured'
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


def main():
    global DATA, MANAGEMENT, STORAGE, IPC, BASE, RUNTIME, DOCKER, IMAGE, MODULE
    global UID, GID, GUEST_UID, GUEST_GID, PROFILE, LIMITS, RESOURCES, PLAN, BASE_CONFIG, PUBLIC_CONFIG
    global SOCKET, SUPERVISOR_UID, SUPERVISOR_MAX_BYTES, CURRENT_CASE
    global ACTIVE_NETWORK_SPEC
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for name in ('plan', 'output', 'config', 'runtime', 'supervisor-socket', 'image-checker'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--supervisor-uid', type=int, required=True)
    parser.add_argument('--supervisor-max-bytes', type=int, required=True)
    parser.add_argument('--overall-seconds', type=int, required=True)
    args = parser.parse_args()
    need(os.geteuid() == 0, 'ROOT_REQUIRED')
    need(180 <= args.overall_seconds <= 7200, 'FINITE_OVERALL_DEADLINE_180_TO_7200_REQUIRED')
    need(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'PIDFD_PYTHON_REQUIRED')
    os.umask(0o077)
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    start = time.monotonic()
    until = start + args.overall_seconds
    trusted(canonical(__file__))
    PLAN, _ = read_json(canonical(args.plan))
    need(set(PLAN) <= {'schema_version', 'base_sha256', 'runtime_uid', 'runtime_gid', 'docker', 'config_directory',
                      'cases', 'controls', 'case_seconds', 'public_config', 'network_cases', 'network_controls', 'runtime_return_holder'}, 'UNKNOWN_PLAN_FIELD')
    need(PLAN['schema_version'] == 1, 'PLAN_VERSION')
    selected = PLAN['cases']
    need(isinstance(selected, list) and selected and len(selected) <= len(CASES) and len(set(selected)) == len(selected)
         and all(x in CASES for x in selected), 'EXPLICIT_UNIQUE_CASES_REQUIRED')
    need(isinstance(PLAN['controls'], list) and 1 <= len(PLAN['controls']) <= 16, 'UNRELATED_LIVE_CONTROLS_REQUIRED')
    case_seconds = PLAN.get('case_seconds', 240)
    need(type(case_seconds) is int and 180 <= case_seconds <= 300, 'CASE_DEADLINE')
    UID, GID = PLAN['runtime_uid'], PLAN['runtime_gid']
    need(type(UID) is int and type(GID) is int and 0 < UID < 2**32 and 0 < GID < 2**32, 'NONROOT_RUNTIME_REQUIRED')
    BASE, RUNTIME, DOCKER = canonical(args.config), canonical(args.runtime), str(canonical(PLAN['docker']))
    trusted(RUNTIME)
    trusted(Path(DOCKER))
    checker = canonical(args.image_checker)
    trusted(checker)
    global IPC_DRIVER, RETURN_HOLDER
    IPC_DRIVER, RETURN_HOLDER = checker, None
    if 'cleanup-crash' in selected:
        need(isinstance(PLAN.get('runtime_return_holder'), str), 'TRUSTED_RUNTIME_RETURN_HOLDER_REQUIRED')
        RETURN_HOLDER = canonical(PLAN['runtime_return_holder'])
        trusted(RETURN_HOLDER)
        need(os.access(RETURN_HOLDER, os.X_OK), 'RETURN_HOLDER_NOT_EXECUTABLE')
    BASE_CONFIG, raw = read_json(BASE)
    need(hashlib.sha256(raw).hexdigest() == PLAN['base_sha256'], 'APPROVED_BASE_HASH_MISMATCH')
    validate_base(BASE_CONFIG)
    m, h = BASE_CONFIG['modules'][0], BASE_CONFIG['host']
    IMAGE, MODULE, GUEST_UID, GUEST_GID = m['image'], m['module_id'], m['uid'], m['gid']
    need(UID != GUEST_UID, 'DISTINCT_HOST_AND_GUEST_IDENTITIES_REQUIRED')
    MANAGEMENT, STORAGE, IPC = (canonical(h[k]) for k in ('management_directory', 'storage_root', 'ipc_root'))
    DATA = MANAGEMENT
    SOCKET = canonical(args.supervisor_socket)
    SUPERVISOR_UID, SUPERVISOR_MAX_BYTES = args.supervisor_uid, args.supervisor_max_bytes
    need(0 <= SUPERVISOR_UID < 2**32 and 0 < SUPERVISOR_MAX_BYTES <= 16 << 20, 'SUPERVISOR_BOUNDS')
    for path in (MANAGEMENT, STORAGE, IPC):
        trusted(path, directory=True)
    LIMITS = BASE_CONFIG['limits']
    cls = m['approval']['resourceClass'].removeprefix('RESOURCE_CLASS_').lower()
    PROFILE = BASE_CONFIG['resource_profiles'][cls]
    approved = m['approval']['resourceLimits']
    RESOURCES = {'nano_cpus': int(approved['cpuMillicores']) * 1000000, 'memory_bytes': int(approved['memoryBytes']),
                 'pids': int(approved['maxPids']), 'persistent_bytes': int(approved['persistentBytes']), 'scratch_bytes': int(approved['scratchBytes']),
                 'persistent_inodes': LIMITS['persistent_inode_limit'], 'scratch_inodes': LIMITS['scratch_inode_limit']}
    for k in ('control_message_max_bytes', 'log_buffer_bytes', 'log_file_max_bytes', 'log_retained_files'):
        RESOURCES[k] = LIMITS[k]
    PUBLIC_CONFIG = None
    if PLAN.get('public_config'):
        PUBLIC_CONFIG, _ = read_json(canonical(PLAN['public_config']))
        other = copy.deepcopy(PUBLIC_CONFIG)
        approval = other['modules'][0]['approval']
        need(approval['egressPolicy'] == 'EGRESS_POLICY_PUBLIC_INTERNET' and
             any(x['name'] == 'core.network.public_egress' for x in approval['coreCapabilities']), 'PUBLIC_APPROVAL_REQUIRED')
        # Only explicit approval/revision may differ; no identity/image/host drift.
        other['modules'][0]['approval'] = m['approval']
        other['modules'][0]['approval_revision'] = m['approval_revision']
        need(other == BASE_CONFIG, 'PUBLIC_CONFIG_IDENTITY_DRIFT')
    outroot = canonical(args.output)
    trusted(outroot, directory=True, private=True)
    need(os.lstat(outroot).st_gid == 0, 'PRIVATE_ROOT_EVIDENCE_REQUIRED')
    configroot = canonical(PLAN['config_directory'])
    trusted(configroot, directory=True)
    st = os.lstat(configroot)
    need(st.st_gid == GID and stat.S_IMODE(st.st_mode) == 0o750, 'ROOT_RUNTIME_GROUP_CONFIG_DIRECTORY_REQUIRED')
    lockfd = open_no_links(MANAGEMENT / 'sandbox-policy.lock', os.O_RDWR | os.O_CREAT)
    st = os.fstat(lockfd)
    need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and not st.st_mode & 0o077, 'LOCK_IDENTITY')
    fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    output = outroot / ('sandbox-policy-' + uuid.uuid4().hex)
    configs = configroot / ('sandbox-policy-' + uuid.uuid4().hex)
    os.mkdir(output, 0o700)
    os.mkdir(configs, 0o750)
    os.chown(configs, 0, GID)
    os.chmod(configs, 0o750)
    summary = {'schema_version': 1, 'image': IMAGE, 'module_id': MODULE,
               'base_sha256': PLAN['base_sha256'], 'selected_cases': selected, 'cases': []}
    journal = quotas = None
    unsafe = False
    try:
        check_config = configs / 'image-check.json'
        try:
            private_json(check_config, BASE_CONFIG)
            os.chown(check_config, 0, GID)
            os.chmod(check_config, 0o640)
            rc, raw_check, _ = command([str(checker), 'sandbox', '--image-check-only',
                '--config', str(check_config), '--runtime', str(RUNTIME), '--supervisor-socket', str(SOCKET),
                '--supervisor-uid', str(SUPERVISOR_UID), '--supervisor-max-bytes', str(SUPERVISOR_MAX_BYTES),
                '--deadline', '4s', '--observe', '1s'], until, output, cap=8192, runtime_peer=True)
            need(rc == 0 and not raw_check.strip(), 'CANONICAL_FIXTURE_SUPERVISOR_CHECK_FAILED')
        finally:
            if check_config.exists():
                check_config.unlink()
        summary['canonical_fixture_verified_by_nonroot_supervisor_peer'] = True
        journal, quotas = Journal(), Quotas()
        need(not journal.active(), 'INSTALLATION_ALREADY_ACTIVE')
        for case in selected:
            CURRENT_CASE = case
            reason = None
            if unsafe:
                reason = 'PRIOR_CLEANUP_OR_CONTROL_FAILURE'
            elif INTERRUPTED or until - time.monotonic() < 180:
                reason = 'INTERRUPTED_OR_OVERALL_DEADLINE'
            elif is_public(case) and PUBLIC_CONFIG is None:
                reason = 'EXPLICIT_PUBLIC_APPROVAL_CONFIG_MISSING'
            elif case in NETWORK_CASES:
                spec = PLAN.get('network_cases', {}).get(case)
                if not spec or not PLAN.get('network_controls', {}).get(case):
                    reason = 'CONTROLLED_ENDPOINT_OR_IPV6_ROUTE_OR_AUTHORITATIVE_REBINDING_PREREQUISITE_MISSING'
                else:
                    specs = spec if isinstance(spec, list) else [spec]
                    need(1 <= len(specs) <= 32, 'NETWORK_TARGET_COUNT_BOUND')
                    for single in specs:
                        validate_network_spec(case, single)
            if reason:
                item = {'case': case, 'status': 'NOT_RUN', 'reason': reason}
                private_json(output / (case + '.json'), item)
            else:
                specs = PLAN['network_cases'][case] if case in NETWORK_CASES else [None]
                specs = specs if isinstance(specs, list) else [specs]
                jobs = []
                for index, single in enumerate(specs):
                    artifact = case if len(specs) == 1 else case + '-' + str(index)
                    if unsafe or INTERRUPTED or until - time.monotonic() < 180:
                        jobs.append({'status': 'NOT_RUN', 'reason': 'PRIOR_SAFETY_FAILURE_OR_DEADLINE', 'artifact': artifact + '.json'})
                        private_json(output / (artifact + '.json'), jobs[-1])
                        continue
                    ACTIVE_NETWORK_SPEC = single
                    observed = CaseRun(case, BASE_CONFIG, output, configs, journal, quotas,
                                       min(until, time.monotonic() + case_seconds), artifact=artifact).run()
                    jobs.append({'status': observed['status'], 'reason': observed['verdict_reason'], 'artifact': artifact + '.json'})
                    unsafe = bool(observed.get('runtime_pid') and (not observed.get('cleanup_complete') or observed['status'] == 'FAIL'))
                status = aggregate_status(jobs)
                item = {'case': case, 'status': status, 'jobs': jobs}
            summary['cases'].append(item)
            print(json.dumps(item, separators=(',', ':')), flush=True)
    except (Fault, OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        summary['error'] = safe_errno(exc)
        completed = {x['case'] for x in summary['cases']}
        for case in selected:
            if case not in completed:
                summary['cases'].append({'case': case, 'status': 'NOT_RUN', 'reason': 'OPERATOR_PREREQUISITE_OR_OBSERVATION_FAILURE'})
    finally:
        if quotas:
            quotas.close()
        if journal:
            journal.db.close()
        try:
            os.rmdir(configs)
        except OSError as exc:
            summary['config_cleanup_error'] = safe_errno(exc)
        os.close(lockfd)
        summary['elapsed_seconds'] = time.monotonic() - start
        summary['status'] = aggregate_status(summary['cases'])
        if summary.get('config_cleanup_error'):
            summary['status'] = 'FAIL'
        elif summary['status'] == 'PASS' and (summary.get('error') or len(summary['cases']) != len(selected)):
            summary['status'] = 'INCONCLUSIVE'
        private_json(output / 'summary.json', summary)
        print(json.dumps({'scenario': 'sandbox.full_policy', 'status': summary['status'],
                          'scope': 'explicit_selected_cases_only', 'artifact_directory': str(output)}, separators=(',', ':')), flush=True)
    return 0 if summary['status'] == 'PASS' else 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Fault, OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        print(json.dumps({'scenario': 'sandbox.full_policy', 'status': 'NOT_RUN', **safe_errno(exc)}, separators=(',', ':')), flush=True)
        sys.exit(2)
