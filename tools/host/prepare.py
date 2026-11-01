#!/usr/bin/python3 -I
"""Operator-only EL9 lab preparation. No changes without --apply.

Install this source under a root-owned, non-writable ancestry before invoking
/usr/bin/python3 -I. The checkout (including its ancestors) is not trusted root
execution storage. See --help for the required operator inventory and bounds.
"""
import sys

if not sys.flags.isolated:
    sys.exit("invoke with /usr/bin/python3 -I /trusted/root-owned/prepare.py")

import argparse
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
import pathlib
import platform
import pwd
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time

RELEASE = "release-20261026.0"
ARCHIVE_URL = "https://github.com/google/gvisor/releases/download/" + RELEASE + "/gvisor-x86_64.tar.zstd"
ARCHIVE_SHA = "708afc62f2ee82d19930c703e85f9dab4f27a78c0aec40c0f55eb1040107f1a7"
ARCHIVE_SIZE = 57851781
INSTALL = "/opt/flexmodule-lab/runsc/" + RELEASE
RUNTIME_NAME = "flexmodule-lab-runsc-20261026"
# Keep the approved OCI CPU quota during creation and teardown, not runsc defaults.
RUNTIME_ARGS = ["--platform=systrap", "--host-uds=create", "--file-access-mounts=shared", "--overlay2=root:self", "--sandbox-creation-cpu-policy=1x", "--sandbox-lifecycle-cpu-policy=1x", "--systemd-cgroup"]
BACKING = "/home/flexmodule-lab-storage"
WORK = BACKING + "/work"
IMAGE = BACKING + "/data.xfs"
IMAGE_BYTES = 32 * 1024 ** 3
MOUNT = "/var/lib/flexmodule-lab/data"
CONFIG = "/etc/flexmodule-lab/supervisor.json"
DAEMON = "/etc/docker/daemon.json"
NAME = "flexmodule-runtime"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C", "LC_ALL": "C"}
TOOLS = {}
PACKAGES = {"docker": "docker-ce-cli", "dockerd": "docker-ce", "curl": "curl", "zstd": "zstd", "mkfs.xfs": "xfsprogs", "xfs_quota": "xfsprogs", "iptables": "iptables-nft", "ip6tables": "iptables-nft", "iptables-restore": "iptables-nft", "ip6tables-restore": "iptables-nft", "conntrack": "conntrack-tools", "ip": "iproute", "findmnt": "util-linux", "losetup": "util-linux", "mount": "util-linux", "blkid": "util-linux", "fallocate": "util-linux", "systemctl": "systemd", "useradd": "shadow-utils", "groupadd": "shadow-utils"}
SPECIAL = [ipaddress.ip_network(s) for s in ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/96", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "ff00::/8")]


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def trusted(path, directory=False):
    """lstat every component: no symlink or user-replaceable ancestor."""
    require(os.path.isabs(path) and not path.startswith("//") and os.path.normpath(path) == path, "noncanonical path: " + path)
    parts = pathlib.Path(path).parts
    current = "/"
    for index, part in enumerate(parts):
        if index:
            current = os.path.join(current, part)
        info = os.lstat(current)
        is_dir = index < len(parts) - 1 or directory
        require(stat.S_ISDIR(info.st_mode) if is_dir else stat.S_ISREG(info.st_mode), "unexpected type/symlink: " + current)
        require(info.st_uid == 0 and info.st_mode & 0o022 == 0, "not root-owned/protected: " + current)
    return info


def trusted_tool(path, depth=0):
    """Permit only administrator-owned system alternatives, not user symlinks."""
    require(depth < 16, "system executable symlink chain too deep")
    trusted(os.path.dirname(path), True)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        require(info.st_uid == 0, "system executable symlink is not root-owned")
        target = os.readlink(path)
        target = os.path.normpath(target if os.path.isabs(target) else os.path.join(os.path.dirname(path), target))
        return trusted_tool(target, depth + 1)
    info = trusted(path)
    require(path.startswith(("/usr/bin/", "/usr/sbin/", "/usr/libexec/")) and info.st_mode & 0o111, "non-system executable")
    return info


def directory(path, mode=0o700, gid=0):
    trusted(os.path.dirname(path), True)
    try:
        os.mkdir(path, mode)
        os.chown(path, 0, gid)
        os.chmod(path, mode)
    except FileExistsError:
        pass
    info = trusted(path, True)
    require(stat.S_IMODE(info.st_mode) == mode and info.st_gid == gid, "existing directory permission/identity mismatch: " + path)


def read_file(path, maximum=16 * 1024 ** 2):
    trusted(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        require(info.st_size <= maximum and info.st_nlink == 1, "oversized/hardlinked file: " + path)
        return source.read(maximum + 1)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique_object)


def json_file(path):
    return decode(read_file(path))


def serialized(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def atomic(path, content, mode=0o600, expected=None):
    parent = os.path.dirname(path)
    trusted(parent, True)
    if os.path.lexists(path):
        old = read_file(path)
        if old == content:
            return False
        require(expected is not None and old == expected, "refusing to replace unrelated/changed file: " + path)
    else:
        require(expected is None, "file disappeared: " + path)
    fd, temporary = tempfile.mkstemp(prefix=".flexmodule-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        if expected is not None:
            require(read_file(path) == expected, "concurrent file change: " + path)
        os.replace(temporary, path)
        fd = os.open(parent, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def child_limits(file_limit):
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
    os.umask(0o077)


def command(executable, *args, timeout=30, allow_failure=False, file_limit=1024 ** 3):
    """Finite wall time, captured bytes and child file size; no shell."""
    path = TOOLS.get(executable, executable)
    if executable in TOOLS:
        trusted_tool(path)
    else:
        trusted(path)
    process = subprocess.Popen([path, *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=ENV, cwd="/", start_new_session=True, preexec_fn=lambda: child_limits(file_limit))
    end = time.monotonic() + timeout
    output = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while selector.get_map():
            remaining = end - time.monotonic()
            require(remaining > 0, "command deadline exceeded: " + executable)
            for key, _ in selector.select(min(remaining, 0.2)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                else:
                    output.extend(chunk)
                    require(len(output) <= 4 * 1024 ** 2, "command output exceeded bound: " + executable)
        code = process.wait(timeout=max(0.01, end - time.monotonic()))
        require(allow_failure or code == 0, "command failed: " + executable + " " + " ".join(args) + "\n" + output.decode(errors="replace")[:8192])
        return code, bytes(output)
    finally:
        selector.close()
        process.stdout.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()


def text(executable, *args, **kwargs):
    return command(executable, *args, **kwargs)[1].decode().strip()


def docker(*args):
    return text("docker", "--host", "unix:///var/run/docker.sock", *args)


def inspect_tools():
    missing = []
    for name, package in PACKAGES.items():
        found = False
        for base in ("/usr/sbin", "/usr/bin"):
            candidate = os.path.join(base, name)
            if not os.path.exists(candidate):
                continue
            # Retain the iptables basename: xtables-nft-multi dispatches by
            # argv[0]. Validate the whole root-owned alternatives chain.
            try:
                trusted_tool(candidate)
                TOOLS[name] = candidate
                found = True
                break
            except (RuntimeError, OSError):
                continue
        if not found:
            missing.append(name + " (EL9 package " + package + ")")
    require(not missing, "missing trusted system prerequisites; operator installation required, no auto-install:\n  " + "\n  ".join(missing))


def positive(low, high):
    def parse(value):
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError("must be in %d..%d" % (low, high))
        return number
    return parse


def inventory(path):
    value = json_file(path)
    required = {"ipv4_pool", "ipv6_pool", "resolvers", "host_public_addresses", "internal_prefixes", "metadata_prefixes", "inventory_revision"}
    require(isinstance(value, dict) and set(value) == required, "inventory must contain exactly: " + ", ".join(sorted(required)))
    require(isinstance(value["inventory_revision"], str) and 1 <= len(value["inventory_revision"]) <= 128 and value["inventory_revision"].strip() == value["inventory_revision"], "finite explicit inventory_revision required")
    pools = [ipaddress.ip_network(value["ipv4_pool"], strict=True), ipaddress.ip_network(value["ipv6_pool"], strict=True)]
    require(pools[0].version == 4 and 8 <= pools[0].prefixlen <= 28 and pools[1].version == 6 and 48 <= pools[1].prefixlen <= 120, "dedicated canonical bounded IPv4/IPv6 pools required")
    for key in ("resolvers", "host_public_addresses", "internal_prefixes", "metadata_prefixes"):
        items = value[key]
        require(isinstance(items, list) and 1 <= len(items) <= 256 and all(isinstance(s, str) and len(s) <= 128 for s in items), "explicit finite nonempty inventory list required: " + key)
        for item in items:
            address = ipaddress.ip_network(item, strict=False)
            if key in ("resolvers", "host_public_addresses"):
                ip = ipaddress.ip_address(item)
                require(not any(ip.version == blocked.version and ip in blocked for blocked in SPECIAL) and (ip.version == 4 or ip in ipaddress.ip_network("2000::/3")), key + " must contain public numeric IPs (include all public/NAT host IPs)")
            if key in ("resolvers", "host_public_addresses"):
                require(not any(address.version == pool.version and address.overlaps(pool) for pool in pools), "public inventory overlaps module pool: " + item)
    value.update({"backend": "iptables", "iptables": TOOLS["iptables"], "ip6tables": TOOLS["ip6tables"], "iptables_restore": TOOLS["iptables-restore"], "ip6tables_restore": TOOLS["ip6tables-restore"], "conntrack": TOOLS["conntrack"]})
    return value, pools


def host_checks(pools):
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86_64 required")
    require(os.confstr("CS_GNU_LIBC_VERSION") == "glibc 2.34", "this lab preparation requires observed EL9 glibc 2.34; never replace host libc")
    info = decode(docker("info", "--format", "{{json .}}"))
    require(info.get("ServerVersion") == "29.5.3" and info.get("OSType") == "linux" and info.get("CgroupVersion") == "2" and info.get("CgroupDriver") == "systemd", "Docker 29.5.3 Linux cgroupv2/systemd required")
    require(all(info.get(key) is True for key in ("MemoryLimit", "SwapLimit", "PidsLimit", "CpuCfsQuota")), "Docker hard-limit prerequisites missing")
    require(not any("rootless" in option or "userns" in option for option in info.get("SecurityOptions", [])), "rootful non-remapped Docker required")
    require(text("systemctl", "show", "--property=ActiveState", "--value", "docker.service") == "active", "Docker systemd service must already be active; never started/restarted")
    pid = int(text("systemctl", "show", "--property=MainPID", "--value", "docker.service"))
    require(pid > 1 and os.stat("/proc/" + str(pid)).st_uid == 0 and os.path.realpath("/proc/" + str(pid) + "/exe") == os.path.realpath(TOOLS["dockerd"]), "Docker service main process is not the trusted rootful dockerd")
    with open("/proc/" + str(pid) + "/cmdline", "rb") as source:
        argv = source.read(65537)
    require(len(argv) <= 65536, "Docker service argv exceeds bound")
    argv = argv.decode().strip("\x00").split("\x00")
    for index, argument in enumerate(argv):
        if argument == "--config-file":
            require(index + 1 < len(argv) and argv[index + 1] == DAEMON, "Docker service uses a different daemon config; not modified")
        elif argument.startswith("--config-file="):
            require(argument == "--config-file=" + DAEMON, "Docker service uses a different daemon config; not modified")
    missing = []
    for path in ("/proc/sys/net/bridge/bridge-nf-call-iptables", "/proc/sys/net/bridge/bridge-nf-call-ip6tables", "/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"):
        try:
            with open(path, "r", encoding="ascii") as source:
                enabled = source.read(32).strip() == "1"
        except OSError:
            enabled = False
        if not enabled:
            missing.append(path + " must already equal 1 (operator policy; not changed)")
    for tool in ("iptables", "ip6tables"):
        if "nf_tables" not in text(tool, "--version"):
            missing.append(tool + " must use nft backend")
        code, _ = command(tool, "-w", "5", "-t", "filter", "-S", "DOCKER-USER", allow_failure=True)
        if code:
            missing.append(tool + " filter DOCKER-USER hook unavailable (not created automatically)")
    require(not missing, "missing P4 network prerequisites:\n  " + "\n  ".join(missing))
    # Route inventory includes all policy-routing tables and both families.
    for family in ("-4", "-6"):
        routes = decode(text("ip", "-j", family, "route", "show", "table", "all"))
        for route in routes:
            destination = route.get("dst", "default")
            if destination == "default":
                continue
            prefix = ipaddress.ip_network(destination, strict=False)
            require(not any(prefix.version == pool.version and prefix.overlaps(pool) for pool in pools), "module pool collides with host route: " + destination)
    for interface in decode(text("ip", "-j", "address", "show")):
        for address in interface.get("addr_info", []):
            prefix = ipaddress.ip_network(str(address["local"]) + "/" + str(address["prefixlen"]), strict=False)
            require(not any(prefix.version == pool.version and prefix.overlaps(pool) for pool in pools), "module pool collides with host interface: " + interface["ifname"] + " " + str(prefix))
    for allocation in info.get("DefaultAddressPools", []) or []:
        prefix = ipaddress.ip_network(allocation["Base"], strict=True)
        require(not any(prefix.version == pool.version and prefix.overlaps(pool) for pool in pools), "module pool collides with Docker default address allocation: " + str(prefix))
    networks = docker("network", "ls", "--quiet").splitlines()
    require(len(networks) <= 256, "Docker network inventory exceeds bounded operator review size")
    for identifier in networks:
        network = decode(docker("network", "inspect", identifier))[0]
        for subnet in network.get("IPAM", {}).get("Config", []) or []:
            if subnet.get("Subnet"):
                prefix = ipaddress.ip_network(subnet["Subnet"], strict=False)
                require(not any(prefix.version == pool.version and prefix.overlaps(pool) for pool in pools), "module pool collides with Docker network: " + network["Name"] + " " + str(prefix))
    return info


def identity(apply):
    try:
        group = grp.getgrnam(NAME)
    except KeyError:
        if not apply:
            return None
        command("groupadd", "--system", NAME)
        group = grp.getgrnam(NAME)
    require(0 < group.gr_gid < 1000 and not group.gr_mem, "runtime group must be a dedicated system group without other members")
    try:
        user = pwd.getpwnam(NAME)
    except KeyError:
        if not apply:
            return None
        command("useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/sbin/nologin", "--gid", NAME, NAME)
        user = pwd.getpwnam(NAME)
    require(0 < user.pw_uid < 1000 and user.pw_gid == group.gr_gid and user.pw_shell in ("/sbin/nologin", "/usr/sbin/nologin") and user.pw_dir == "/nonexistent", "existing runtime identity is not a dedicated nonlogin system user")
    require(set(os.getgrouplist(NAME, user.pw_gid)) == {user.pw_gid}, "runtime supplementary groups forbidden, especially docker/wheel")
    require(not any(other.pw_name != NAME and other.pw_gid == group.gr_gid for other in pwd.getpwall()), "runtime primary group shared by another account")
    return user


def digest(path):
    trusted(path)
    checksum = hashlib.sha256()
    with open(path, "rb") as source:
        while True:
            block = source.read(1024 ** 2)
            if not block:
                return checksum.hexdigest()
            checksum.update(block)


def release():
    archive = WORK + "/gvisor-x86_64.tar.zstd"
    if not os.path.lexists(archive):
        fd, temporary = tempfile.mkstemp(prefix=".download-", dir=WORK)
        os.close(fd)
        try:
            command("curl", "--fail", "--location", "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "15", "--max-time", "180", "--max-filesize", str(ARCHIVE_SIZE), "--output", temporary, ARCHIVE_URL, timeout=190)
            require(os.stat(temporary).st_size == ARCHIVE_SIZE and digest(temporary) == ARCHIVE_SHA, "full release archive SHA256 mismatch")
            os.replace(temporary, archive)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    require(os.stat(archive, follow_symlinks=False).st_size == ARCHIVE_SIZE and digest(archive) == ARCHIVE_SHA, "cached full release archive SHA256 mismatch")
    fd, tarpath = tempfile.mkstemp(prefix=".release-", suffix=".tar", dir=WORK)
    os.close(fd)
    stage = None
    try:
        command("zstd", "--decompress", "--force", "-M256MiB", archive, "-o", tarpath, timeout=120)
        with tarfile.open(tarpath, mode="r:") as bundle:
            members = bundle.getmembers()
            require(0 < len(members) <= 4096 and sum(member.size for member in members) <= 512 * 1024 ** 2, "release extraction bounds exceeded")
            # Archives may have a single enclosing gvisor directory. Locate it
            # from the actual pinned archive, never discard arbitrary paths.
            names = {}
            for member in members:
                name = member.name
                while name.startswith("./"):
                    name = name[2:]
                if name in ("", ".") and member.isdir():
                    continue
                require(not name.startswith("/") and ".." not in pathlib.PurePosixPath(name).parts and "\\" not in name, "unsafe archive path")
                name = name.rstrip("/")
                require(name not in names and (member.isfile() or member.isdir()), "duplicate/link/special archive member: " + name)
                names[name] = member
            launchers = [name for name, member in names.items() if pathlib.PurePosixPath(name).name == "runsc" and member.isfile() and not "/gvisor-bin/" in "/" + name]
            require(len(launchers) == 1, "pinned archive must have one runsc launcher")
            prefix = launchers[0][:-len("runsc")]
            files = {}
            for name, member in names.items():
                if name + "/" == prefix and member.isdir():
                    continue
                require(name.startswith(prefix), "archive member outside release root")
                relative = name[len(prefix):]
                require(relative and os.path.normpath(relative) == relative, "noncanonical release member")
                if member.isfile():
                    files[relative] = member
            require("runsc" in files and "containerd-shim-runsc-v1" in files and any(name.startswith("gvisor-bin/") for name in files), "complete launcher/shim/gvisor-bin closure required")
            expected = {}
            for name, member in files.items():
                checksum = hashlib.sha256()
                with bundle.extractfile(member) as source:
                    for block in iter(lambda: source.read(1024 ** 2), b""):
                        checksum.update(block)
                expected[name] = checksum.hexdigest()
            if not os.path.lexists(INSTALL):
                stage = tempfile.mkdtemp(prefix=".release-", dir=os.path.dirname(INSTALL))
                for name, member in files.items():
                    target = os.path.join(stage, name)
                    os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
                    with bundle.extractfile(member) as source, open(target, "xb") as output:
                        shutil.copyfileobj(source, output, 1024 ** 2)
                        output.flush()
                        os.fsync(output.fileno())
                    os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
                for current, dirs, _ in os.walk(stage):
                    os.chmod(current, 0o755)
                os.rename(stage, INSTALL)
                stage = None
            trusted(INSTALL, True)
            observed = {}
            for current, dirs, entries in os.walk(INSTALL, followlinks=False):
                trusted(current, True)
                for name in dirs:
                    trusted(os.path.join(current, name), True)
                for name in entries:
                    path = os.path.join(current, name)
                    observed[os.path.relpath(path, INSTALL)] = digest(path)
            require(observed == expected, "installed full-release per-file SHA256 map mismatch; never overwrite an existing release")
        version_output = text(INSTALL + "/runsc", "--version")
        first = version_output.splitlines()[0] if version_output else ""
        require(first in ("runsc version release-20261026.0", "runsc version 20261026.0"), "installed runsc version mismatch; possible EL9 loader/native incompatibility")
        atomic(BACKING + "/runsc-manifest.json", serialized({"archive_url": ARCHIVE_URL, "archive_sha256": ARCHIVE_SHA, "runsc_version": first[len("runsc version "):], "files": expected}))
        return first[len("runsc version "):], expected
    finally:
        os.unlink(tarpath)
        if stage is not None:
            shutil.rmtree(stage)


def loop_details(device):
    value = decode(text("losetup", "--json", "--list", "--output", "NAME,BACK-FILE,OFFSET,SIZELIMIT,RO", device))["loopdevices"]
    require(len(value) == 1, "loop mapping missing/ambiguous")
    loop = value[0]
    require(loop["back-file"] == IMAGE and int(loop["offset"]) == 0 and int(loop["sizelimit"]) == 0 and not loop["ro"], "loop device does not map exactly to owned backing file")


def storage(user):
    statepath = BACKING + "/storage.json"
    if os.path.lexists(IMAGE):
        info = trusted(IMAGE)
        state = json_file(statepath)
        require(state == {"path": IMAGE, "bytes": IMAGE_BYTES, "device": info.st_dev, "inode": info.st_ino, "uuid": text("blkid", "-p", "-s", "UUID", "-o", "value", IMAGE)}, "existing backing file ownership/UUID manifest mismatch; never reformat")
        require(info.st_size == IMAGE_BYTES and info.st_blocks * 512 >= IMAGE_BYTES and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600, "backing file size/allocation/link/permissions mismatch")
        require(text("blkid", "-p", "-s", "TYPE", "-o", "value", IMAGE) == "xfs", "existing backing filesystem is not XFS")
    else:
        require(not os.path.lexists(statepath), "backing manifest exists but data missing; operator recovery required")
        require(os.statvfs(BACKING).f_bavail * os.statvfs(BACKING).f_frsize >= IMAGE_BYTES + 2 * 1024 ** 3, "home filesystem needs 34GiB free for allocated backing plus workspace")
        fd, fresh = tempfile.mkstemp(prefix=".new-data-", dir=BACKING)
        os.close(fd)
        try:
            command("fallocate", "--length", str(IMAGE_BYTES), fresh, timeout=120, file_limit=IMAGE_BYTES)
            # No -f, no block device, and only the file created in THIS invocation.
            command("mkfs.xfs", "-q", "-L", "flexmod-lab", fresh, timeout=120, file_limit=IMAGE_BYTES)
            uuid = text("blkid", "-p", "-s", "UUID", "-o", "value", fresh)
            require(uuid, "new XFS UUID missing")
            os.rename(fresh, IMAGE)
            info = trusted(IMAGE)
            state = {"path": IMAGE, "bytes": IMAGE_BYTES, "device": info.st_dev, "inode": info.st_ino, "uuid": uuid}
            atomic(statepath, serialized(state))
        finally:
            if os.path.exists(fresh):
                os.unlink(fresh)
    directory("/var/lib/flexmodule-lab", 0o711)
    directory(MOUNT, 0o711)
    code, data = command("findmnt", "--json", "--mountpoint", MOUNT, "--output", "TARGET,SOURCE,FSTYPE,OPTIONS,UUID", allow_failure=True)
    if code:
        require(code == 1 and not os.listdir(MOUNT), "refusing to mount over existing data")
        mappings = decode(text("losetup", "--json", "--list", "--output", "NAME,BACK-FILE,OFFSET,SIZELIMIT,RO"))["loopdevices"]
        owned = [loop["name"] for loop in mappings if loop.get("back-file") == IMAGE]
        require(len(owned) <= 1, "multiple loop mappings of owned file")
        device = owned[0] if owned else text("losetup", "--find", "--show", "--nooverlap", IMAGE)
        loop_details(device)
        command("mount", "--types", "xfs", "--options", "prjquota,nodev,nosuid", device, MOUNT)
        data = command("findmnt", "--json", "--mountpoint", MOUNT, "--output", "TARGET,SOURCE,FSTYPE,OPTIONS,UUID")[1]
    mounted = decode(data)["filesystems"]
    require(len(mounted) == 1, "ambiguous mount")
    mounted = mounted[0]
    require(mounted["target"] == MOUNT and mounted["fstype"] == "xfs" and mounted["uuid"] == state["uuid"], "existing mount is not the owned XFS image")
    require({"rw", "prjquota", "nodev", "nosuid"}.issubset(set(mounted["options"].split(","))), "existing mount lacks required project-quota/security options; never remounted automatically")
    loop_details(mounted["source"])
    # Root of a freshly formatted XFS is 0755; only this verified owned mount
    # may have its top-level mode initialized. No home/global remount occurs.
    trusted(MOUNT, True)
    os.chmod(MOUNT, 0o711)
    quota = text("xfs_quota", "-x", "-c", "state -p", MOUNT)
    require("Accounting: ON" in quota and "Enforcement: ON" in quota, "XFS project quota accounting/enforcement not active")
    directory(MOUNT + "/management", 0o710, user.pw_gid)
    directory(MOUNT + "/modules", 0o700)
    directory(MOUNT + "/ipc", 0o711)
    discord = MOUNT + "/discord"
    try:
        os.mkdir(discord, 0o700)
        os.chown(discord, user.pw_uid, user.pw_gid)
    except FileExistsError:
        pass
    info = os.lstat(discord)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == user.pw_uid and info.st_gid == user.pw_gid and stat.S_IMODE(info.st_mode) == 0o700, "existing Discord ownership directory must be runtime-owned 0700; not adopted/chowned")


def register_runtime(before):
    original = read_file(DAEMON)
    daemon = decode(original)
    require(isinstance(daemon, dict) and isinstance(daemon.get("runtimes", {}), dict), "invalid existing Docker runtimes configuration")
    entry = {"path": INSTALL + "/runsc", "runtimeArgs": RUNTIME_ARGS}
    existing = before.get("Runtimes", {}).get(RUNTIME_NAME)
    require(existing is None or (existing.get("path") == entry["path"] and existing.get("runtimeArgs") == RUNTIME_ARGS), "lab runtime name already registered with different settings")
    runtimes = daemon.setdefault("runtimes", {})
    if RUNTIME_NAME in runtimes:
        require(runtimes[RUNTIME_NAME] == entry, "existing named lab runtime differs; not overwritten")
    runtimes[RUNTIME_NAME] = entry
    replacement = serialized(daemon)
    if decode(original) != daemon:
        # Validate the FULL merged configuration before replacing anything.
        fd, candidate = tempfile.mkstemp(prefix=".flexmodule-validate-", suffix=".json", dir=os.path.dirname(DAEMON))
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(replacement)
            command("dockerd", "--validate", "--config-file", candidate)
        finally:
            os.unlink(candidate)
        atomic(BACKING + "/docker-daemon-before-" + hashlib.sha256(original).hexdigest() + ".json", original)
        atomic(DAEMON, replacement, mode=stat.S_IMODE(trusted(DAEMON).st_mode), expected=original)
        # Only SIGHUP to the existing service's main process. Never restart,
        # reload-or-restart, daemon-reexec, or mutate unrelated runtime entries.
        command("systemctl", "kill", "--kill-whom=main", "--signal=HUP", "docker.service")
    deadline = time.monotonic() + 15
    while True:
        after = decode(docker("info", "--format", "{{json .}}"))
        registered = after.get("Runtimes", {}).get(RUNTIME_NAME, {})
        if registered.get("path") == entry["path"] and registered.get("runtimeArgs", registered.get("args")) == RUNTIME_ARGS:
            break
        require(time.monotonic() < deadline, "Docker SIGHUP registration not confirmed; configuration retained, no restart attempted")
        time.sleep(0.5)
    require(before.get("DefaultRuntime") == after.get("DefaultRuntime"), "Docker default runtime changed externally")
    for name, value in before.get("Runtimes", {}).items():
        require(after.get("Runtimes", {}).get(name) == value, "existing Docker runtime changed externally: " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__, epilog="Inventory JSON fields (no defaults): ipv4_pool, ipv6_pool, resolvers, host_public_addresses (all public/NAT IPs), internal_prefixes, metadata_prefixes, inventory_revision. All list fields must be nonempty. Inputs/config/script must be root-owned below root-protected no-symlink ancestors. Default is read-only preflight; --apply is required for account/download/install/mount/Docker SIGHUP/config mutations. No services are started. No fstab/sysctl/firewall changes. Repeated application preserves existing data and rejects mismatches. Re-run only with module networks absent: collision checks deliberately do not exempt existing workload routes.")
    parser.allow_abbrev = False
    parser.add_argument("--apply", action="store_true", help="explicitly authorize only the documented lab preparation mutations")
    parser.add_argument("--inventory", required=True, help="absolute trusted operator inventory JSON, not committed to repository")
    parser.add_argument("--max-message-bytes", type=positive(1024, 16 * 1024 ** 2), required=True)
    parser.add_argument("--max-connections", type=positive(1, 4096), required=True)
    parser.add_argument("--operation-timeout-seconds", type=positive(1, 600), required=True)
    parser.add_argument("--reconcile-interval-seconds", type=positive(1, 300), required=True)
    parser.add_argument("--api-deadline-seconds", type=positive(1, 120), required=True)
    parser.add_argument("--termination-deadline-seconds", type=positive(1, 300), required=True)
    parser.add_argument("--deadline-seconds", type=positive(30, 3600), required=True, help="whole operator command wall-time bound")
    args = parser.parse_args()
    require(os.geteuid() == 0, "root required even for read-only host preflight; no sudo subprocesses")
    trusted(os.path.abspath(__file__))
    trusted("/usr/bin/python3" if not os.path.islink("/usr/bin/python3") else os.path.realpath("/usr/bin/python3"))
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(RuntimeError("whole preparation deadline exceeded; no automatic destructive recovery")))
    signal.alarm(args.deadline_seconds)
    os.umask(0o077)
    inspect_tools()
    network, pools = inventory(args.inventory)
    before = host_checks(pools)
    user = identity(False)
    trusted(os.path.dirname(DAEMON), True)
    daemon = json_file(DAEMON)
    require(isinstance(daemon, dict) and isinstance(daemon.get("runtimes", {}), dict), "existing Docker configuration is not a runtimes object")
    for parent in ("/home", "/opt", "/var/lib", "/etc"):
        trusted(parent, True)
    if not args.apply:
        print(json.dumps({"mode": "READ_ONLY", "prerequisites": "system_tools_docker_network_inventory_observed", "release_and_storage": "not_installed_or_verified", "runtime_identity": "existing_verified" if user else "will_create_dedicated_system_user", "archive_url": ARCHIVE_URL, "archive_sha256": ARCHIVE_SHA, "install": INSTALL, "backing_bytes": IMAGE_BYTES, "backing": IMAGE, "mount": MOUNT, "supervisor_config": CONFIG, "apply_required": True}, sort_keys=True))
        return
    directory(BACKING)
    directory(WORK)
    lock = os.open(BACKING + "/prepare.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        lockstat = os.fstat(lock)
        require(stat.S_ISREG(lockstat.st_mode) and lockstat.st_uid == 0 and lockstat.st_nlink == 1 and lockstat.st_mode & 0o077 == 0, "untrusted setup lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        directory("/opt/flexmodule-lab", 0o755)
        directory("/opt/flexmodule-lab/runsc", 0o755)
        version, files = release()
        user = identity(True)
        storage(user)
        register_runtime(before)
        directory("/etc/flexmodule-lab", 0o700)
        config = {"supervisor": {"socket_path": MOUNT + "/management/control.sock", "runtime_uid": user.pw_uid, "runtime_gid": user.pw_gid, "management_directory": MOUNT + "/management", "storage_root": MOUNT + "/modules", "ipc_root": MOUNT + "/ipc", "max_message_bytes": args.max_message_bytes, "operation_timeout": args.operation_timeout_seconds * 10 ** 9, "reconcile_interval": args.reconcile_interval_seconds * 10 ** 9, "max_connections": args.max_connections}, "platform": {"endpoint": "unix:///var/run/docker.sock", "engine_version": "29.5.3", "runtime_name": RUNTIME_NAME, "runsc_path": INSTALL + "/runsc", "runsc_version": version, "runsc_sha256": files["runsc"], "runsc_files": files, "api_deadline": args.api_deadline_seconds * 10 ** 9, "termination_deadline": args.termination_deadline_seconds * 10 ** 9, "network": network}}
        atomic(CONFIG, serialized(config))
        print(json.dumps({"mode": "APPLIED", "config": CONFIG, "runtime_uid": user.pw_uid, "runtime_gid": user.pw_gid, "socket": config["supervisor"]["socket_path"], "discord_ownership_directory": MOUNT + "/discord", "runsc_version": version, "runsc_files": files, "services_started": False, "sandbox_tests_executed": False}, sort_keys=True))
    finally:
        os.close(lock)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError, tarfile.TarError) as error:
        print("LAB_SETUP_FAILED: " + str(error), file=sys.stderr)
        sys.exit(1)
