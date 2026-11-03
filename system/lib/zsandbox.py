"""The sandbox the conductor runs code in (docs/ORCHESTRATOR.md).

The same approach as openai/codex's Linux sandbox (codex-rs/linux-sandbox, Apache-2.0): bubblewrap gives the
program a read-only view of the system with no network and no access to the person's home, and a seccomp filter
installed by bubblewrap refuses the system calls that could get around that. The filter is built here, in classic
BPF, with no library, for x86-64 and arm64:

  - sockets other than AF_UNIX (no new network stack, even inside the empty network namespace);
  - io_uring (codex blocks it too: it can bypass socket-family rules);
  - ptrace, process_vm_readv/writev, bpf, perf_event_open, userfaultfd, keyctl/add_key/request_key,
    kexec_load, init_module/finit_module;
  - on x86-64, the x32 system-call numbers.
A program built for another architecture is killed.

Inside: an empty root with /usr, /etc and /opt read-only (and the /bin, /lib links), /work/in (the inputs,
read-only), /work/out (writable), a private /tmp. Not there at all: /home, /root, /var, /run, /media, /mnt, /srv;
/etc/zenos is hidden.
"""
import os, platform, shutil, struct, subprocess, tempfile

AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}
DENY = {
    "x86_64": {"io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427, "ptrace": 101,
               "process_vm_readv": 310, "process_vm_writev": 311, "bpf": 321, "perf_event_open": 298,
               "userfaultfd": 323, "keyctl": 250, "add_key": 248, "request_key": 249, "kexec_load": 246,
               "kexec_file_load": 320, "init_module": 175, "finit_module": 313},
    "aarch64": {"io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427, "ptrace": 117,
                "process_vm_readv": 270, "process_vm_writev": 271, "bpf": 280, "perf_event_open": 241,
                "userfaultfd": 282, "keyctl": 219, "add_key": 217, "request_key": 218, "kexec_load": 104,
                "kexec_file_load": 294, "init_module": 105, "finit_module": 273},
}
SOCKET = {"x86_64": 41, "aarch64": 198}
AF_UNIX = 1
RET_ALLOW, RET_KILL = 0x7FFF0000, 0x80000000
RET_EPERM, RET_EAFNOSUPPORT = 0x00050000 | 1, 0x00050000 | 97
LD_ABS_W, JEQ, JGE, RET = 0x20, 0x15, 0x35, 0x06


class Unavailable(Exception):
    pass


def _ins(code, jt, jf, k):
    return struct.pack("<HBBI", code, jt, jf, k)


def seccomp_filter(arch=None):
    """the BPF program (bytes) for bubblewrap's --seccomp"""
    arch = arch or platform.machine()
    if arch not in AUDIT_ARCH:
        raise Unavailable(f"no seccomp filter for {arch}")
    prog = []                                   # (code, true target, false target, k); targets: label or None
    prog.append((LD_ABS_W, None, None, 4))
    prog.append((JEQ, None, "kill", AUDIT_ARCH[arch]))
    prog.append((LD_ABS_W, None, None, 0))
    if arch == "x86_64":
        prog.append((JGE, "eperm", None, 0x40000000))
    for nr in sorted(DENY[arch].values()):
        prog.append((JEQ, "eperm", None, nr))
    prog.append((JEQ, "sock", None, SOCKET[arch]))
    labels = {}
    prog.append((RET, None, None, RET_ALLOW))
    labels["sock"] = len(prog)
    prog.append((LD_ABS_W, None, None, 16))
    prog.append((JEQ, None, "eafno", AF_UNIX))
    prog.append((RET, None, None, RET_ALLOW))
    labels["eafno"] = len(prog)
    prog.append((RET, None, None, RET_EAFNOSUPPORT))
    labels["eperm"] = len(prog)
    prog.append((RET, None, None, RET_EPERM))
    labels["kill"] = len(prog)
    prog.append((RET, None, None, RET_KILL))
    out = b""
    for i, (code, t, f, k) in enumerate(prog):
        jt = labels[t] - i - 1 if t else 0
        jf = labels[f] - i - 1 if f else 0
        if not (0 <= jt <= 255 and 0 <= jf <= 255):
            raise ValueError("jump out of range")
        out += _ins(code, jt, jf, k)
    return out


def bwrap():
    return shutil.which("bwrap")


def run(argv, inputs=None, out_dir=None, timeout=120, stdin=None, text=True):
    """run argv in the sandbox. inputs: {name inside /work/in: real path}. Returns CompletedProcess (text, or bytes
    with text=False)."""
    bw = bwrap()
    if not bw:
        raise Unavailable("bubblewrap is not installed")
    args = [bw, "--tmpfs", "/"]
    for top in ("usr", "etc", "opt"):
        if os.path.isdir("/" + top):
            args += ["--ro-bind", "/" + top, "/" + top]
    for top in ("bin", "sbin", "lib", "lib32", "lib64", "libx32"):
        p = "/" + top
        if os.path.islink(p):
            args += ["--symlink", os.readlink(p), p]
        elif os.path.isdir(p):
            args += ["--ro-bind", p, p]
    args += ["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"]
    if os.path.isdir("/etc/zenos"):
        args += ["--tmpfs", "/etc/zenos"]
    args += ["--dir", "/work", "--dir", "/work/in"]
    for name, real in (inputs or {}).items():
        if "/" in name or name in ("", ".", ".."):
            raise ValueError("bad input name")
        args += ["--ro-bind", os.path.realpath(real), "/work/in/" + name]
    if out_dir:
        args += ["--bind", os.path.realpath(out_dir), "/work/out"]
    args += ["--chdir", "/work", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
             "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/tmp",
             "--setenv", "LANG", "C.UTF-8"]
    with tempfile.TemporaryFile() as f:
        f.write(seccomp_filter())
        f.seek(0)
        fd = f.fileno()
        args += ["--seccomp", str(fd), "--"] + list(argv)
        return subprocess.run(args, input=stdin, capture_output=True, text=text, timeout=timeout, pass_fds=(fd,))
