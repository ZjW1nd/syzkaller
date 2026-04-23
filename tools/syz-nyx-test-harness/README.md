# syz-nyx-test-harness

Minimal Windows Nyx harness for validating the `my-qemu-nyx/nyx/syz_cov`
collector without starting the full syzkaller runner path.

It does only one thing:

1. initialize the Nyx guest protocol
2. submit `ntoskrnl.exe` as PT range 0
3. receive kAFL/Nyx payloads
4. execute `NtQuerySystemInformation`
5. wrap the syscall with `SYZ_COV_RESET`, `ACQUIRE`, `RELEASE`, `SYZ_COV_DUMP`

Build on the old kAFL machine with MinGW:

```bash
cd syzkaller/tools/syz-nyx-test-harness
make
```

Copy `syz_nyx_test_harness.exe` into the Windows image and auto-start it.

Run qemu-nyx with reload disabled for the first smoke test. The current harness
calls `SYZ_COV_DUMP` after `RELEASE`; if the guest is restored immediately at
release time, the dump call may not execute. Once this smoke test works, move the
dump into qemu-nyx's release path or use the full `syz-executor exec nyx` flow.

Expected success artifact:

```text
<kafl_workdir>/syz_cov_0.bin
```

Quick parser:

```bash
python3 - <<'PY' /path/to/workdir/syz_cov_0.bin
import struct, sys
data = open(sys.argv[1], "rb").read()
magic, ver, _, records = struct.unpack_from("<IHHI", data, 0)
print(hex(magic), ver, records)
off = 12
for i in range(records):
    call, slot, flags, n, _ = struct.unpack_from("<IIQII", data, off)
    off += 24
    pcs = struct.unpack_from("<" + "Q" * n, data, off) if n else []
    print("record", i, "call", call, "pcs", n, [hex(x) for x in pcs[:16]])
PY
```
