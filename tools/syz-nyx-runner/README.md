# syz-nyx-runner

`syz-nyx-runner` is a host-side bridge between `syz-manager(type=none)` and a
Nyx/QEMU Windows guest that runs `syz-executor exec nyx`.

Current v1 expectations:

- the Windows guest auto-starts `syz-executor exec nyx`
- the guest image may expose the optional CR3 helper; the executor will
  continue without CR3 submission when it is unavailable
- the host can start `syz-manager` with `type: "none"` and `reproduce: false`
- the host starts `syz-nyx-runner` manually

Two Windows Nyx manager configs are kept here:

- `windows-nyx-test.cfg` is the minimal `type: "none"` config for manual
  runner testing.
- `windows-nyx.cfg` is the normal `type: "nyx"` fuzzing config used by the
  fullchain scripts.

Example:

```bash
./bin/syz-manager -config tools/syz-nyx-runner/windows-nyx-test.cfg
./bin/syz-nyx-runner \
  --qemu-path /path/to/qemu-system-x86_64 \
  --workdir /tmp/syz-nyx \
  --image /path/to/windows.qcow2 \
  --qemu-arg=-enable-kvm \
  --qemu-arg=-cpu \
  --qemu-arg=host,migratable=off \
  0 127.0.0.1 12345
```
