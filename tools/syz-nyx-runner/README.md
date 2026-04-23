# syz-nyx-runner

`syz-nyx-runner` is a host-side bridge between `syz-manager(type=none)` and a
Nyx/QEMU Windows guest that runs `syz-executor exec nyx`.

Current v1 expectations:

- the Windows guest auto-starts `syz-executor exec nyx`
- the guest image contains the minimal CR3 helper
- the host starts `syz-manager` with `type: "none"` and `reproduce: false`
- the host starts `syz-nyx-runner` manually

A minimal manager config is provided in `demo-windows-none.cfg`.

Example:

```bash
./bin/syz-manager -config demo.cfg
./bin/syz-nyx-runner 0 127.0.0.1 12345 \
  --qemu-path /path/to/qemu-system-x86_64 \
  --workdir /tmp/syz-nyx-demo \
  --image /path/to/windows.qcow2 \
  --qemu-arg=-enable-kvm \
  --qemu-arg=-cpu \
  --qemu-arg=host,migratable=off
```
