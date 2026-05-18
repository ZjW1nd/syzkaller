# syz-nyx-runner

`syz-nyx-runner` is a host-side bridge between `syz-manager(type=none)` and a
Nyx/QEMU Windows guest that runs `syz-executor exec nyx`.

Current v1 expectations:

- the Windows guest auto-starts `syz-executor exec nyx`
- the guest image may expose the optional CR3 helper; the executor will
  continue without CR3 submission when it is unavailable
- the host starts `syz-manager` with `type: "none"` and `reproduce: false`
- the host starts `syz-nyx-runner` manually

A minimal manager config is provided in `windows-nyx-none.cfg`.

Focused configs now narrow the Windows surface through
`enable_syscalls`, `disable_syscalls`, `seed_prefix`, and
`borrowing_seed_prefix`, for example:

- `windows-nyx-afd-none.cfg` enables a small accept/transmit-oriented socket set
- `windows-nyx-fsctl-none.cfg` enables a focused file/FSCTL set
- `windows-nyx-afd-accept-race-none.cfg` narrows corpus and borrowing seeds to `nyx_afd_accept_`
- `windows-nyx-afd-transmit-none.cfg` narrows corpus and borrowing seeds to `nyx_afd_accept_transmit`

Example:

```bash
./bin/syz-manager -config tools/syz-nyx-runner/windows-nyx-none.cfg
./bin/syz-nyx-runner \
  --qemu-path /path/to/qemu-system-x86_64 \
  --workdir /tmp/syz-nyx \
  --image /path/to/windows.qcow2 \
  --qemu-arg=-enable-kvm \
  --qemu-arg=-cpu \
  --qemu-arg=host,migratable=off \
  0 127.0.0.1 12345
```
