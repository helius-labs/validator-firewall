# validator-firewall

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`
2. If you're running on Ubuntu 20.04, there is a bug with bpftool and the default kernel installed by the distribution. To avoid running into it, you can install a newer bpftool version that does not include the bug with:

```
sudo apt install linux-tools-5.8.0-63-generic
export PATH=/usr/lib/linux-tools/5.8.0-63-generic:$PATH
```

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run -- --iface <iface> --static_overrides <path_to_static_overrides.yaml> -p 8004 -p 8005 -p 8006
```
