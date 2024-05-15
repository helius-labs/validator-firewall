# Helius Validator Firewall

Low level blocking for validator nodes. This project is a work in progress and interfaces may change.

![arch diagram](./validator_firewall.png)


## Prerequisites

1. Install nightly components: `rustup toolchain install nightly --component rust-src`
2. Install bpf-linker: `cargo install bpf-linker`
3. If you're running on Ubuntu 20.04, there is a bug with bpftool and the default kernel installed by the distribution. To avoid running into it, you can install a newer bpftool version that does not include the bug with:

```
sudo apt install linux-tools-5.8.0-63-generic
export PATH=/usr/lib/linux-tools/5.8.0-63-generic:$PATH
```

## General Structure

The project is split into two main components: the eBPF program and the userspace program.  The eBPF program is linked
into the userspace program and is loaded into the kernel. The userspace program is responsible for setting up the eBPF 
maps (shared memory between the eBPF program and the userspace program), pushing in external data, and reporting stats.

By default, all non-gossip traffic is blocked on the specified ports.  An additional set of hosts can be specified in a
static overrides file.  This file is a YAML file that contains a list of IP addresses that should be allowed to bypass 
the firewall.  The format is as follows:

```yaml
nodes:
  - name: "host1"
    address: 1.2.3.4
  - name: "host2"
    address: 4.5.6.7
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


## Production
This should be run under a user with the CAP_NET_ADMIN capability. This is required to load the eBPF program and to set the XDP program on the interface.

