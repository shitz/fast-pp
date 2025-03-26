# Fast packet processing with eBPF (fast-pp)

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build

Use `cargo build`, `cargo check`, etc. as normal.

Cargo build scripts are used to automatically build the eBPF correctly and
include it in the program.

## Run

Before running the program, you need to setup a virtual network topology. You
can use the provided `setup.sh` script to create a network namespace and veth
pairs.

```sh
sudo ./setup.sh
```

Then change into the `net2` namespace and run the program.

```sh
sudo ip netns exec net2 bash
RUST_LOG=debug ./target/debug/fast-pp
```

In a separate terminal, you can run the `ping` command to generate some traffic.

```sh
sudo ip netns exec net1 ping 192.168.10.2
sudo ip netns exec net1 ping 192.168.20.2
```

Observe that the pings to `192.168.10.2` are processed by the kernel and pings
to `192.168.20.2` by `fast-pp`.

## Cleanup

After you are done, you can run the `cleanup.sh` script to remove the network
namespace and veth pairs.

```sh
sudo ./cleanup.sh
```
