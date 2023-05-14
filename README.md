# Yggdrasil-jumper

This project aims to transparently reduce latency of a connection over Yggdrasil network for such applications as online gaming, VoIP and others.

## How it works

By default, `yggdrasil-go` routes data only through explicitly connected peers and doesn't attempt to reach other nodes accessible over the internet. Therefore, path usually contains 1-2 intermediary nodes, namely public peers of both sides. If both you and your peer use internet, you can send traffic directly (aka peer-to-peer), thus reducing latency.

* Jumper connects to [Admin API] of the running router. And monitors active sessions (peers you have data exchange over Yggdrasil network with).
* Once any such session appears, jumper tries to connect to associated peer, assuming it has another jumper running on the same `listen_port`.
* Both jumpers exchange their external internet addresses and use [NAT traversal] technique to instantiate direct bridge over the internet.
* If previous step was successful, jumper will relay all data passing the bridge to the router until session is closed or other error occurs.

[STUN]: https://en.wikipedia.org/wiki/STUN
[Admin API]: https://yggdrasil-network.github.io/admin.html
[NAT traversal]: https://en.wikipedia.org/wiki/NAT_traversal

## Usage

Jumper can run without additional configuration. All it needs is access to [Admin API] of the router and to the IP network.

```shell
$ yggdrasil-jumper --loglevel info # off/error/warn/info/debug
...
```

It may be helpful to know what the defaults are.

```shell
$ yggdrasil-jumper --print-default
...
# List of possible admin socket locations
yggdrasil_admin_listen = [
  "unix:///var/run/yggdrasil/yggdrasil.sock",
  "unix:///var/run/yggdrasil.sock",
  "tcp://localhost:9001",
]
...
# List of yggdrasil listen addresses
# Connect to one, instead of using `add/removepeer` commands
# Noteworthy, this is the only way to use routers prior to v0.4.5 (Oct 2022)
yggdrasil_listen = [ ]
...
# List of allowed yggdrasil peer addresses
# Uncomment to apply
#whitelist = [ ]
...
# Default connect/listen port in yggdrasil network
listen_port = 4701
...
# List of STUN servers
stun_servers = [
  ...
]
...
```

You can also overwrite some if needed.

```shell
$ yggdrasil-jumper --config <path> # standard input will be read if path is "-"
...
```

## Installation

- **Downloading:** Check the [Releases page](https://github.com/one-d-wide/yggdrasil-jumper/releases).
- **Compiling:**
  ```shell
  $ git clone https://github.com/one-d-wide/yggdrasil-jumper
  $ cd yggdrasil-jumper
  $ cargo build --bin yggdrasil-jumper --release
  $ sudo cp target/release/yggdrasil-jumper /usr/local/bin/yggdrasil-jumper
  ```

## Details

<details>
<summary>External address lookup</summary>

In order to know what address to use with [NAT traversal], jumper must know self external internet address and port. This task is performed using [STUN] protocol with TCP extension, hence not every [STUN] server is supported. [STUN] standard is quite broad, but jumper utilities only address lookup feature.

You can check compatibility with `stun-tcp` binary from this repository.

```shell
$ cargo build --bin stun-tcp --release
$ # ./target/release/stun-tcp
```

`stun-tcp` takes [STUN] server(s) as argument and outputs resolved address.

```shell
$ stun-tcp --print-server stunserver.stunprotocol.org:3478
stunserver.stunprotocol.org:3478 244.13.30.107:28674
```

You can also take servers from hardcoded defaults or your configuration.

```shell
$ stun-tcp --default
244.13.30.107:28674
...
```

If `stun-tcp` fails to connect to any server it will print error and exit with code `1`.
```shell
$ stun-tcp stunserver.stunprotocol.org:3478 [::]:0
244.13.30.107:28674
ERROR While resolving {server=[::]:0}: Failed to connect: Connection refused
```

It also checks whether all servers return same address. You can skip this check by passing `--no-check` argument.

```shell
$ stun-tcp stunserver.stunprotocol.org:3478 wrong.resolver
244.13.30.107:28674
ERROR While resolving {server=wrong.resolver}: {received=0.0.0.0:0}: Previously resolved addresses do not match
```

</details>

<details>
<summary>Establishing direct connection over the internet</summary>

You can read more about the procedure in  [this paper](https://bford.info/pub/net/p2pnat).

- Create and bind listen and connection sockets to the same port (using `SO_REUSEADDR` and `SO_REUSEPORT` flags).
- Lookup self external address and port.
- Exchange external addresses with peer.
- Try to connect to the peer and listen for connection simultaneously.

</details>

<details>
<summary>Improvements since prototype</summary>

 The overall pipeline is mostly the same. The most notable improvements are:

 * Efficient concurrent multitasking.
 * Robust error handling.
 * Sane user interface and logging.
 * Support of older routers.
 * Firewall traversal at address exchange phase.

</details>
