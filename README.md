# Yggdrasil-jumper

Yggdrasil-Jumper is an independent project that aims to transparently reduce
latency of a connection over Yggdrasil network, utilizing NAT traversal to
bypass intermediary nodes. It periodically probes for active sessions and
automatically establishes direct peerings over the internet with remote nodes
running Yggdrasil-Jumper without requiring any firewall configuration or port
mapping.

## Features

* Peer-to-peer level latency for any traffic between a pair of peers, running
the jumper.
* Automatic NAT/Firewall traversal (aka hole-punching).
* Seamless integration with yggdrasil router.
* Peering over both TCP and UDP (QUIC) protocols are supported.
* No firewall configuration required.
* No jumper configuration required by default.

## How it works

By default, `yggdrasil-go` routes data only through explicitly connected peers
and doesn't attempt to reach other nodes accessible over the internet.
Therefore, path usually contains 1-2 intermediary nodes, namely public peers of
both sides. If both you and your peer have connection to the internet, you can
send traffic directly (aka peer-to-peer), thus reducing latency.

* Jumper connects to [Admin API][admin-api] of the running router. And monitors active
sessions (peers you have data exchange over Yggdrasil network with).
* Once any such session appears, jumper tries to connect to associated peer,
assuming it has another jumper running on the same `listen_port`.
* Both jumpers exchange their external internet addresses and use [NAT
traversal][nat-traversal] technique to instantiate a direct bridge over the
internet.
* If previous step was successful, jumper will relay all data passing the bridge
to the router until session is closed or other error occurs.

[admin-api]: https://yggdrasil-network.github.io/admin.html
[nat-traversal]: https://en.wikipedia.org/wiki/NAT_traversal

## Usage

Jumper can run without any additional configuration. All it needs is access to
[Admin API][admin-api] of the router and to the IP network.

```sh
$ yggdrasil-jumper --loglevel info # off/error/warn/info/debug
...
```

It may be helpful to know what the defaults are.

```sh
$ yggdrasil-jumper --show-defaults
...
# List of possible admin socket locations
yggdrasil_admin_listen = [
  "unix:///var/run/yggdrasil/yggdrasil.sock",
  "unix:///var/run/yggdrasil.sock",
  "tcp://localhost:9001",
]
...
# Connect/listen port on yggdrasil network
listen_port = 4701
...
# List of peering protocols
# Supported are "tcp", "quic", "tls"
yggdrasil_protocols = [ "tcp", "quic" ]

# List of yggdrasil listen addresses, aka `Listen` in yggdrasil config
yggdrasil_listen = [ ]
...
# List of STUN servers
stun_servers = [
  ...
]
...
```

And you can configure them, of course.

```sh
$ yggdrasil-jumper --config <path> # or "-" for standard input
...
```

## Installation

- **Downloading:** Check the [Releases page](https://github.com/one-d-wide/yggdrasil-jumper/releases).
- **Compiling:**
  ```sh
  $ git clone https://github.com/one-d-wide/yggdrasil-jumper
  $ cd yggdrasil-jumper
  $ cargo build --bin yggdrasil-jumper --release
  $ sudo cp target/release/yggdrasil-jumper /usr/local/bin/yggdrasil-jumper
  ```

## Advanced configuration

- If you prefer to manage jumper independently of the yggdrasil router, use
`--reconnect` or `yggdrasil_admin_reconnect = true`. This tells jumper to
automatically reconnect if the yggdrasil router is restarted or yet to be
started.

- Whitelist the nodes jumper attempts to peer with: `whitelist = [ <ipv6
address> ]`. The node address itself and any address in it's subnet are both
accepted.

- Only connect to nodes that are actively advertise jumper support: set
`only_peers_advertising_jumper = true` (default is false), along with
`NodeInfo: { "jumper": true }` in the yggdrasil config file.

- Avoid repeated traversal attempts, if there already were n that failed:
`failed_yggdrasil_traversal_limit = n` (default is unlimited). The counter is
preserved between sessions for some time, and is reset if at least one
traversal succeeds.

- `yggdrasil_dpi` (highly experimental) - send network traffic over an
unreliable channel, reducing latency under load. Currently yggdrasil router
expects all communication between peers be conducted over a reliable channel.
This includes all traffic over yggdrasil network, which effectively conceals
packet loss and the real network bandwidth, leading to
[bufferbloat][bufferbloat].

[bufferbloat]: https://en.wikipedia.org/wiki/Bufferbloat

To address this issue jumper can analyze packets going through a peering,
extract the packets carrying network traffic, and send them directly over the
regular network infrastructure, which is better suited in managing bufferbloat.
This functionality is enabled by setting `yggdrasil_dpi = true`.

You should also limit the MTU of the yggdrasil TUN interface, so it doesn't
overflow the MTU of the regular network. Set `IfMTU: 1280` in yggdrasil config
or `ip link tun0 mtu 1280` (assuming regular network mtu is 1500). Option
`yggdrasil_dpi_udp_mtu = 1452` controls the maximum size of a packet
(containing headers added by yggdrasil router) that can be sent over the
regular network using UDP, and `yggdrasil_dpi_fallback_to_reliable = false`
(default is true) whether to fallback to reliable channel if received packet is
larger than udp mtu. This is configuration needed because jumper can't emit a
proper destination-unreachable packet itself in case udp mtu is exceeded, as
mandated by ip specification.

Minimal reproducible example to observe bufferbloat is to run something hungry
for bandwidth, like iperf3 or just `cat /dev/zero | nc -u <other node> 1234`,
while simultaneously monitoring the latency with ping. In my setup I got
latency of 1s-3s when running iperf3 without jumper, while in the same setup
but with jumper it's just 120ms (less than double the latency of the same link
without the load).

Caveats:
- If jumper very recently established connection, the yggdrasil router may
still continue to route traffic through other peers for some time, use `watch
yggdrasilctl getpeers` to verify which peerings are actually being used.
- Jumper may still be sending traffic over a reliable channel if it exceeds
provided udp mtu, in which case using --loglevel debug you'll see lines
containing "backed up", instead of "via shortcut".

P.S. The root of the problem is that yggdrasil doesn't correctly implements
buffering (in addition to relying on streaming data channel for regular
traffic), hence it suffers from [bufferbloat][bufferbloat]. This should
probably be addressed inside the yggdrasil router by implementing something
like [FQ-CoDel/RFC8290][fq_codel] or just delegating dealing with this issue to
the network layer as jumper does.

P.P.S. At least on Linux, network interfaces already have associated [network
scheduler][network-scheduler] with proper queue management, but the yggdrasil
router circumvents it by eagerly reading the data into it's own internal
buffers.

[fq_codel]: https://www.rfc-editor.org/rfc/rfc8290
[network-scheduler]: https://en.wikipedia.org/wiki/Network_scheduler

## Details

<details>
<summary>External address lookup</summary>

In order to know what address to use with [NAT traversal][nat-traversal], jumper
must know self external internet address and port. This task is performed using
[STUN][stun] protocol. STUN supports both UDP and TCP, although many STUN
servers doesn't support the latter. Jumper only needs one supporting UDP.

[stun]: https://en.wikipedia.org/wiki/STUN

You can check compatibility using `stun-test` binary from this repository.

```sh
$ cargo build --bin stun-test --release
$ # ./target/release/stun-test
```

`stun-test` takes network protocol and [STUN] server(s) as argument and outputs
resolved address.

```sh
$ stun-test --udp --print-servers stun.l.google.com:3478
stun.l.google.com:3478 244.13.30.107:28674
```

You can also take servers from hardcoded defaults or your configuration.

```sh
$ stun-test --udp --default
244.13.30.107:28674
...
```

If `stun-test` fails to connect to any server it will print error and exit with
code `1`.

```sh
$ stun-test --udp stun.l.google.com:3478 127.0.0.1:3478
244.13.30.107:28674
ERROR While resolving {server=127.0.0.1:3478}: Failed to connect: Time out
```

It also checks whether all queried servers return the same address, this can be
disabled by adding `--no-check`.

```sh
$ stun-test --udp stun.l.google.com:3478 false.resolver
244.13.30.107:28674
ERROR While resolving {server=false.resolver}: {received=0.0.0.0:0}: Previously resolved addresses do not match
```

`stun-test` can act as a minimal STUN server.

```sh
$ stun-test --udp --serve --port 3478
 INFO Serving at port 3478 (UDP)
```

</details>

<details>
<summary>Establishing direct connection over the internet (NAT traversal)</summary>

NAT traversal procedure is described in [this paper](https://bford.info/pub/net/p2pnat),
here is a short summary for TCP:

- Create and bind listen and connection sockets to the same port (using
`SO_REUSEADDR` and `SO_REUSEPORT` flags).
- Lookup self external address and port.
- Exchange external addresses with the peer (over a separate channel).
- Try to connect to the peer and listen for connection simultaneously.

</details>
