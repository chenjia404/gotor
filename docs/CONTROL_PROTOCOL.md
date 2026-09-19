# Control Protocol Documentation

## Overview

The go-tor client implements a subset of the Tor control protocol for monitoring and management. The control protocol allows external applications to query status, configure settings, and monitor events.

## Protocol Specification

The control protocol follows the [Tor Control Protocol Specification](https://spec.torproject.org/control-spec) and uses a text-based, line-oriented protocol over TCP.

## Connection

Default address: `127.0.0.1:9051`

Configure with the `-control-port` command-line option:
```bash
./bin/tor-client -control-port 9051
```

## Authentication

Currently, the implementation accepts any authentication (including no password) for development purposes. In production, authentication should be implemented using one of these methods:

- **NULL**: No authentication (current implementation)
- **HASHEDPASSWORD**: Password-based authentication (planned)
- **COOKIE**: Cookie file authentication (planned)

## Supported Commands

### PROTOCOLINFO

Get information about the control protocol version and authentication methods.

**Syntax:**
```
PROTOCOLINFO [version]
```

**Example:**
```
> PROTOCOLINFO
< 250-PROTOCOLINFO 1
< 250-AUTH METHODS=NULL
< 250-VERSION Tor="0.4.9.11 (gotor)"
< 250 OK
```

### AUTHENTICATE

Authenticate to the control port. Currently accepts any authentication.

**Syntax:**
```
AUTHENTICATE [token]
```

**Example:**
```
> AUTHENTICATE
< 250 OK
```

### GETINFO

Query various information about the Tor client state.

**Syntax:**
```
GETINFO key [key ...]
```

**Supported Keys:**

| Key | Description | Example Value |
|-----|-------------|---------------|
| `version` | 实现版本 | `Tor 0.4.9.11 (gotor)` |
| `status/circuit-established` | Whether circuits are available | `0` or `1` |
| `status/enough-dir-info` | 已有验签共识且能选 Guard 则为 1，否则 0（不写死） | `0` 或 `1` |
| `traffic/read` | 入口 OR 已读字节 | `4096` |
| `traffic/written` | 入口 OR 已写字节 | `2048` |
| `net/listeners/socks` | SOCKS 实际绑定（TCP 或 unix 路径，不写死 127.0.0.1） | `127.0.0.1:9050` |
| `net/listeners/control` | 控制口实际绑定（TCP 或 unix 路径） | `127.0.0.1:9051` |
| `net/listeners/httptunnel` | HTTPTunnelPort 实际绑定；未开为空 | `127.0.0.1:9080` |
| `net/listeners/dns` | DNSPort 实际绑定；未开为空 | `127.0.0.1:5353` |
| `net/listeners/or` | ORPort 实际绑定；未开或 ClientOnly 为空 | `0.0.0.0:9001` |
| `net/listeners/dir` | DirPort 实际绑定；未开或 ClientOnly 为空 | `0.0.0.0:9030` |
| `config-file` | 实际 torrc 路径；未从文件加载则为空（不用 DataDirectory 冒充） | `/etc/tor/torrc` |

**Example:**
```
> GETINFO version status/circuit-established
< 250-version=Tor 0.4.9.11 (gotor)
< 250 status/circuit-established=1
```

### GETCONF

Query configuration values.

**Syntax:**
```
GETCONF key [key ...]
```

**Example:**
```
> GETCONF SocksPort ORPort Nickname
< 250-SocksPort=9050
< 250-ORPort=9001
< 250 Nickname=gotorRelay
```

已实现键返回当前配置（端口未开为 `0`；`DisableNetwork`/`ClientOnly`/`ExitRelay` 为 `0`/`1`）；未知键按 control-spec 返回空值。

### SETCONF

Set configuration values.

**Syntax:**
```
SETCONF key=value [key=value ...]
```

**Example:**
```
> SETCONF LogLevel=debug
< 250 OK
```

运行时可写键立即生效；`SocksPort`/`ORPort`/`ExitPolicy`/`MyFamily`/`FamilyID` 等需重启，会报错而非假装已改出口策略或家族。

### SETEVENTS

Subscribe to asynchronous event notifications.

**Syntax:**
```
SETEVENTS [event ...]
```

**Supported Events:**
- `CIRC` - Circuit status changes
- `STREAM` - Stream status changes
- `ORCONN` - OR connection status
- `BW` - Bandwidth usage
- `NEWDESC` - New relay descriptors
- `GUARD` - Guard node changes
- `NS` - Network status changes

**Example:**
```
> SETEVENTS CIRC STREAM
< 250 OK
```

Events will be sent asynchronously as they occur. Each event is prefixed with `650` status code.

### QUIT

Close the control connection.

**Syntax:**
```
QUIT
```

**Example:**
```
> QUIT
< 250 closing connection
```

## Response Codes

The control protocol uses numeric response codes similar to SMTP:

| Code | Meaning |
|------|---------|
| `250` | OK - Command successful |
| `500` | Syntax error |
| `510` | Unrecognized command |
| `514` | Authentication required |
| `552` | Unrecognized key or invalid argument |

## Multi-line Responses

Responses can span multiple lines. All lines except the last use `code-` format, and the last line uses `code ` (space) format:

```
250-version=Tor 0.4.9.11 (gotor)
250-status/circuit-established=1
250 status/enough-dir-info=1
```

## Example Session

Here's a complete example session:

```bash
$ telnet localhost 9051
Connected to localhost.
< 250 OK

> PROTOCOLINFO
< 250-PROTOCOLINFO 1
< 250-AUTH METHODS=NULL
< 250-VERSION Tor="0.4.9.11 (gotor)"
< 250 OK

> AUTHENTICATE
< 250 OK

> GETINFO version status/circuit-established
< 250-version=Tor 0.4.9.11 (gotor)
< 250 status/circuit-established=1

> SETEVENTS CIRC
< 250 OK

> QUIT
< 250 closing connection
Connection closed.
```

## Using with Tools

### netcat

```bash
(echo "AUTHENTICATE"; echo "GETINFO version"; echo "QUIT") | nc localhost 9051
```

### Python

```python
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('localhost', 9051))

# Read greeting
print(sock.recv(1024).decode())

# Authenticate
sock.send(b'AUTHENTICATE\r\n')
print(sock.recv(1024).decode())

# Get info
sock.send(b'GETINFO version\r\n')
print(sock.recv(1024).decode())

# Quit
sock.send(b'QUIT\r\n')
print(sock.recv(1024).decode())

sock.close()
```

### stem (Python Tor Control Library)

```python
from stem.control import Controller

with Controller.from_port(port=9051) as controller:
    controller.authenticate()
    
    version = controller.get_info("version")
    print(f"Version: {version}")
    
    circuits = controller.get_info("status/circuit-established")
    print(f"Circuits established: {circuits}")
```

## Implementation Status

| Feature | Status |
|---------|--------|
| Basic protocol server | ✅ Complete |
| PROTOCOLINFO command | ✅ Complete |
| AUTHENTICATE command | ✅ Complete (NULL auth only) |
| GETINFO command | ✅ Partial (core keys implemented) |
| GETCONF command | ✅ 已实现键返回当前值（含 HTTPTunnelPort/DNSPort） |
| SETCONF command | ✅ 可写子集立即生效；监听端口需重启 |
| SETEVENTS command | ✅ Complete |
| QUIT command | ✅ Complete |
| Event notifications | ✅ Complete (CIRC, STREAM, BW, ORCONN, NEWDESC, GUARD, NS) |
| Password authentication | ⏳ Planned |
| Cookie authentication | ⏳ Planned |
| Circuit management commands | ⏳ Planned |
| Configuration management | ⏳ Planned |

## Security Considerations

**Development Mode:** The current implementation accepts connections without authentication. This is suitable for:
- Development and testing
- Single-user systems
- Containerized deployments with network isolation

**Production Requirements:**
- Implement proper authentication (password or cookie)
- Use firewall rules to restrict access to `127.0.0.1`
- Consider TLS for remote connections
- Implement rate limiting

## Future Enhancements

### Phase 7.1 ✅ (Complete)
- ✅ Event notification system (CIRC, STREAM, ORCONN, BW, NEWDESC, GUARD, NS)
- Extended GETINFO keys (circuit details, stream info)
- Full configuration management
- Password/cookie authentication

### Phase 7.2 (Medium-term)
- Circuit management commands (EXTENDCIRCUIT, CLOSECIRCUIT)
- Stream management commands
- Signal handling (NEWNYM, RELOAD, SHUTDOWN)
- Hidden service management (ADD_ONION, DEL_ONION)

### Phase 7.3 (Long-term)
- Control port over Unix domain socket
- TLS support for remote connections
- Rate limiting and DoS protection
- Audit logging

## References

- [Tor Control Protocol Specification](https://spec.torproject.org/control-spec)
- [Tor Control Port Usage](https://2019.www.torproject.org/docs/tor-manual.html.en#ControlPort)
- [stem - Python controller library](https://stem.torproject.org/)

## Support

For issues or questions about the control protocol:
- GitHub Issues: https://github.com/opd-ai/go-tor/issues
- Tag with `control-protocol` label
