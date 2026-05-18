# openssl-psk

TLS-PSK (pre-shared key) socket wrapper for Python 3.10+.  
No compiled extensions — pure Python using the standard `ssl` module and `ctypes`.

```
pip install openssl-psk
```

---

## Why this exists

The standard `ssl` module has no PSK support below Python 3.13, and the only
existing library ([sslpsk](https://github.com/drbild/sslpsk)) is broken on
Python 3.12+ because its `wrap_socket()` creates a default context with
`check_hostname=True`, which raises `ValueError` for server-side sockets.

`openssl-psk` fixes this by:
- Calling `libssl`'s `SSL_CTX_set_psk_*_callback` directly via `ctypes` on
  Python 3.10–3.12
- Using the native `SSLContext.set_psk_*_callback()` API transparently on
  Python 3.13+

No C extension to compile. Just `pip install`.

---

## Quick start

### Client

```python
import socket
from openssl_psk import wrap_socket_client

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.connect(("192.168.1.1", 4116))

# simplest form — just the key
ssl_sock = wrap_socket_client(tcp, psk=b"84155C93FDB08FB384B75C44A7D3B625")

ssl_sock.sendall(b"GET /resource HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n")
print(ssl_sock.recv(4096))
ssl_sock.close()
```

### Server

```python
import socket
from openssl_psk import wrap_socket_server

PSK_DB = {
    b"device-001": b"84155C93FDB08FB384B75C44A7D3B625",
    b"device-002": b"0AE9DF505E3D3B9A5305409550D42C96",
}

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind(("0.0.0.0", 4116))
tcp.listen(5)

while True:
    conn, addr = tcp.accept()
    ssl_sock = wrap_socket_server(
        conn,
        psk=lambda identity: PSK_DB[identity],
        hint="my-server",                   # optional identity hint sent to clients
    )
    data = ssl_sock.recv(4096)
    ssl_sock.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
    ssl_sock.close()
```

---

## API

### `wrap_socket_client(sock, psk, ciphers=..., server_hostname=None)`

| Parameter         | Type                          | Description                                              |
|-------------------|-------------------------------|----------------------------------------------------------|
| `sock`            | `socket.socket`               | Connected TCP socket to wrap                             |
| `psk`             | `bytes \| tuple \| callable`  | Pre-shared key — see accepted shapes below               |
| `ciphers`         | `str`                         | OpenSSL cipher string (default: `PSK-AES128-CBC-SHA256`) |
| `server_hostname` | `str \| None`                 | SNI hostname passed to `wrap_socket`                     |

**Accepted `psk` shapes:**

```python
# 1. Just the key — identity sent to server is b''
wrap_socket_client(sock, psk=b"mypsk")

# 2. Key + client identity
wrap_socket_client(sock, psk=(b"mypsk", b"myidentity"))

# 3. Callable: server hint → key
PSK_FOR = {b"server1": b"abcdef", b"server2": b"123456"}
wrap_socket_client(sock, psk=lambda hint: PSK_FOR[hint])
```

Returns an `ssl.SSLSocket` after completing the handshake.

---

### `wrap_socket_server(sock, psk, hint=None, ciphers=...)`

| Parameter | Type                    | Description                                              |
|-----------|-------------------------|----------------------------------------------------------|
| `sock`    | `socket.socket`         | Accepted TCP socket to wrap (from `socket.accept()`)     |
| `psk`     | `bytes \| callable`     | Pre-shared key — see accepted shapes below               |
| `hint`    | `str \| None`           | PSK identity hint sent to clients (optional)             |
| `ciphers` | `str`                   | OpenSSL cipher string (default: `PSK-AES128-CBC-SHA256`) |

**Accepted `psk` shapes:**

```python
# 1. Just the key — same key accepted for every client identity
wrap_socket_server(sock, psk=b"mypsk")

# 2. Callable: client identity → key (raise to reject)
PSK_FOR = {b"clientA": b"abcdef", b"clientB": b"123456"}
wrap_socket_server(sock, psk=lambda identity: PSK_FOR[identity])
```

Returns an `ssl.SSLSocket` after completing the handshake.  
When using a callable, raise any exception to reject the client.

---

## Compatibility

| Python | Mechanism                               | CPython only? |
|--------|-----------------------------------------|---------------|
| 3.10   | ctypes → `libssl`                       | Yes           |
| 3.11   | ctypes → `libssl`                       | Yes           |
| 3.12   | ctypes → `libssl`                       | Yes           |
| 3.13+  | `ssl.SSLContext.set_psk_*_callback()`   | No            |

The ctypes path reads the `SSL_CTX*` pointer out of CPython's `PySSLContext`
struct at a fixed offset that has been stable across CPython 3.x. It will
raise a `RuntimeError` with a clear message if the pointer is NULL, so you
will know immediately if anything changes in a future CPython release.

Requires OpenSSL ≥ 1.0.1 (for PSK cipher support).

---

## Running the tests

```bash
pip install pytest
pytest
```

---

## License

MIT — see [LICENSE](LICENSE).
