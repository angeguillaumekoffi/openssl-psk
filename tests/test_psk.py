"""
Integration tests for openssl-psk.

All tests use a loopback TCP socket pair — no external server needed.
Each test spins up a server thread, connects a client, and asserts the
round-trip payload matches.

PSK shapes under test
---------------------
Client:
  bytes            wrap_socket_client(sock, psk=b'key')
  (bytes, bytes)   wrap_socket_client(sock, psk=(b'key', b'identity'))
  callable→bytes   wrap_socket_client(sock, psk=lambda hint: b'key')
  callable→tuple   wrap_socket_client(sock, psk=lambda hint: (b'key', b'id'))

Server:
  bytes            wrap_socket_server(sock, psk=b'key')
  callable         wrap_socket_server(sock, psk=lambda identity: PSK_DB[identity])
"""

import socket
import ssl
import threading
import pytest

from openssl_psk import wrap_socket_client, wrap_socket_server

PSK       = b"84155C93FDB08FB384B75C44A7D3B625"
IDENTITY  = b"device-001"
CIPHERS   = "PSK-AES128-CBC-SHA256"

PSK_DB = {
    b"device-001": b"84155C93FDB08FB384B75C44A7D3B625",
    b"device-002": b"0AE9DF505E3D3B9A5305409550D42C96",
}

_PORT = [20000]


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def loopback():
    port = _PORT[0]
    _PORT[0] += 1

    srv_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_tcp.bind(("127.0.0.1", port))
    srv_tcp.listen(1)

    cli_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cli_tcp.connect(("127.0.0.1", port))

    conn, _ = srv_tcp.accept()
    srv_tcp.close()
    yield conn, cli_tcp

    for s in (conn, cli_tcp):
        try:
            s.close()
        except Exception:
            pass


# ── helpers ───────────────────────────────────────────────────────────────────

class _Server(threading.Thread):
    def __init__(self, conn, psk, **kw):
        super().__init__(daemon=True)
        self.conn, self.psk, self.kw = conn, psk, kw
        self.received = None
        self.error    = None

    def run(self):
        try:
            s = wrap_socket_server(self.conn, psk=self.psk, **self.kw)
            self.received = s.recv(256)
            s.sendall(b"pong")
            s.close()
        except Exception as e:
            self.error = e


def _roundtrip(loopback, client_psk, server_psk, payload=b"ping",
               hint=None, server_hostname="127.0.0.1"):
    """Start server thread, wrap client, exchange payload, return (received, response)."""
    conn, cli_tcp = loopback
    t = _Server(conn, psk=server_psk, hint=hint)
    t.start()

    ssl_cli = wrap_socket_client(
        cli_tcp, psk=client_psk,
        ciphers=CIPHERS, server_hostname=server_hostname,
    )
    ssl_cli.sendall(payload)
    response = ssl_cli.recv(256)
    ssl_cli.close()

    t.join(timeout=3)
    if t.error:
        raise t.error
    return t.received, response


# ── server shape: bytes ───────────────────────────────────────────────────────

class TestServerBytes:
    """Server psk=b'key' — same key for every client."""

    def test_client_bytes(self, loopback):
        received, response = _roundtrip(loopback, client_psk=PSK, server_psk=PSK)
        assert received == b"ping"
        assert response == b"pong"

    def test_client_tuple(self, loopback):
        received, _ = _roundtrip(
            loopback,
            client_psk=(PSK, IDENTITY),
            server_psk=PSK,
        )
        assert received == b"ping"

    def test_client_callable_returns_bytes(self, loopback):
        received, _ = _roundtrip(
            loopback,
            client_psk=lambda hint: PSK,
            server_psk=PSK,
        )
        assert received == b"ping"

    def test_client_callable_returns_tuple(self, loopback):
        received, _ = _roundtrip(
            loopback,
            client_psk=lambda hint: (PSK, IDENTITY),
            server_psk=PSK,
        )
        assert received == b"ping"


# ── server shape: callable ────────────────────────────────────────────────────

class TestServerCallable:
    """Server psk=lambda identity: PSK_DB[identity]."""

    def test_client_bytes(self, loopback):
        # identity is b'' when client sends only a key — server must handle it
        received, _ = _roundtrip(
            loopback,
            client_psk=PSK,
            server_psk=lambda identity: PSK,  # ignore identity, return fixed key
        )
        assert received == b"ping"

    def test_client_tuple_identity_resolved(self, loopback):
        seen = []

        def lookup(identity):
            seen.append(identity)
            return PSK_DB[identity]

        received, _ = _roundtrip(
            loopback,
            client_psk=(PSK, IDENTITY),
            server_psk=lookup,
        )
        assert received == b"ping"
        assert seen == [IDENTITY]

    def test_client_callable_hint_received(self, loopback):
        """Hint set on the server should arrive in the client callable."""
        hints_seen = []

        def client_psk(hint):
            hints_seen.append(hint)
            return PSK

        _roundtrip(
            loopback,
            client_psk=client_psk,
            server_psk=PSK,
            hint="my-server",
        )
        # hint arrives as bytes from OpenSSL
        assert hints_seen == [b"my-server"]

    def test_unknown_identity_rejected(self, loopback):
        conn, cli_tcp = loopback

        def strict(identity):
            if identity not in PSK_DB:
                raise KeyError(identity)
            return PSK_DB[identity]

        t = _Server(conn, psk=strict)
        t.start()

        with pytest.raises(ssl.SSLError):
            wrap_socket_client(
                cli_tcp,
                psk=(PSK, b"unknown-device"),
                ciphers=CIPHERS,
                server_hostname="127.0.0.1",
            )
        t.join(timeout=3)


# ── input type normalisation ──────────────────────────────────────────────────

class TestInputTypes:
    """str inputs must be accepted everywhere bytes are."""

    def test_str_psk_bytes_shape(self, loopback):
        _roundtrip(loopback, client_psk=PSK.decode(), server_psk=PSK)

    def test_str_psk_tuple_shape(self, loopback):
        _roundtrip(
            loopback,
            client_psk=(PSK.decode(), IDENTITY.decode()),
            server_psk=PSK,
        )

    def test_str_psk_server(self, loopback):
        _roundtrip(loopback, client_psk=PSK, server_psk=PSK.decode())

    def test_callable_returning_str(self, loopback):
        _roundtrip(
            loopback,
            client_psk=lambda hint: PSK.decode(),
            server_psk=lambda identity: PSK.decode(),
        )


# ── custom payload ────────────────────────────────────────────────────────────

def test_custom_payload(loopback):
    payload = b"Hello, PSK world! \x00\xff"
    received, _ = _roundtrip(loopback, client_psk=PSK, server_psk=PSK, payload=payload)
    assert received == payload
