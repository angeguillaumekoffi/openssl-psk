"""
Core TLS-PSK implementation.

Two paths:
  - Python 3.13+  : native ssl.SSLContext.set_psk_*_callback() API
  - Python 3.10-12: ctypes calls to libssl (SSL_CTX_set_psk_*_callback)
                    requires CPython (PySSLContext memory layout assumption)

PSK argument shapes
-------------------
Client (``psk`` parameter of :func:`wrap_socket_client`):
  - ``bytes``             – just the key; identity sent to server is ``b''``
  - ``(bytes, bytes)``    – (psk, identity) tuple
  - ``callable``          – ``hint -> psk`` or ``hint -> (psk, identity)``
                            where *hint* is ``bytes | None``

Server (``psk`` parameter of :func:`wrap_socket_server`):
  - ``bytes``             – same key accepted for every identity
  - ``callable``          – ``identity -> psk`` where *identity* is ``bytes``
"""

import ctypes
import ctypes.util
import platform
import ssl
import socket

# Python 3.13 added native PSK support to the ssl module
_HAS_NATIVE_PSK = hasattr(ssl.SSLContext, "set_psk_client_callback")

# ── ctypes setup (only needed on Python < 3.13) ──────────────────────────────

if not _HAS_NATIVE_PSK:
    if platform.python_implementation() != "CPython":
        raise RuntimeError(
            "openssl-psk requires CPython on Python < 3.13. "
            "Upgrade to Python 3.13+ for interpreter-independent PSK support."
        )

    _libssl_name = ctypes.util.find_library("ssl")
    if not _libssl_name:
        raise RuntimeError(
            "openssl-psk: cannot find libssl. "
            "Ensure OpenSSL is installed (e.g. apt install libssl-dev)."
        )
    _libssl = ctypes.CDLL(_libssl_name, use_errno=True)

    # c_void_p for writable output buffers; c_char_p only for read-only inputs
    _PSK_CLIENT_CB = ctypes.CFUNCTYPE(
        ctypes.c_uint,    # returns psk_len (0 = authentication failure)
        ctypes.c_void_p,  # ssl*
        ctypes.c_char_p,  # hint     (in,  read-only)
        ctypes.c_void_p,  # identity (out, writable buffer)
        ctypes.c_uint,    # max_identity_len
        ctypes.c_void_p,  # psk      (out, writable buffer)
        ctypes.c_uint,    # max_psk_len
    )
    _PSK_SERVER_CB = ctypes.CFUNCTYPE(
        ctypes.c_uint,    # returns psk_len (0 = authentication failure)
        ctypes.c_void_p,  # ssl*
        ctypes.c_char_p,  # identity (in, read-only)
        ctypes.c_void_p,  # psk      (out, writable buffer)
        ctypes.c_uint,    # max_psk_len
    )

    _libssl.SSL_CTX_set_psk_client_callback.restype = None
    _libssl.SSL_CTX_set_psk_client_callback.argtypes = [ctypes.c_void_p, _PSK_CLIENT_CB]
    _libssl.SSL_CTX_set_psk_server_callback.restype = None
    _libssl.SSL_CTX_set_psk_server_callback.argtypes = [ctypes.c_void_p, _PSK_SERVER_CB]
    _libssl.SSL_CTX_use_psk_identity_hint.restype = ctypes.c_int
    _libssl.SSL_CTX_use_psk_identity_hint.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    # CPython's PySSLContext struct (_ssl.c):
    #   PyObject_HEAD  →  ob_refcnt + ob_type  =  2 × sizeof(void*)
    #   SSL_CTX *ctx   →  immediately follows
    _PTR_SIZE = ctypes.sizeof(ctypes.c_void_p)

    # Keeps ctypes callback objects alive for the lifetime of their SSL context;
    # without this the GC frees them and OpenSSL calls a dangling function pointer.
    _cb_refs: dict = {}

    def _ssl_ctx_ptr(ctx: ssl.SSLContext) -> int:
        ptr = ctypes.c_void_p.from_address(id(ctx) + 2 * _PTR_SIZE).value
        if not ptr:
            raise RuntimeError(
                "openssl-psk: SSL_CTX* extracted as NULL — the CPython internal "
                "PySSLContext layout may have changed. Please open an issue at "
                "https://github.com/angekoffi/openssl-psk with your Python version."
            )
        return ptr


# ── helpers ───────────────────────────────────────────────────────────────────

def _to_bytes(value: "bytes | str") -> bytes:
    return value.encode() if isinstance(value, str) else bytes(value)


def _make_ctx(ciphers: str, server_side: bool) -> ssl.SSLContext:
    proto = ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT
    ctx = ssl.SSLContext(proto)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(ciphers)
    return ctx


def _make_client_resolver(psk) -> "callable":
    """Normalise any client *psk* shape into ``hint -> (psk_bytes, id_bytes)``."""
    if callable(psk):
        def _resolver(hint):
            result = psk(hint)
            if isinstance(result, tuple):
                return _to_bytes(result[0]), _to_bytes(result[1])
            return _to_bytes(result), b""
        return _resolver
    if isinstance(psk, tuple):
        psk_b, identity_b = _to_bytes(psk[0]), _to_bytes(psk[1])
        return lambda hint: (psk_b, identity_b)
    psk_b = _to_bytes(psk)
    return lambda hint: (psk_b, b"")


def _make_server_resolver(psk) -> "callable":
    """Normalise any server *psk* shape into ``identity_bytes -> psk_bytes``."""
    if callable(psk):
        return lambda identity: _to_bytes(psk(identity))
    psk_b = _to_bytes(psk)
    return lambda identity: psk_b


# ── public API ────────────────────────────────────────────────────────────────

def wrap_socket_client(
    sock: socket.socket,
    psk: "bytes | tuple | callable",
    ciphers: str = "PSK-AES128-CBC-SHA256",
    server_hostname: "str | None" = None,
) -> ssl.SSLSocket:
    """Wrap *sock* with TLS-PSK as a client.

    Performs the TLS handshake before returning the ssl.SSLSocket.

    Args:
        sock:             Connected TCP socket to wrap.
        psk:              Pre-shared key — three accepted shapes:

                          * ``bytes`` — just the key; identity sent as ``b''``
                          * ``(psk, identity)`` tuple of bytes
                          * ``callable`` — ``hint -> psk`` or
                            ``hint -> (psk, identity)`` where *hint*
                            is ``bytes | None``

        ciphers:          OpenSSL cipher string; must include a PSK cipher.
        server_hostname:  SNI hostname passed to ``wrap_socket``.
    """
    resolver = _make_client_resolver(psk)
    ctx = _make_ctx(ciphers, server_side=False)

    if _HAS_NATIVE_PSK:
        # Python 3.13+: callback receives (socket, hint) as str|None, returns (psk, identity)
        def _native_cb(socket_obj, hint: "str | None"):
            psk_b, id_b = resolver(hint.encode() if hint else None)
            return psk_b, id_b.decode() if id_b else ""
        ctx.set_psk_client_callback(_native_cb)
    else:
        ptr = _ssl_ctx_ptr(ctx)

        def _cb(ssl_ptr, hint, id_buf, max_id_len, psk_buf, max_psk_len):
            psk_b, id_b = resolver(hint)  # hint is bytes|None (ctypes c_char_p)
            id_bytes = id_b[: max_id_len - 1]
            psk_bytes = psk_b[:max_psk_len]
            ctypes.memmove(id_buf, id_bytes + b"\x00", len(id_bytes) + 1)
            ctypes.memmove(psk_buf, psk_bytes, len(psk_bytes))
            return len(psk_bytes)

        cb = _PSK_CLIENT_CB(_cb)
        _libssl.SSL_CTX_set_psk_client_callback(ptr, cb)
        _cb_refs[id(ctx)] = cb

    ssl_sock = ctx.wrap_socket(
        sock, server_hostname=server_hostname, do_handshake_on_connect=False
    )
    ssl_sock.do_handshake()
    return ssl_sock


def wrap_socket_server(
    sock: socket.socket,
    psk: "bytes | callable",
    hint: "str | None" = None,
    ciphers: str = "PSK-AES128-CBC-SHA256",
) -> ssl.SSLSocket:
    """Wrap *sock* with TLS-PSK as a server.

    Performs the TLS handshake before returning the ssl.SSLSocket.

    Args:
        sock:    Accepted TCP socket to wrap (from ``socket.accept()``).
        psk:     Pre-shared key — two accepted shapes:

                 * ``bytes`` — same key accepted for every client identity
                 * ``callable`` — ``identity -> psk`` where *identity* is
                   ``bytes``; raise an exception to reject the client.

        hint:    PSK identity hint sent to clients (optional).
        ciphers: OpenSSL cipher string; must include a PSK cipher.
    """
    resolver = _make_server_resolver(psk)
    ctx = _make_ctx(ciphers, server_side=True)

    if _HAS_NATIVE_PSK:
        # Python 3.13+: callback receives (socket, identity) as str, returns psk bytes
        def _native_cb(socket_obj, identity: str) -> bytes:
            return resolver(identity.encode())
        ctx.set_psk_server_callback(_native_cb, identity_hint=hint)
    else:
        ptr = _ssl_ctx_ptr(ctx)

        if hint:
            _libssl.SSL_CTX_use_psk_identity_hint(ptr, hint.encode())

        def _cb(ssl_ptr, identity, psk_buf, max_psk_len):
            try:
                # identity is bytes|None (ctypes c_char_p)
                psk_b = resolver(identity if identity is not None else b"")
                psk_b = psk_b[:max_psk_len]
                ctypes.memmove(psk_buf, psk_b, len(psk_b))
                return len(psk_b)
            except Exception:
                return 0  # signals authentication failure to OpenSSL

        cb = _PSK_SERVER_CB(_cb)
        _libssl.SSL_CTX_set_psk_server_callback(ptr, cb)
        _cb_refs[id(ctx)] = cb

    ssl_sock = ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
    ssl_sock.do_handshake()
    return ssl_sock
