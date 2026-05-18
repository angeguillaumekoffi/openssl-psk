"""
openssl-psk — TLS-PSK socket wrapper for Python 3.10+

Pure-Python, no compiled extensions. Uses the native ssl module API on
Python 3.13+ and falls back to direct libssl ctypes calls on 3.10–3.12.
"""

from ._psk import wrap_socket_client, wrap_socket_server

__all__ = ["wrap_socket_client", "wrap_socket_server"]
__version__ = "0.1.0"
