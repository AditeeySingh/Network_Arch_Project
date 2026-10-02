"""BHTTP/1 Server Implementation (bserve).

Listens on TCP, decodes binary request frames, enforces path traversal security,
supports persistent connections, streaming unknown-frame discarding,
and robust error handling (400, 403, 404, 405, 500).
"""

from __future__ import annotations

import mimetypes
import os
import socket
import sys
import threading
from typing import Optional, Tuple

from protocol import (
    FRAME_HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
    STATUS_BAD_REQUEST,
    STATUS_FORBIDDEN,
    STATUS_INTERNAL_ERROR,
    STATUS_METHOD_NOT_ALLOWED,
    STATUS_NOT_FOUND,
    STATUS_OK,
    TYPE_REQUEST,
    ConnectionClosedError,
    MalformedFrameError,
    OversizedPayloadError,
    ProtocolError,
    Request,
    Response,
    TruncatedFrameError,
    decode_frame_header,
    decode_request_payload,
    discard_exact,
    encode_response_frame,
    read_exact,
    write_exact,
)


def resolve_safe_path(web_root: str, req_path: str) -> Tuple[int, Optional[str], bytes]:
    """Safely map request path to a file under web_root.

    Returns (status_code, content_type, body_bytes).
    Enforces directory traversal containment.
    """
    abs_root = os.path.realpath(web_root)

    if "\x00" in req_path:
        return STATUS_BAD_REQUEST, "text/plain", b"400 Bad Request: Path contains NUL bytes\n"

    if not req_path.startswith("/"):
        return STATUS_BAD_REQUEST, "text/plain", b"400 Bad Request: Path must begin with '/'\n"

    # Strip leading slash to join with web_root
    rel_path = req_path.lstrip("/")
    target = os.path.realpath(os.path.join(abs_root, rel_path))

    # Path traversal verification
    try:
        common = os.path.commonpath([abs_root, target])
    except ValueError:
        return STATUS_BAD_REQUEST, "text/plain", b"400 Bad Request: Path traversal forbidden\n"

    if common != abs_root:
        return STATUS_BAD_REQUEST, "text/plain", b"400 Bad Request: Path traversal forbidden\n"

    # Directory fallback to index.html
    if os.path.isdir(target):
        index_candidate = os.path.join(target, "index.html")
        if os.path.isfile(index_candidate):
            target = index_candidate
        else:
            return STATUS_NOT_FOUND, "text/plain", b"404 Not Found: Directory index missing\n"

    if not os.path.isfile(target):
        return STATUS_NOT_FOUND, "text/plain", b"404 Not Found: File not found\n"

    try:
        # Check size before reading into memory to prevent unconstrained RAM allocation
        file_size = os.path.getsize(target)
        if file_size > MAX_PAYLOAD_SIZE - 256:
            return (
                STATUS_INTERNAL_ERROR,
                "text/plain",
                b"500 Internal Server Error: File exceeds 16 MiB protocol limit\n",
            )

        with open(target, "rb") as f:
            content = f.read()

        mime, _ = mimetypes.guess_type(target)
        if not mime:
            mime = "application/octet-stream"
        return STATUS_OK, mime, content
    except PermissionError:
        return STATUS_FORBIDDEN, "text/plain", b"403 Forbidden: File access permission denied\n"
    except Exception:
        return STATUS_INTERNAL_ERROR, "text/plain", b"500 Internal Server Error\n"


def handle_client_connection(
    conn: socket.socket, addr: Tuple[str, int], web_root: str, timeout: float = 30.0
) -> None:
    """Handle a single persistent client TCP connection."""
    conn.settimeout(timeout)
    try:
        while True:
            try:
                # 1. Read exactly 7 header bytes
                header_bytes = read_exact(conn, FRAME_HEADER_SIZE)
                payload_len, frame_type, flags, stream_id = decode_frame_header(header_bytes)
            except ConnectionClosedError:
                # Normal persistent connection termination by peer at frame boundary
                break
            except TruncatedFrameError:
                # Connection dropped mid-frame: loss of synchronization
                break
            except socket.timeout:
                # Inactive client timeout (Slowloris mitigation)
                break
            except (MalformedFrameError, OversizedPayloadError) as e:
                # Send 400 Bad Request response before closing connection
                err_resp = Response(
                    status_code=STATUS_BAD_REQUEST,
                    headers=[("server", "bserve/1.0"), ("content-type", "text/plain")],
                    body=f"400 Bad Request: {str(e)}\n".encode("utf-8"),
                    stream_id=0,
                )
                try:
                    write_exact(conn, encode_response_frame(err_resp))
                except Exception:
                    pass
                break

            # 2. Unknown-Frame Forward Compatibility Rule:
            # Any frame type other than 0x01 (REQUEST) MUST be skipped cleanly
            if frame_type != TYPE_REQUEST:
                try:
                    # Stream discard in 64 KiB chunks without buffering into RAM
                    discard_exact(conn, payload_len)
                except TruncatedFrameError:
                    break
                continue

            # 3. Read valid REQUEST frame payload
            try:
                payload = read_exact(conn, payload_len)
            except TruncatedFrameError:
                break

            # 4. Decode request payload
            try:
                req = decode_request_payload(payload, stream_id=stream_id)
            except MalformedFrameError as e:
                err_resp = Response(
                    status_code=STATUS_BAD_REQUEST,
                    headers=[("server", "bserve/1.0"), ("content-type", "text/plain")],
                    body=f"400 Bad Request: {str(e)}\n".encode("utf-8"),
                    stream_id=stream_id,
                )
                try:
                    write_exact(conn, encode_response_frame(err_resp))
                except Exception:
                    pass
                continue

            # 5. Method enforcement (GET and HEAD supported; others return 405)
            if req.method not in ("GET", "HEAD"):
                err_resp = Response(
                    status_code=STATUS_METHOD_NOT_ALLOWED,
                    headers=[
                        ("server", "bserve/1.0"),
                        ("content-type", "text/plain"),
                        ("allow", "GET, HEAD"),
                    ],
                    body=f"405 Method Not Allowed: {req.method} is not supported\n".encode("utf-8"),
                    stream_id=req.stream_id,
                )
                try:
                    write_exact(conn, encode_response_frame(err_resp))
                except Exception:
                    pass
                continue

            # 6. Process resource mapping
            status, mime, body = resolve_safe_path(web_root, req.path)
            content_length = len(body)

            # For HEAD requests, compute content-length but omit body bytes
            if req.method == "HEAD":
                body = b""

            resp_headers = [
                ("server", "bserve/1.0"),
                ("content-type", mime or "application/octet-stream"),
                ("content-length", str(content_length)),
            ]

            resp = Response(
                status_code=status,
                headers=resp_headers,
                body=body,
                stream_id=req.stream_id,
            )

            try:
                write_exact(conn, encode_response_frame(resp))
            except OversizedPayloadError:
                err_resp = Response(
                    status_code=STATUS_INTERNAL_ERROR,
                    headers=[("server", "bserve/1.0"), ("content-type", "text/plain")],
                    body=b"500 Internal Server Error: File exceeds 16 MiB payload limit\n",
                    stream_id=req.stream_id,
                )
                try:
                    write_exact(conn, encode_response_frame(err_resp))
                except Exception:
                    pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def run_server(web_root: str, port: int, host: str = "0.0.0.0") -> None:
    """Start the BHTTP/1 server socket and accept connections."""
    abs_root = os.path.realpath(web_root)
    if not os.path.isdir(abs_root):
        print(f"Error: web root directory '{web_root}' does not exist", file=sys.stderr)
        sys.exit(1)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind((host, port))
        server_sock.listen(128)
        print(f"bserve listening on {host}:{port} serving {abs_root}", file=sys.stderr)

        while True:
            conn, addr = server_sock.accept()
            client_thread = threading.Thread(
                target=handle_client_connection,
                args=(conn, addr, abs_root),
                daemon=True,
            )
            client_thread.start()
    except KeyboardInterrupt:
        print("\nShutting down bserve...", file=sys.stderr)
    finally:
        server_sock.close()


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: ./bserve <web_root> <port>", file=sys.stderr)
        sys.exit(1)

    web_root = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print(f"Error: port must be an integer, got '{sys.argv[2]}'", file=sys.stderr)
        sys.exit(1)

    run_server(web_root, port)


if __name__ == "__main__":
    main()
