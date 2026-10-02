"""BHTTP/1 Server Implementation (bserve).

Listens on TCP, decodes binary request frames, enforces path traversal security,
supports persistent connections, and cleanly skips unknown frame types.
"""

from __future__ import annotations

import mimetypes
import os
import socket
import sys
import threading
from typing import Optional, Tuple

from protocol import (
    STATUS_BAD_REQUEST,
    STATUS_INTERNAL_ERROR,
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
    decode_request_payload,
    encode_response_frame,
    read_frame,
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
        with open(target, "rb") as f:
            content = f.read()

        mime, _ = mimetypes.guess_type(target)
        if not mime:
            mime = "application/octet-stream"
        return STATUS_OK, mime, content
    except PermissionError:
        return STATUS_BAD_REQUEST, "text/plain", b"400 Bad Request: File access permission denied\n"
    except Exception:
        return STATUS_INTERNAL_ERROR, "text/plain", b"500 Internal Server Error\n"


def handle_client_connection(conn: socket.socket, addr: Tuple[str, int], web_root: str) -> None:
    """Handle a single persistent client TCP connection."""
    try:
        while True:
            try:
                frame = read_frame(conn)
            except ConnectionClosedError:
                # Normal persistent connection termination by peer
                break
            except TruncatedFrameError:
                # Connection dropped mid-frame
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

            # Unknown Frame Rule (Forward Compatibility):
            # A receiver meeting a frame type it does not know MUST skip it cleanly!
            if frame.frame_type != TYPE_REQUEST:
                # read_frame has already consumed the payload according to payload_length
                # Discard and continue to next frame on this persistent connection
                continue

            # Decode request payload
            try:
                req = decode_request_payload(frame.payload, stream_id=frame.stream_id)
            except MalformedFrameError as e:
                err_resp = Response(
                    status_code=STATUS_BAD_REQUEST,
                    headers=[("server", "bserve/1.0"), ("content-type", "text/plain")],
                    body=f"400 Bad Request: {str(e)}\n".encode("utf-8"),
                    stream_id=frame.stream_id,
                )
                write_exact(conn, encode_response_frame(err_resp))
                continue

            # Process request against safe filesystem
            status, mime, body = resolve_safe_path(web_root, req.path)

            resp_headers = [
                ("server", "bserve/1.0"),
                ("content-type", mime or "application/octet-stream"),
                ("content-length", str(len(body))),
            ]

            resp = Response(
                status_code=status,
                headers=resp_headers,
                body=body,
                stream_id=req.stream_id,
            )

            write_exact(conn, encode_response_frame(resp))
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
