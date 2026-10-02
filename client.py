"""BHTTP/1 Client Implementation (bcurl).

Connects over TCP, sends binary request frames, reads binary responses,
outputs response body to stdout, logs annotated hexdumps on -v,
and strictly enforces single-connection persistent TCP rules.
"""

from __future__ import annotations

import argparse
import socket
import sys
from typing import Optional, Tuple
from urllib.parse import urlparse

from protocol import (
    FRAME_HEADER_SIZE,
    STATUS_OK,
    TYPE_REQUEST,
    TYPE_RESPONSE,
    ConnectionClosedError,
    MalformedFrameError,
    ProtocolError,
    Request,
    Response,
    TruncatedFrameError,
    decode_response_payload,
    encode_frame,
    encode_request_frame,
    encode_response_frame,
    format_hexdump,
    read_frame,
    write_exact,
)


def parse_target(target: str) -> Tuple[str, int, str]:
    """Parse target string like 'localhost:9000/index.html' or 'http://localhost:9000/test'.

    Returns (host, port, path).
    """
    if "://" not in target:
        target = "bhttp://" + target

    parsed = urlparse(target)
    host = parsed.hostname or "localhost"
    port = parsed.port or 9000
    path = parsed.path
    if not path:
        path = "/"
    if parsed.query:
        path += f"?{parsed.query}"

    return host, port, path


def hexdump_annotated_frame(frame_bytes: bytes, direction: str) -> str:
    """Produce an annotated, human-readable breakdown of a frame for verbose output."""
    lines = []
    lines.append(f"--- {direction} Frame ({len(frame_bytes)} bytes) ---")
    lines.append(format_hexdump(frame_bytes))
    return "\n".join(lines)


def send_request(
    sock: socket.socket,
    req: Request,
    verbose: bool = False,
) -> Response:
    """Send request frame and read response frame over the given TCP socket.

    Cleanly skips any intervening unknown frame types per SPEC.md.
    """
    req_frame_bytes = encode_request_frame(req)
    if verbose:
        print(hexdump_annotated_frame(req_frame_bytes, "SEND REQUEST"), file=sys.stderr)
        print(f"> {req.method} {req.path} (Stream {req.stream_id})", file=sys.stderr)
        for h_name, h_val in req.headers:
            print(f"> {h_name}: {h_val}", file=sys.stderr)

    write_exact(sock, req_frame_bytes)

    # Read response frames in loop to handle forward-compatibility unknown frames
    while True:
        frame = read_frame(sock)

        full_frame_bytes = encode_frame(
            frame.frame_type, frame.flags, frame.stream_id, frame.payload
        )

        if frame.frame_type != TYPE_RESPONSE:
            # Unknown frame type: safely skipped by read_frame!
            if verbose:
                print(
                    hexdump_annotated_frame(
                        full_frame_bytes, f"RECV UNKNOWN (0x{frame.frame_type:02X})"
                    ),
                    file=sys.stderr,
                )
                print(
                    f"* Skipping unknown frame type: 0x{frame.frame_type:02X} (length {frame.payload_length})",
                    file=sys.stderr,
                )
            continue

        if verbose:
            print(hexdump_annotated_frame(full_frame_bytes, "RECV RESPONSE"), file=sys.stderr)

        # Received RESPONSE frame
        resp = decode_response_payload(frame.payload, stream_id=frame.stream_id)
        if verbose:
            print(f"< Status: {resp.status_code}", file=sys.stderr)
            for h_name, h_val in resp.headers:
                print(f"< {h_name}: {h_val}", file=sys.stderr)
            print(f"< Body size: {len(resp.body)} bytes", file=sys.stderr)

        return resp


def execute_bcurl(
    host: str,
    port: int,
    path: str,
    verbose: bool = False,
    existing_sock: Optional[socket.socket] = None,
    stream_id: int = 1,
) -> Tuple[Response, socket.socket]:
    """Execute bcurl request. Returns (Response, sock)."""
    sock = existing_sock
    if sock is None:
        if verbose:
            print(f"* Connecting to {host}:{port}...", file=sys.stderr)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        if verbose:
            print(f"* Connected to {host}:{port}", file=sys.stderr)

    headers = [
        ("host", f"{host}:{port}"),
        ("user-agent", "bcurl/1.0"),
        ("accept", "*/*"),
    ]

    req = Request(method="GET", path=path, headers=headers, stream_id=stream_id)
    resp = send_request(sock, req, verbose=verbose)
    return resp, sock


def main() -> None:
    parser = argparse.ArgumentParser(
        description="bcurl - BHTTP/1 binary client",
        usage="%(prog)s [-v] <host>:<port><path>",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print annotated hexdump and frame trace to stderr",
    )
    parser.add_argument(
        "target",
        help="Target URL (e.g. localhost:9000/index.html)",
    )

    args = parser.parse_args()

    try:
        host, port, path = parse_target(args.target)
    except Exception as e:
        print(f"Error parsing target: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        resp, sock = execute_bcurl(host, port, path, verbose=args.verbose)
    except Exception as e:
        print(f"Connection/protocol error: {e}", file=sys.stderr)
        sys.exit(2)
    finally:
        try:
            if "sock" in locals() and sock:
                sock.close()
        except Exception:
            pass

    # Write binary body directly to stdout
    sys.stdout.buffer.write(resp.body)
    sys.stdout.buffer.flush()

    # Exit non-zero on 4xx / 5xx
    if resp.status_code >= 400:
        if args.verbose:
            print(f"* Exiting with error status {resp.status_code}", file=sys.stderr)
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
