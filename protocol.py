"""BHTTP/1 Protocol Implementation.

This module provides the shared binary framing, encoding, decoding,
and exact network I/O functions for BHTTP/1 as specified in SPEC.md.
"""

from __future__ import annotations

import io
import socket
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ==============================================================================
# Protocol Constants
# ==============================================================================

FRAME_HEADER_SIZE = 7
MAX_PAYLOAD_SIZE = 0xFFFFFF  # 24-bit max: 16,777,215 bytes (~16 MiB)

# Frame Types
TYPE_REQUEST = 0x01
TYPE_RESPONSE = 0x02

# Frame Flags
FLAG_NONE = 0x00
FLAG_END_STREAM = 0x01

# HTTP-like Methods
METHOD_GET = 0x01
METHOD_HEAD = 0x02
METHOD_POST = 0x03

METHOD_TO_NAME = {
    METHOD_GET: "GET",
    METHOD_HEAD: "HEAD",
    METHOD_POST: "POST",
}

NAME_TO_METHOD = {
    "GET": METHOD_GET,
    "HEAD": METHOD_HEAD,
    "POST": METHOD_POST,
}

# Static HPACK-inspired Header Table (IDs 1 through 10)
STATIC_HEADER_TABLE = {
    1: "host",
    2: "user-agent",
    3: "content-type",
    4: "content-length",
    5: "connection",
    6: "accept",
    7: "server",
    8: "date",
    9: "last-modified",
    10: "etag",
}

STATIC_HEADER_NAME_TO_ID = {name: idx for idx, name in STATIC_HEADER_TABLE.items()}
STATIC_HEADER_ID_TO_NAME = STATIC_HEADER_TABLE

# Status Codes
STATUS_OK = 200
STATUS_BAD_REQUEST = 400
STATUS_NOT_FOUND = 404
STATUS_METHOD_NOT_ALLOWED = 405
STATUS_INTERNAL_ERROR = 500


# ==============================================================================
# Protocol Exceptions
# ==============================================================================

class ProtocolError(Exception):
    """Base class for BHTTP/1 protocol errors."""


class ConnectionClosedError(ProtocolError):
    """Raised when the peer closes the TCP connection cleanly."""


class TruncatedFrameError(ProtocolError):
    """Raised when connection ends prematurely during frame read."""


class MalformedFrameError(ProtocolError):
    """Raised when frame header, payload, or headers violate specification."""


class OversizedPayloadError(ProtocolError):
    """Raised when payload length exceeds the protocol limit."""


# ==============================================================================
# Data Structures
# ==============================================================================

@dataclass
class Frame:
    payload_length: int
    frame_type: int
    flags: int
    stream_id: int
    payload: bytes


@dataclass
class Request:
    method: str
    path: str
    headers: List[Tuple[str, str]] = field(default_factory=list)
    stream_id: int = 1


@dataclass
class Response:
    status_code: int
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    stream_id: int = 1


# ==============================================================================
# Low-Level Exact Network I/O
# ==============================================================================

def read_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Read exactly `num_bytes` from socket.

    Handles TCP stream fragmentation cleanly.
    Raises ConnectionClosedError if connection closes at boundary (0 bytes read).
    Raises TruncatedFrameError if connection closes prematurely (partial read).
    """
    if num_bytes < 0:
        raise ValueError("num_bytes cannot be negative")
    if num_bytes == 0:
        return b""

    chunks: List[bytes] = []
    bytes_read = 0

    while bytes_read < num_bytes:
        to_read = min(num_bytes - bytes_read, 65536)
        chunk = sock.recv(to_read)
        if not chunk:
            if bytes_read == 0:
                raise ConnectionClosedError("Connection closed cleanly by peer")
            raise TruncatedFrameError(
                f"Unexpected EOF: expected {num_bytes} bytes, received {bytes_read} bytes"
            )
        chunks.append(chunk)
        bytes_read += len(chunk)

    return b"".join(chunks)


def write_exact(sock: socket.socket, data: bytes) -> None:
    """Send all `data` bytes over socket, handling partial writes."""
    view = memoryview(data)
    total_sent = 0
    total_len = len(data)
    while total_sent < total_len:
        sent = sock.send(view[total_sent:])
        if sent == 0:
            raise ConnectionClosedError("Socket connection broken during send")
        total_sent += sent


# ==============================================================================
# Frame Header Encoding / Decoding
# ==============================================================================

def encode_frame_header(payload_length: int, frame_type: int, flags: int, stream_id: int) -> bytes:
    """Encode a 7-byte BHTTP/1 frame header."""
    if payload_length < 0 or payload_length > MAX_PAYLOAD_SIZE:
        raise OversizedPayloadError(f"Payload length {payload_length} exceeds limit {MAX_PAYLOAD_SIZE}")
    if frame_type < 0 or frame_type > 0xFF:
        raise ValueError(f"Invalid frame type: {frame_type}")
    if flags < 0 or flags > 0xFF:
        raise ValueError(f"Invalid flags: {flags}")
    if stream_id < 0 or stream_id > 0xFFFF:
        raise ValueError(f"Invalid stream ID: {stream_id}")

    # Byte 0..2: 24-bit payload length (Big-Endian)
    len_msb = (payload_length >> 16) & 0xFF
    len_mid = (payload_length >> 8) & 0xFF
    len_lsb = payload_length & 0xFF

    # Byte 3..6: Type (8), Flags (8), Stream ID (16, Big-Endian)
    header = struct.pack("!BBB B B H", len_msb, len_mid, len_lsb, frame_type, flags, stream_id)
    return header


def decode_frame_header(header_bytes: bytes) -> Tuple[int, int, int, int]:
    """Decode a 7-byte BHTTP/1 frame header into (payload_length, frame_type, flags, stream_id)."""
    if len(header_bytes) != FRAME_HEADER_SIZE:
        raise MalformedFrameError(
            f"Frame header must be exactly {FRAME_HEADER_SIZE} bytes, got {len(header_bytes)}"
        )

    len_msb, len_mid, len_lsb, frame_type, flags, stream_id = struct.unpack(
        "!BBB B B H", header_bytes
    )
    payload_length = (len_msb << 16) | (len_mid << 8) | len_lsb

    return payload_length, frame_type, flags, stream_id


def encode_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    """Encode a complete BHTTP/1 frame (7-byte header + payload)."""
    header = encode_frame_header(len(payload), frame_type, flags, stream_id)
    return header + payload


def read_frame(sock: socket.socket) -> Frame:
    """Read a single frame from the socket according to BHTTP/1 framing rules."""
    header_bytes = read_exact(sock, FRAME_HEADER_SIZE)
    payload_len, frame_type, flags, stream_id = decode_frame_header(header_bytes)
    payload = read_exact(sock, payload_len)
    return Frame(
        payload_length=payload_len,
        frame_type=frame_type,
        flags=flags,
        stream_id=stream_id,
        payload=payload,
    )


# ==============================================================================
# Header Encoding / Decoding (Compact Static Table & Literals)
# ==============================================================================

def encode_headers(headers: List[Tuple[str, str]]) -> bytes:
    """Encode header list using static-table indices and length-prefixed literals."""
    if len(headers) > 255:
        raise MalformedFrameError("Header count cannot exceed 255")

    buf = io.BytesIO()
    buf.write(struct.pack("!B", len(headers)))

    for name, value in headers:
        name_clean = name.strip().lower()
        value_bytes = value.encode("utf-8")
        if len(value_bytes) > 0xFFFF:
            raise MalformedFrameError(f"Header value too long: {len(value_bytes)} bytes")

        if name_clean in STATIC_HEADER_NAME_TO_ID:
            name_id = STATIC_HEADER_NAME_TO_ID[name_clean]
            # Case A: 1 byte ID + 2 bytes value length + value bytes
            buf.write(struct.pack("!B H", name_id, len(value_bytes)))
            buf.write(value_bytes)
        else:
            name_bytes = name_clean.encode("utf-8")
            if len(name_bytes) == 0 or len(name_bytes) > 255:
                raise MalformedFrameError(f"Invalid header name length: {len(name_bytes)}")
            # Case B: 0x00 + 1 byte name length + name bytes + 2 bytes value length + value bytes
            buf.write(struct.pack("!B B", 0x00, len(name_bytes)))
            buf.write(name_bytes)
            buf.write(struct.pack("!H", len(value_bytes)))
            buf.write(value_bytes)

    return buf.getvalue()


def decode_headers(data: bytes, offset: int = 0) -> Tuple[List[Tuple[str, str]], int]:
    """Decode header entries from data starting at offset.

    Returns (headers_list, next_offset).
    """
    total_len = len(data)
    if offset >= total_len:
        raise MalformedFrameError("Missing header count byte in payload")

    count = data[offset]
    offset += 1
    headers: List[Tuple[str, str]] = []

    for _ in range(count):
        if offset >= total_len:
            raise MalformedFrameError("Truncated header entry in payload")

        name_id = data[offset]
        offset += 1

        if name_id == 0x00:
            # Literal header: Name Length (1B) + Name + Value Length (2B) + Value
            if offset >= total_len:
                raise MalformedFrameError("Truncated literal header name length")
            name_len = data[offset]
            offset += 1
            if name_len == 0 or offset + name_len > total_len:
                raise MalformedFrameError("Truncated literal header name")
            try:
                name = data[offset : offset + name_len].decode("utf-8")
            except UnicodeDecodeError as e:
                raise MalformedFrameError("Header name contains invalid UTF-8") from e
            offset += name_len

            if offset + 2 > total_len:
                raise MalformedFrameError("Truncated literal header value length")
            (val_len,) = struct.unpack("!H", data[offset : offset + 2])
            offset += 2
            if offset + val_len > total_len:
                raise MalformedFrameError("Truncated literal header value")
            try:
                val = data[offset : offset + val_len].decode("utf-8")
            except UnicodeDecodeError as e:
                raise MalformedFrameError("Header value contains invalid UTF-8") from e
            offset += val_len
            headers.append((name.lower(), val))

        elif 1 <= name_id <= 10:
            name = STATIC_HEADER_ID_TO_NAME[name_id]
            if offset + 2 > total_len:
                raise MalformedFrameError("Truncated indexed header value length")
            (val_len,) = struct.unpack("!H", data[offset : offset + 2])
            offset += 2
            if offset + val_len > total_len:
                raise MalformedFrameError("Truncated indexed header value")
            try:
                val = data[offset : offset + val_len].decode("utf-8")
            except UnicodeDecodeError as e:
                raise MalformedFrameError("Header value contains invalid UTF-8") from e
            offset += val_len
            headers.append((name, val))

        else:
            raise MalformedFrameError(f"Unknown or unsupported header name ID: {name_id}")

    return headers, offset


# ==============================================================================
# Request Encoding / Decoding
# ==============================================================================

def encode_request_payload(req: Request) -> bytes:
    """Encode Request object into binary request payload."""
    method_id = NAME_TO_METHOD.get(req.method.upper())
    if method_id is None:
        raise MalformedFrameError(f"Unsupported HTTP method: {req.method}")

    path_bytes = req.path.encode("utf-8")
    if len(path_bytes) == 0 or len(path_bytes) > 4096:
        raise MalformedFrameError(f"Path length {len(path_bytes)} out of bounds [1, 4096]")
    if b"\x00" in path_bytes:
        raise MalformedFrameError("Path must not contain NUL bytes")
    if not req.path.startswith("/"):
        raise MalformedFrameError("Path must start with '/'")

    buf = io.BytesIO()
    buf.write(struct.pack("!B H", method_id, len(path_bytes)))
    buf.write(path_bytes)
    buf.write(encode_headers(req.headers))
    return buf.getvalue()


def encode_request_frame(req: Request, flags: int = FLAG_NONE) -> bytes:
    """Encode a full BHTTP/1 frame for a Request."""
    payload = encode_request_payload(req)
    return encode_frame(TYPE_REQUEST, flags, req.stream_id, payload)


def decode_request_payload(payload: bytes, stream_id: int = 1) -> Request:
    """Decode binary request payload into a Request object."""
    total_len = len(payload)
    if total_len < 3:
        raise MalformedFrameError("Request payload too short for method and path length")

    method_id, path_len = struct.unpack("!B H", payload[0:3])
    method = METHOD_TO_NAME.get(method_id)
    if method is None:
        raise MalformedFrameError(f"Invalid method ID: {method_id}")

    offset = 3
    if offset + path_len > total_len:
        raise MalformedFrameError("Request payload truncated: path exceeds payload size")

    path_raw = payload[offset : offset + path_len]
    offset += path_len

    if b"\x00" in path_raw:
        raise MalformedFrameError("Path contains NUL byte")

    try:
        path = path_raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise MalformedFrameError("Path is not valid UTF-8") from e

    if not path.startswith("/"):
        raise MalformedFrameError("Path must begin with '/'")

    headers, offset = decode_headers(payload, offset)

    return Request(method=method, path=path, headers=headers, stream_id=stream_id)


# ==============================================================================
# Response Encoding / Decoding
# ==============================================================================

def encode_response_payload(resp: Response) -> bytes:
    """Encode Response object into binary response payload."""
    if resp.status_code < 100 or resp.status_code > 999:
        raise MalformedFrameError(f"Invalid status code: {resp.status_code}")

    buf = io.BytesIO()
    buf.write(struct.pack("!H", resp.status_code))
    buf.write(encode_headers(resp.headers))
    buf.write(resp.body)
    return buf.getvalue()


def encode_response_frame(resp: Response, flags: int = FLAG_NONE) -> bytes:
    """Encode a full BHTTP/1 frame for a Response."""
    payload = encode_response_payload(resp)
    return encode_frame(TYPE_RESPONSE, flags, resp.stream_id, payload)


def decode_response_payload(payload: bytes, stream_id: int = 1) -> Response:
    """Decode binary response payload into a Response object."""
    total_len = len(payload)
    if total_len < 3:  # 2 bytes status + at least 1 byte header count
        raise MalformedFrameError("Response payload too short for status and headers")

    (status_code,) = struct.unpack("!H", payload[0:2])
    headers, offset = decode_headers(payload, 2)
    body = payload[offset:]

    return Response(status_code=status_code, headers=headers, body=body, stream_id=stream_id)


# ==============================================================================
# Hexdump Utility
# ==============================================================================

def format_hexdump(data: bytes, width: int = 16) -> str:
    """Format bytes into canonical hexdump string with hex offsets and ASCII."""
    lines: List[str] = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_bytes = " ".join(f"{b:02X}" for b in chunk)
        ascii_chars = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04X}  {hex_bytes:<{width * 3}} |{ascii_chars}|")
    return "\n".join(lines)
