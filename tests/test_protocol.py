"""Unit tests for protocol.py - BHTTP/1 protocol encoding, decoding, and framing."""

import unittest
import struct
import io
import socket
from protocol import (
    FRAME_HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
    TYPE_REQUEST,
    TYPE_RESPONSE,
    FLAG_NONE,
    FLAG_END_STREAM,
    METHOD_GET,
    METHOD_HEAD,
    METHOD_POST,
    STATUS_OK,
    STATUS_BAD_REQUEST,
    STATUS_NOT_FOUND,
    STATIC_HEADER_TABLE,
    STATIC_HEADER_NAME_TO_ID,
    Frame,
    Request,
    Response,
    ProtocolError,
    ConnectionClosedError,
    TruncatedFrameError,
    MalformedFrameError,
    OversizedPayloadError,
    encode_frame_header,
    decode_frame_header,
    encode_frame,
    encode_headers,
    decode_headers,
    encode_request_payload,
    decode_request_payload,
    encode_request_frame,
    encode_response_payload,
    decode_response_payload,
    encode_response_frame,
    read_exact,
    write_exact,
    read_frame,
    format_hexdump,
)


class TestProtocolFraming(unittest.TestCase):
    def test_header_encode_decode_basic(self):
        payload_len = 42
        frame_type = TYPE_REQUEST
        flags = FLAG_NONE
        stream_id = 1

        header = encode_frame_header(payload_len, frame_type, flags, stream_id)
        self.assertEqual(len(header), FRAME_HEADER_SIZE)
        # Expected byte layout:
        # byte 0..2: 00 00 2A
        # byte 3: 01
        # byte 4: 00
        # byte 5..6: 00 01
        self.assertEqual(header, b"\x00\x00\x2a\x01\x00\x00\x01")

        dec_len, dec_type, dec_flags, dec_sid = decode_frame_header(header)
        self.assertEqual(dec_len, payload_len)
        self.assertEqual(dec_type, frame_type)
        self.assertEqual(dec_flags, flags)
        self.assertEqual(dec_sid, stream_id)

    def test_24bit_payload_boundaries(self):
        # Zero length
        hdr_0 = encode_frame_header(0, TYPE_RESPONSE, FLAG_END_STREAM, 65535)
        self.assertEqual(decode_frame_header(hdr_0), (0, TYPE_RESPONSE, FLAG_END_STREAM, 65535))

        # Max 24-bit payload
        hdr_max = encode_frame_header(MAX_PAYLOAD_SIZE, 0x05, 0x00, 100)
        self.assertEqual(decode_frame_header(hdr_max), (MAX_PAYLOAD_SIZE, 0x05, 0x00, 100))

        # Overflow
        with self.assertRaises(OversizedPayloadError):
            encode_frame_header(MAX_PAYLOAD_SIZE + 1, 0x01, 0x00, 1)

        with self.assertRaises(OversizedPayloadError):
            encode_frame_header(-1, 0x01, 0x00, 1)

    def test_truncated_header_decode(self):
        with self.assertRaises(MalformedFrameError):
            decode_frame_header(b"\x00\x00\x05\x01\x00")  # 5 bytes instead of 7


class TestHeaderEncoding(unittest.TestCase):
    def test_static_table_headers(self):
        headers = [
            ("Host", "localhost:9000"),
            ("User-Agent", "bcurl/1.0"),
            ("Content-Type", "text/html; charset=utf-8"),
        ]
        encoded = encode_headers(headers)
        # Count byte = 3
        self.assertEqual(encoded[0], 3)

        decoded, offset = decode_headers(encoded, 0)
        self.assertEqual(offset, len(encoded))
        self.assertEqual(len(decoded), 3)
        self.assertEqual(decoded[0], ("host", "localhost:9000"))
        self.assertEqual(decoded[1], ("user-agent", "bcurl/1.0"))
        self.assertEqual(decoded[2], ("content-type", "text/html; charset=utf-8"))

    def test_literal_and_mixed_headers(self):
        headers = [
            ("Host", "example.com"),
            ("X-Custom-Header", "SecretValue123"),
            ("Accept", "*/*"),
        ]
        encoded = encode_headers(headers)
        decoded, offset = decode_headers(encoded, 0)
        self.assertEqual(offset, len(encoded))
        self.assertEqual(len(decoded), 3)
        self.assertEqual(decoded[0], ("host", "example.com"))
        self.assertEqual(decoded[1], ("x-custom-header", "SecretValue123"))
        self.assertEqual(decoded[2], ("accept", "*/*"))

    def test_malformed_header_tag(self):
        # 1 header, tag 0x0B (11, outside 1..10 static range and not 0x00)
        corrupted = b"\x01\x0b\x00\x04test"
        with self.assertRaises(MalformedFrameError):
            decode_headers(corrupted, 0)

    def test_truncated_headers(self):
        # Header count 2, but payload ends
        truncated = b"\x02\x01\x00\x04test"
        with self.assertRaises(MalformedFrameError):
            decode_headers(truncated, 0)


class TestRequestEncoding(unittest.TestCase):
    def test_request_roundtrip(self):
        req = Request(
            method="GET",
            path="/index.html",
            headers=[("host", "localhost:9000"), ("accept", "text/html")],
            stream_id=42,
        )
        frame_bytes = encode_request_frame(req)
        self.assertEqual(len(frame_bytes), FRAME_HEADER_SIZE + len(encode_request_payload(req)))

        # Parse header
        p_len, f_type, flags, s_id = decode_frame_header(frame_bytes[:FRAME_HEADER_SIZE])
        self.assertEqual(f_type, TYPE_REQUEST)
        self.assertEqual(s_id, 42)

        # Parse payload
        dec_req = decode_request_payload(frame_bytes[FRAME_HEADER_SIZE:], stream_id=s_id)
        self.assertEqual(dec_req.method, "GET")
        self.assertEqual(dec_req.path, "/index.html")
        self.assertEqual(dec_req.stream_id, 42)
        self.assertEqual(dec_req.headers, [("host", "localhost:9000"), ("accept", "text/html")])

    def test_invalid_request_paths(self):
        # Path without leading slash
        req_bad = Request(method="GET", path="index.html")
        with self.assertRaises(MalformedFrameError):
            encode_request_payload(req_bad)

        # Path with NUL byte
        req_nul = Request(method="GET", path="/test\x00evil")
        with self.assertRaises(MalformedFrameError):
            encode_request_payload(req_nul)


class TestResponseEncoding(unittest.TestCase):
    def test_response_roundtrip(self):
        body = b"<!DOCTYPE html><html><body><h1>Hello BHTTP!</h1></body></html>"
        resp = Response(
            status_code=STATUS_OK,
            headers=[("server", "bserve/1.0"), ("content-type", "text/html")],
            body=body,
            stream_id=1,
        )
        frame_bytes = encode_response_frame(resp)
        p_len, f_type, flags, s_id = decode_frame_header(frame_bytes[:FRAME_HEADER_SIZE])
        self.assertEqual(f_type, TYPE_RESPONSE)
        self.assertEqual(s_id, 1)

        dec_resp = decode_response_payload(frame_bytes[FRAME_HEADER_SIZE:], stream_id=s_id)
        self.assertEqual(dec_resp.status_code, 200)
        self.assertEqual(dec_resp.headers, [("server", "bserve/1.0"), ("content-type", "text/html")])
        self.assertEqual(dec_resp.body, body)
        self.assertEqual(dec_resp.stream_id, 1)

    def test_arbitrary_binary_body(self):
        # Body containing arbitrary non-text binary bytes including NULs and 0xFF
        binary_body = bytes([i % 256 for i in range(2048)])
        resp = Response(status_code=200, headers=[], body=binary_body, stream_id=7)
        frame_bytes = encode_response_frame(resp)
        p_len, f_type, flags, s_id = decode_frame_header(frame_bytes[:FRAME_HEADER_SIZE])
        dec_resp = decode_response_payload(frame_bytes[FRAME_HEADER_SIZE:], stream_id=s_id)
        self.assertEqual(dec_resp.body, binary_body)


class TestExactIO(unittest.TestCase):
    def test_socket_exact_read_and_fragmentation(self):
        # Create a connected socketpair
        server_sock, client_sock = socket.socketpair()
        try:
            # Fragmented send: 7 bytes header split across 3 sends
            server_sock.sendall(b"\x00\x00")
            server_sock.sendall(b"\x05\x01")
            server_sock.sendall(b"\x00\x00\x01")

            header = read_exact(client_sock, 7)
            self.assertEqual(header, b"\x00\x00\x05\x01\x00\x00\x01")

            # Clean EOF detection on boundary
            server_sock.close()
            with self.assertRaises(ConnectionClosedError):
                read_exact(client_sock, 7)
        finally:
            client_sock.close()


if __name__ == "__main__":
    unittest.main()
