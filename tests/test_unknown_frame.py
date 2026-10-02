"""Tests for unknown frame forward compatibility (skipping unknown frame types)."""

import unittest
import socket
import threading
import time
from protocol import (
    FRAME_HEADER_SIZE,
    TYPE_REQUEST,
    TYPE_RESPONSE,
    FLAG_NONE,
    STATUS_OK,
    Request,
    Response,
    encode_frame,
    encode_request_frame,
    encode_response_frame,
    read_frame,
    write_exact,
)
from server import handle_client_connection
from client import send_request


class TestUnknownFrameHandling(unittest.TestCase):
    def setUp(self):
        self.server_sock, self.client_sock = socket.socketpair()

    def tearDown(self):
        self.server_sock.close()
        self.client_sock.close()

    def test_client_skips_unknown_frame_from_server(self):
        """Client must skip unrecognized frame types sent by server before RESPONSE."""
        req = Request(method="GET", path="/index.html", stream_id=1)

        def mock_server():
            # Read request frame
            req_frame = read_frame(self.server_sock)

            # Send an unknown frame type (0x42: FUTURE_EXPERIMENTAL_FRAME)
            unknown_payload = b"Future protocol extension data with arbitrary binary \x00\xff"
            unknown_frame = encode_frame(0x42, FLAG_NONE, 1, unknown_payload)
            write_exact(self.server_sock, unknown_frame)

            # Send another unknown frame type (0x77: PING)
            write_exact(self.server_sock, encode_frame(0x77, FLAG_NONE, 0, b"PING"))

            # Finally send the real RESPONSE frame
            resp = Response(
                status_code=STATUS_OK,
                headers=[("server", "mock-server/1.0")],
                body=b"Real response content",
                stream_id=1,
            )
            write_exact(self.server_sock, encode_response_frame(resp))

        t = threading.Thread(target=mock_server)
        t.start()

        # Client should skip 0x42 and 0x77 and receive the valid RESPONSE
        resp = send_request(self.client_sock, req, verbose=False)
        t.join()

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.body, b"Real response content")

    def test_server_skips_unknown_frame_from_client(self):
        """Server must cleanly skip unrecognized frame types and process subsequent REQUEST."""
        # Run server in thread
        t = threading.Thread(
            target=handle_client_connection,
            args=(self.server_sock, ("127.0.0.1", 12345), "./www"),
            daemon=True,
        )
        t.start()

        # Client sends unknown frame (0x33: TELEMETRY) with 64 bytes of payload
        unknown_frame = encode_frame(0x33, FLAG_NONE, 0, b"X" * 64)
        write_exact(self.client_sock, unknown_frame)

        # Client then sends a valid REQUEST frame
        req = Request(method="GET", path="/hello.txt", stream_id=5)
        write_exact(self.client_sock, encode_request_frame(req))

        # Server should have skipped 0x33 and answered the REQUEST
        resp_frame = read_frame(self.client_sock)
        self.assertEqual(resp_frame.frame_type, TYPE_RESPONSE)
        self.assertEqual(resp_frame.stream_id, 5)

        self.client_sock.close()
        t.join(timeout=1.0)


if __name__ == "__main__":
    unittest.main()
