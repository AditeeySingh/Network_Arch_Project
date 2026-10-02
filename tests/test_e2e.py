"""End-to-End integration and adversarial test suite for BHTTP/1."""

import os
import socket
import subprocess
import sys
import threading
import time
import unittest

from protocol import (
    FRAME_HEADER_SIZE,
    FLAG_NONE,
    STATUS_BAD_REQUEST,
    STATUS_NOT_FOUND,
    STATUS_OK,
    TYPE_REQUEST,
    TYPE_RESPONSE,
    Request,
    Response,
    decode_response_payload,
    encode_frame,
    encode_frame_header,
    encode_request_frame,
    read_frame,
    write_exact,
)
from server import handle_client_connection
from client import execute_bcurl, send_request


class TestBHttpEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.web_root = os.path.abspath("./www")
        cls.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind to port 0 for automatic ephemeral port assignment
        cls.server_sock.bind(("127.0.0.1", 0))
        cls.port = cls.server_sock.getsockname()[1]
        cls.server_sock.listen(16)
        cls.running = True
        cls.accepted_connections_count = 0

        def server_worker():
            while cls.running:
                try:
                    conn, addr = cls.server_sock.accept()
                    cls.accepted_connections_count += 1
                    t = threading.Thread(
                        target=handle_client_connection,
                        args=(conn, addr, cls.web_root),
                        daemon=True,
                    )
                    t.start()
                except OSError:
                    break

        cls.server_thread = threading.Thread(target=server_worker, daemon=True)
        cls.server_thread.start()
        time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.running = False
        cls.server_sock.close()
        cls.server_thread.join(timeout=1.0)

    def test_01_get_index_html(self):
        resp, sock = execute_bcurl("127.0.0.1", self.port, "/index.html")
        sock.close()
        self.assertEqual(resp.status_code, 200)
        with open(os.path.join(self.web_root, "index.html"), "rb") as f:
            expected = f.read()
        self.assertEqual(resp.body, expected)

    def test_02_get_hello_txt(self):
        resp, sock = execute_bcurl("127.0.0.1", self.port, "/hello.txt")
        sock.close()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.body, b"Hello BHTTP/1!\n")

    def test_03_get_binary_test_bin(self):
        resp, sock = execute_bcurl("127.0.0.1", self.port, "/test.bin")
        sock.close()
        self.assertEqual(resp.status_code, 200)
        with open(os.path.join(self.web_root, "test.bin"), "rb") as f:
            expected = f.read()
        self.assertEqual(resp.body, expected)
        self.assertEqual(len(resp.body), 16384)

    def test_04_get_empty_file(self):
        resp, sock = execute_bcurl("127.0.0.1", self.port, "/empty.txt")
        sock.close()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.body, b"")

    def test_05_get_missing_resource_returns_404(self):
        resp, sock = execute_bcurl("127.0.0.1", self.port, "/nonexistent_file_404.html")
        sock.close()
        self.assertEqual(resp.status_code, 404)
        self.assertIn(b"404 Not Found", resp.body)

    def test_06_path_traversal_attempts_blocked(self):
        traversal_paths = [
            "/../secret.txt",
            "/../../etc/passwd",
            "/....//....//etc/shadow",
            "/index.html/../../../etc/hosts",
        ]
        for bad_path in traversal_paths:
            with self.subTest(path=bad_path):
                resp, sock = execute_bcurl("127.0.0.1", self.port, bad_path)
                sock.close()
                self.assertIn(resp.status_code, [400, 404])
                self.assertNotIn(b"root:", resp.body)

    def test_07_persistent_connection_multiple_requests(self):
        """Mandatory requirement: Multiple requests over the EXACT SAME TCP socket.
        
        Instrumented to verify:
        1. Only 1 connection is accepted by the server.
        2. Client socket fileno and local port remain identical across all requests.
        3. No secondary TCP connection is ever opened.
        """
        conn_count_start = self.accepted_connections_count
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", self.port))
        
        # Verify exactly one new connection was registered on the server
        time.sleep(0.05)
        self.assertEqual(self.accepted_connections_count, conn_count_start + 1)
        
        client_fd = sock.fileno()
        client_port = sock.getsockname()[1]
        self.assertGreater(client_fd, 0)

        try:
            # We will send 6 sequential requests across this single socket
            requests_to_send = [
                ("/hello.txt", 200, b"Hello BHTTP/1!\n"),
                ("/index.html", 200, None),
                ("/missing_one.txt", 404, None),
                ("/test.bin", 200, None),
                ("/empty.txt", 200, b""),
                ("/missing_two.txt", 404, None),
            ]

            for idx, (path, expected_status, expected_body) in enumerate(requests_to_send, start=1):
                req = Request(
                    method="GET",
                    path=path,
                    headers=[("host", f"127.0.0.1:{self.port}")],
                    stream_id=idx,
                )
                resp = send_request(sock, req, verbose=False)
                self.assertEqual(resp.stream_id, idx)
                self.assertEqual(resp.status_code, expected_status)
                if expected_body is not None:
                    self.assertEqual(resp.body, expected_body)

                # Crucial assertion: The TCP socket connection is unchanged
                self.assertEqual(sock.fileno(), client_fd)
                self.assertEqual(sock.getsockname()[1], client_port)
                self.assertEqual(self.accepted_connections_count, conn_count_start + 1)

        finally:
            sock.close()

    def test_08_adversarial_malformed_requests(self):
        """Test server defense against structurally corrupted frames."""
        # 1. Invalid method ID (0x99)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", self.port))
        try:
            # Method 0x99, path /hello.txt
            bad_payload = b"\x99\x00\x0a/hello.txt\x00"
            bad_frame = encode_frame(TYPE_REQUEST, FLAG_NONE, 1, bad_payload)
            write_exact(sock, bad_frame)

            resp_frame = read_frame(sock)
            resp = decode_response_payload(resp_frame.payload, stream_id=resp_frame.stream_id)
            self.assertEqual(resp.status_code, 400)
        finally:
            sock.close()

    def test_09_cli_bcurl_execution(self):
        """Test invoking ./bcurl as a real subprocess."""
        # Successful request
        cmd = [sys.executable, "./bcurl", f"127.0.0.1:{self.port}/hello.txt"]
        proc = subprocess.run(cmd, capture_output=True)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"Hello BHTTP/1!\n")

        # 404 request must exit non-zero
        cmd_404 = [sys.executable, "./bcurl", f"127.0.0.1:{self.port}/missing_file.html"]
        proc_404 = subprocess.run(cmd_404, capture_output=True)
        self.assertNotEqual(proc_404.returncode, 0)

        # Verbose flag test: stdout has body, stderr has hexdump trace
        cmd_v = [sys.executable, "./bcurl", "-v", f"127.0.0.1:{self.port}/hello.txt"]
        proc_v = subprocess.run(cmd_v, capture_output=True)
        self.assertEqual(proc_v.returncode, 0)
        self.assertEqual(proc_v.stdout, b"Hello BHTTP/1!\n")
        # Verbose flag test: stdout has body, stderr has hexdump trace
        cmd_v = [sys.executable, "./bcurl", "-v", f"127.0.0.1:{self.port}/hello.txt"]
        proc_v = subprocess.run(cmd_v, capture_output=True)
        self.assertEqual(proc_v.returncode, 0)
        self.assertEqual(proc_v.stdout, b"Hello BHTTP/1!\n")
        self.assertIn(b"SEND REQUEST Frame", proc_v.stderr)
        self.assertIn(b"Status: 200", proc_v.stderr)

    def test_10_head_request_returns_headers_and_empty_body(self):
        """HEAD request must compute content-length but return 0 body bytes."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", self.port))
        try:
            req = Request(
                method="HEAD",
                path="/hello.txt",
                headers=[("host", f"127.0.0.1:{self.port}")],
                stream_id=42,
            )
            resp = send_request(sock, req, verbose=False)
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.stream_id, 42)
            self.assertEqual(resp.body, b"")
            # Ensure content-length is present and equals 15 (size of "Hello BHTTP/1!\n")
            headers_dict = dict(resp.headers)
            self.assertEqual(headers_dict.get("content-length"), "15")
        finally:
            sock.close()

    def test_11_post_request_returns_405_method_not_allowed(self):
        """POST request must return 405 Method Not Allowed with Allow header."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", self.port))
        try:
            req = Request(
                method="POST",
                path="/hello.txt",
                headers=[("host", f"127.0.0.1:{self.port}")],
                stream_id=43,
            )
            resp = send_request(sock, req, verbose=False)
            self.assertEqual(resp.status_code, 405)
            self.assertEqual(resp.stream_id, 43)
            headers_dict = dict(resp.headers)
            self.assertEqual(headers_dict.get("allow"), "GET, HEAD")
        finally:
            sock.close()

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "Root user bypasses filesystem permission checks")
    def test_12_permission_denied_returns_403(self):
        """Unreadable file permissions must return 403 Forbidden."""
        test_file = os.path.join(self.web_root, "forbidden.txt")
        with open(test_file, "w") as f:
            f.write("Secret data")
        os.chmod(test_file, 0o000)
        try:
            resp, sock = execute_bcurl("127.0.0.1", self.port, "/forbidden.txt")
            sock.close()
            self.assertEqual(resp.status_code, 403)
            self.assertIn(b"403 Forbidden", resp.body)
        finally:
            os.chmod(test_file, 0o644)
            if os.path.exists(test_file):
                os.remove(test_file)

    def test_13_streaming_unknown_frame_discard(self):
        """Server must discard large unknown frames (>64 KiB) using streaming chunks."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", self.port))
        try:
            # Send 128 KiB unknown frame (type 0x99)
            large_unknown_payload = b"Z" * (128 * 1024)
            unknown_frame = encode_frame(0x99, FLAG_NONE, 10, large_unknown_payload)
            write_exact(sock, unknown_frame)

            # Immediately send valid request on the same persistent socket
            req = Request(
                method="GET",
                path="/hello.txt",
                headers=[("host", f"127.0.0.1:{self.port}")],
                stream_id=11,
            )
            resp = send_request(sock, req, verbose=False)
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.stream_id, 11)
            self.assertEqual(resp.body, b"Hello BHTTP/1!\n")
        finally:
            sock.close()

    def test_14_oversized_file_returns_500(self):
        """A file exceeding the 16 MiB payload limit must return 500 cleanly."""
        large_file = os.path.join(self.web_root, "oversized.bin")
        # Create a 17 MiB sparse file (zero disk allocation)
        with open(large_file, "wb") as f:
            f.truncate(17 * 1024 * 1024)
        try:
            resp, sock = execute_bcurl("127.0.0.1", self.port, "/oversized.bin")
            sock.close()
            self.assertEqual(resp.status_code, 500)
            self.assertIn(b"500 Internal Server Error", resp.body)
        finally:
            if os.path.exists(large_file):
                os.remove(large_file)


if __name__ == "__main__":
    unittest.main()


