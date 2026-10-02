"""Specification Conformance and Mock Foreign Interoperability Test Suite.

Simulates a third-party client and server built strictly from SPEC.md using only
Python standard library struct and socket without importing protocol.py.
Tests compatibility of bserve against a foreign client, and bcurl against a foreign server.
"""

import os
import socket
import struct
import threading
import time
import unittest

from client import execute_bcurl
from server import handle_client_connection


def foreign_pack_request(method_str: str, path_str: str, headers: list, stream_id: int) -> bytes:
    """Independent implementation of REQUEST frame builder using only SPEC.md."""
    # Method mapping per SPEC Section 4
    method_map = {"GET": 1, "HEAD": 2, "POST": 3}
    method_byte = method_map[method_str]

    path_bytes = path_str.encode("utf-8")
    payload = struct.pack(">BH", method_byte, len(path_bytes)) + path_bytes
    payload += struct.pack(">B", len(headers))

    # Static table per SPEC Section 5
    static_table = {
        "host": 1, "user-agent": 2, "content-type": 3, "content-length": 4,
        "connection": 5, "accept": 6, "server": 7, "date": 8, "last-modified": 9, "etag": 10
    }

    for name, value in headers:
        val_bytes = value.encode("utf-8")
        if name in static_table:
            payload += struct.pack(">BH", static_table[name], len(val_bytes)) + val_bytes
        else:
            name_bytes = name.encode("utf-8")
            payload += struct.pack(">BHH", 0, len(name_bytes), len(val_bytes)) + name_bytes + val_bytes

    # 7-byte header per SPEC Section 2: Length (3), Type=0x01 (1), Flags=0x00 (1), StreamID (2)
    length = len(payload)
    header = struct.pack(">I", length)[1:] + struct.pack(">BBH", 0x01, 0x00, stream_id)
    return header + payload


def foreign_parse_response(sock: socket.socket):
    """Independent implementation of RESPONSE frame parser using only SPEC.md."""
    # Read 7 header bytes
    hdr = b""
    while len(hdr) < 7:
        c = sock.recv(7 - len(hdr))
        if not c:
            raise ConnectionError("EOF while reading header")
        hdr += c

    payload_len = struct.unpack(">I", b"\x00" + hdr[0:3])[0]
    frame_type = hdr[3]
    flags = hdr[4]
    stream_id = struct.unpack(">H", hdr[5:7])[0]

    # Read payload
    payload = b""
    while len(payload) < payload_len:
        c = sock.recv(payload_len - len(payload))
        if not c:
            raise ConnectionError("EOF while reading payload")
        payload += c

    # Parse response payload: Status (2), Header Count (1)
    status_code, header_count = struct.unpack(">HB", payload[0:3])
    offset = 3
    headers = []
    inv_table = {
        1: "host", 2: "user-agent", 3: "content-type", 4: "content-length",
        5: "connection", 6: "accept", 7: "server", 8: "date", 9: "last-modified", 10: "etag"
    }

    for _ in range(header_count):
        name_id = payload[offset]
        offset += 1
        if 1 <= name_id <= 10:
            v_len = struct.unpack(">H", payload[offset:offset + 2])[0]
            offset += 2
            v_val = payload[offset:offset + v_len].decode("utf-8")
            offset += v_len
            headers.append((inv_table[name_id], v_val))
        else:
            n_len, v_len = struct.unpack(">HH", payload[offset:offset + 4])
            offset += 4
            n_val = payload[offset:offset + n_len].decode("utf-8")
            offset += n_len
            v_val = payload[offset:offset + v_len].decode("utf-8")
            offset += v_len
            headers.append((n_val, v_val))

    body = payload[offset:]
    return {
        "status_code": status_code,
        "stream_id": stream_id,
        "headers": headers,
        "body": body,
    }


class TestInteropSpecIndependent(unittest.TestCase):
    """Test interoperability against independent client and server implementations."""

    @classmethod
    def setUpClass(cls):
        cls.web_root = os.path.abspath("./www")
        cls.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.server_sock.bind(("127.0.0.1", 0))
        cls.port = cls.server_sock.getsockname()[1]
        cls.server_sock.listen(16)
        cls.running = True

        def server_worker():
            while cls.running:
                try:
                    conn, addr = cls.server_sock.accept()
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

    def test_independent_foreign_client_against_our_server(self):
        """A foreign client built solely from SPEC.md queries our bserve."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", self.port))
        try:
            # Foreign client sends GET /hello.txt with Stream ID 99
            wire_bytes = foreign_pack_request("GET", "/hello.txt", [("host", f"127.0.0.1:{self.port}")], 99)
            sock.sendall(wire_bytes)

            resp = foreign_parse_response(sock)
            self.assertEqual(resp["status_code"], 200)
            self.assertEqual(resp["stream_id"], 99)
            self.assertEqual(resp["body"], b"Hello BHTTP/1!\n")

            # Foreign client tests persistent connection reuse: request 2
            wire_bytes_2 = foreign_pack_request("GET", "/empty.txt", [("host", f"127.0.0.1:{self.port}")], 100)
            sock.sendall(wire_bytes_2)
            resp_2 = foreign_parse_response(sock)
            self.assertEqual(resp_2["status_code"], 200)
            self.assertEqual(resp_2["stream_id"], 100)
            self.assertEqual(resp_2["body"], b"")
        finally:
            sock.close()

    def test_our_bcurl_against_independent_foreign_server(self):
        """Our bcurl queries an independent mock server built solely from SPEC.md."""
        foreign_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        foreign_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        foreign_srv.bind(("127.0.0.1", 0))
        foreign_port = foreign_srv.getsockname()[1]
        foreign_srv.listen(1)

        def mock_foreign_server():
            conn, _ = foreign_srv.accept()
            try:
                # Read 7-byte header
                hdr = conn.recv(7)
                payload_len = struct.unpack(">I", b"\x00" + hdr[0:3])[0]
                stream_id = struct.unpack(">H", hdr[5:7])[0]
                # Read request payload
                payload = conn.recv(payload_len)

                # Send response built strictly per SPEC Section 6
                body = b"Foreign Server Payload OK"
                # Status 200 (2), count 1 (1), server=7 (1), len=14 (2), "foreign-srv/1" (13) + body
                resp_payload = struct.pack(">HBBH", 200, 1, 7, 13) + b"foreign-srv/1" + body
                resp_hdr = struct.pack(">I", len(resp_payload))[1:] + struct.pack(">BBH", 0x02, 0x00, stream_id)
                conn.sendall(resp_hdr + resp_payload)
            finally:
                conn.close()

        t = threading.Thread(target=mock_foreign_server, daemon=True)
        t.start()

        try:
            resp, client_sock = execute_bcurl("127.0.0.1", foreign_port, "/independent")
            client_sock.close()
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.body, b"Foreign Server Payload OK")
            headers_dict = dict(resp.headers)
            self.assertEqual(headers_dict.get("server"), "foreign-srv/1")
        finally:
            foreign_srv.close()
            t.join(timeout=1.0)


if __name__ == "__main__":
    unittest.main()
