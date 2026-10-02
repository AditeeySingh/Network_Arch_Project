"""Advanced TCP framing tests: fragmentation, coalescing, boundaries, limits."""

import unittest
import socket
import threading
from protocol import (
    FRAME_HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
    TYPE_REQUEST,
    TYPE_RESPONSE,
    FLAG_NONE,
    FLAG_END_STREAM,
    Frame,
    ConnectionClosedError,
    TruncatedFrameError,
    MalformedFrameError,
    OversizedPayloadError,
    encode_frame,
    encode_frame_header,
    decode_frame_header,
    read_frame,
    read_exact,
    write_exact,
)


class TestFramingEdgeCases(unittest.TestCase):
    def test_multiple_frames_coalesced_in_single_read(self):
        """Test reading multiple frames that arrive together in one network buffer."""
        server_sock, client_sock = socket.socketpair()
        try:
            # Build 3 separate frames
            f1 = encode_frame(TYPE_REQUEST, FLAG_NONE, 1, b"FRAME_ONE")
            f2 = encode_frame(TYPE_REQUEST, FLAG_NONE, 2, b"FRAME_TWO")
            f3 = encode_frame(TYPE_RESPONSE, FLAG_END_STREAM, 3, b"FRAME_THREE")

            # Send all 3 together in one write
            server_sock.sendall(f1 + f2 + f3)

            # Client reads frames sequentially
            r1 = read_frame(client_sock)
            self.assertEqual(r1.stream_id, 1)
            self.assertEqual(r1.payload, b"FRAME_ONE")

            r2 = read_frame(client_sock)
            self.assertEqual(r2.stream_id, 2)
            self.assertEqual(r2.payload, b"FRAME_TWO")

            r3 = read_frame(client_sock)
            self.assertEqual(r3.stream_id, 3)
            self.assertEqual(r3.flags, FLAG_END_STREAM)
            self.assertEqual(r3.payload, b"FRAME_THREE")
        finally:
            server_sock.close()
            client_sock.close()

    def test_single_byte_fragmentation(self):
        """Test reading a frame sent byte-by-byte with small delays."""
        server_sock, client_sock = socket.socketpair()
        try:
            payload = b"FragmentedPayloadData12345"
            frame_data = encode_frame(TYPE_REQUEST, FLAG_NONE, 99, payload)

            def slow_sender():
                for b in frame_data:
                    server_sock.sendall(bytes([b]))

            t = threading.Thread(target=slow_sender)
            t.start()

            received_frame = read_frame(client_sock)
            t.join()

            self.assertEqual(received_frame.stream_id, 99)
            self.assertEqual(received_frame.payload, payload)
        finally:
            server_sock.close()
            client_sock.close()

    def test_zero_length_payload_frame(self):
        """Test frame with payload length = 0."""
        server_sock, client_sock = socket.socketpair()
        try:
            frame_data = encode_frame(0x05, FLAG_NONE, 10, b"")
            server_sock.sendall(frame_data)

            frame = read_frame(client_sock)
            self.assertEqual(frame.payload_length, 0)
            self.assertEqual(frame.payload, b"")
            self.assertEqual(frame.frame_type, 0x05)
        finally:
            server_sock.close()
            client_sock.close()

    def test_truncated_payload_raises_error(self):
        """Test premature connection drop while reading payload."""
        server_sock, client_sock = socket.socketpair()
        try:
            # Header promises 100 bytes, but only 20 are sent before close
            header = encode_frame_header(100, TYPE_REQUEST, FLAG_NONE, 1)
            server_sock.sendall(header + b"A" * 20)
            server_sock.close()

            with self.assertRaises(TruncatedFrameError):
                read_frame(client_sock)
        finally:
            client_sock.close()


if __name__ == "__main__":
    unittest.main()
