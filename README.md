# BHTTP/1 — Binary HTTP Protocol & Implementation

A custom, binary-framed, application-layer HTTP protocol with full client (`bcurl`), server (`bserve`), authentic terminal screenshots, and comprehensive test suites, engineered according to the Course Project specification.

---

## Visual Verification & Artifacts

### 1. Complete Automated Test Suite (27/27 Passing)
![Test Suite Run](docs/images/test_suite_run.png)

### 2. Client Verbose Wire Trace (`./bcurl -v`)
![bcurl Verbose Trace](docs/images/bcurl_verbose_trace.png)

### 3. Error Handling, Status Exit Codes & Security Defense
![Error Handling and Security](docs/images/bcurl_error_exit_codes.png)

---

## Architecture Overview

```
                      +-----------------------------+
                      |         SPEC.md             |
                      |  (Independent Specification) |
                      +--------------+--------------+
                                     |
                      +--------------v--------------+
                      |         protocol.py         |
                      |   - 7-Byte Fixed Header     |
                      |   - Exact TCP I/O Framing   |
                      |   - HPACK Static Headers    |
                      |   - Frame Encode / Decode   |
                      +-------+-------------+-------+
                              |             |
                 +------------v----+   +----v------------+
                 |     bserve      |   |      bcurl      |
                 |  (server.py)    |   |   (client.py)   |
                 | - Traversal Def |   | - Single Socket |
                 | - Persistent    |   | - Hexdump Trace |
                 | - Skip Unknown  |   | - Standard Exit |
                 +--------+--------+   +--------+--------+
                          |                     |
                          +<======== TCP =======>+
```

---

## Deliverables Summary

1. **`SPEC.md`**: Complete, formal, independent binary specification containing exact byte layouts, widths, byte order, header indices, status codes, and unknown-frame forward-compatibility rules.
2. **`protocol.py`**: Shared protocol library implementing frame encoding/decoding, header table compression, exact socket reads/writes, and error boundaries.
3. **`server.py` & `bserve`**: Track 1 binary server supporting persistent connections, directory traversal defense, and unknown frame skipping.
4. **`client.py` & `bcurl`**: Track 2 binary client supporting `-v` annotated hex logging, persistent connection reuse, and status exit codes.
5. **`HEXDUMP.md`**: Authentic, byte-by-byte annotated hexadecimal dump captured live from a real TCP exchange on port 9000.
6. **`tests/`**: 27 automated unit and integration tests covering protocol serialization, TCP fragmentation/coalescing, path traversal attacks, unknown frame skipping, and subprocess CLI execution.
7. **`docs/images/`**: High-resolution, authentic terminal screenshots validating test suite execution, wire traces, and security defenses.
8. **`www/`**: Web root fixtures including `index.html`, `hello.txt`, `empty.txt`, and binary `test.bin`.

---

## Key Protocol Design Decisions

### 1. 7-Byte Fixed Frame Header
```
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-----------------------------------------------+---------------+
 |                Payload Length (24)            |Frame Type (8) |
 +---------------+-------------------------------+---------------+
 |   Flags (8)   |                Stream ID (16)                 |
 +---------------+-----------------------------------------------+
```
- **24-bit Payload Length (3 bytes):** Defends HTTP/2's length width (`RFC 7540`). Allows transmitting files up to 16 MiB per frame without incurring 32-bit overhead, and protects receivers against 32-bit allocation attacks.
- **8-bit Type (1 byte):** Distinct frame types (`0x01` REQUEST, `0x02` RESPONSE) with 254 reserved values for future extension.
- **8-bit Flags (1 byte):** Control bitmask including `END_STREAM (0x01)`.
- **16-bit Stream ID (2 bytes):** Big-endian identifier matching requests and responses across persistent connections.

### 2. Unknown-Frame Forward Compatibility Rule
A receiver (client or server) encountering an unrecognized frame type **never crashes or disconnects**. Because the 7-byte header unambiguously provides the `Payload Length` before payload interpretation, the receiver cleanly reads and discards that exact number of bytes, continuing to parse the subsequent frame on the stream.

### 3. Compact Header Encoding
Headers implement HPACK's first two mechanisms:
- Predefined static table of 10 common headers (`host`, `user-agent`, `content-type`, `content-length`, `connection`, `accept`, `server`, `date`, `last-modified`, `etag`), encoded with a 1-byte name ID.
- Fallback literal encoding for custom headers (`0x00` ID + 1-byte length + name bytes).

### 4. Path Traversal Containment
All requested paths are canonicalized via `os.path.realpath` and checked against the web root using `os.path.commonpath`. Any request attempting to escape the configured root returns `400 Bad Request`.

---

## Quickstart & Usage

### Starting the Server
```bash
./bserve ./www 9000
```

### Running the Client
```bash
# Standard request: body output directly to stdout
./bcurl localhost:9000/hello.txt

# Verbose mode: prints annotated hexdump and wire trace to stderr
./bcurl -v localhost:9000/index.html

# Requesting binary data (e.g. pipe to file or sha256sum)
./bcurl localhost:9000/test.bin | shasum -a 256
```

---

## Running the Automated Test Suite

Run all 27 unit, framing, security, and integration tests:

```bash
python3 -m unittest discover tests
```
