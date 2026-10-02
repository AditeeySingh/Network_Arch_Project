# BHTTP/1 Protocol Specification

**Status:** Final | **Version:** 1.0 | **Transport:** TCP | **Byte Order:** Network Byte Order (Big-Endian)

---

## 1. Overview & Transport Model

BHTTP/1 is a binary-framed application protocol operating over a persistent TCP byte stream. 

1. **Exact Framing:** TCP does not preserve message boundaries. Receivers MUST read exactly 7 header bytes, parse the declared payload length, and read exactly that many payload bytes.
2. **Persistence:** TCP connections are persistent by default. Multiple sequential request/response exchanges occur over a single socket without reconnecting.
3. **Connection Closure:** A receiver reading 0 bytes at a 7-byte header boundary MUST treat this as clean connection termination by the peer.

---

## 2. Invariant 7-Byte Fixed Frame Header

Every frame begins with a fixed 7-byte binary header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-----------------------------------------------+---------------+
|                Payload Length (24)            |Frame Type (8) |
+---------------+-------------------------------+---------------+
|   Flags (8)   |                Stream ID (16)                 |
+---------------+-----------------------------------------------+
```

| Field | Offset | Width | Type | Description |
| :--- | :---: | :---: | :---: | :--- |
| **Payload Length** | 0..2 | 3 Bytes (24 bits) | Big-Endian uint | Size of payload in bytes (0 to 16,777,215). Excludes the 7-byte header. |
| **Frame Type** | 3 | 1 Byte (8 bits) | uint8 | `0x01` = REQUEST, `0x02` = RESPONSE. Any other value is UNKNOWN. |
| **Flags** | 4 | 1 Byte (8 bits) | bitfield | Bit 0 (`0x01`): `END_STREAM`. Bits 1..7: Reserved (MUST be 0). |
| **Stream ID** | 5..6 | 2 Bytes (16 bits) | Big-Endian uint | Correlation ID (1 to 65,535). Stream ID 0 is reserved. |

### Rationale for Field Widths
- **24-bit Length Prefix:** Matches the maximum negotiable frame size in HTTP/2 (`RFC 7540` `SETTINGS_MAX_FRAME_SIZE` upper bound of $2^{24}-1$). It allows transferring files up to 16 MiB in a single frame without fragmentation overhead.
- **16-bit Stream ID:** Unlike HTTP/2, which uses a 31-bit stream ID to track concurrent multiplexed streams over long-lived sessions, BHTTP/1 uses persistent sequential transactions. A 16-bit field reduces the header from 9 to 7 bytes (saving 22.2% framing overhead) while providing 65,535 transactions before wrapping. Stream IDs increment monotonically and wrap from 65,535 back to 1.

---

## 3. Unknown-Frame Forward Compatibility Rule

Any frame whose `Frame Type` is not `0x01` or `0x02` (including `0x00`, `0x03`..`0xFE`, and `0xFF`) is **UNKNOWN**.

A receiver encountering an unknown frame MUST:
1. Parse `Payload Length` from the 7-byte header.
2. Read and discard exactly `Payload Length` bytes from the socket without buffering into memory.
3. Continue parsing subsequent frames on the persistent TCP connection without closing or desynchronizing.

---

## 4. Header Encoding (Static Table & Literals)

Headers consist of a 1-byte `Header Count` (0..255) followed by that many serialized header entries.

### Static Table (Indices 1 to 10)
`1: host`, `2: user-agent`, `3: content-type`, `4: content-length`, `5: connection`, `6: accept`, `7: server`, `8: date`, `9: last-modified`, `10: etag`.

### Encoding Formats
- **Indexed (`1 <= ID <= 10`):** `[1B Name ID] [2B Value Length (BE)] [Value Bytes (UTF-8)]`
- **Literal (`ID == 0x00`):** `[0x00] [1B Name Length] [Name Bytes (lowercase UTF-8)] [2B Value Length (BE)] [Value Bytes (UTF-8)]`
- **Invalid IDs:** Any Name ID in range `0x0B`..`0xFF` is malformed and MUST be rejected with `400 Bad Request`.

---

## 5. Request Frame Format (`Type = 0x01`)

```
+---------------+-------------------------------+-----------------------+
|  Method (8)   |       Path Length (16)        |   Path Bytes (UTF-8)  |
+---------------+-------------------------------+-----------------------+
| Hdr Count (8) | Header Entries (0 or more, encoded per Section 4) ... |
+---------------+-------------------------------------------------------+
```
- **Method (1 byte):** `0x01` = GET, `0x02` = HEAD. Any other method (e.g. POST `0x03`) MUST be rejected with `405 Method Not Allowed`.
- **Path Length (2 bytes, Big-Endian):** $1 \le L \le 4096$.
- **Path Bytes (UTF-8):** Must begin with `/` and MUST NOT contain NUL (`0x00`) bytes.
- **Header Count (1 byte):** Number of headers following.

---

## 6. Response Frame Format (`Type = 0x02`)

```
+-------------------------------+---------------+-------------------------------------------------------+
|        Status Code (16)       | Hdr Count (8) | Header Entries (0 or more, encoded per Section 4) ... |
+-------------------------------+---------------+-------------------------------------------------------+
| Body Bytes (Raw Binary, Length = Payload Length - Offset of Body) ...                                 |
+-------------------------------------------------------------------------------------------------------+
```
- **Status Code (2 bytes, Big-Endian):** 16-bit status: `200` (OK), `400` (Bad Request), `403` (Forbidden), `404` (Not Found), `405` (Method Not Allowed), `500` (Internal Error).
- **Body Bytes:** Raw binary data. `Body Length = Payload Length - (3 + Total Headers Size)`. Never NUL-terminated. HEAD responses MUST have `Body Length = 0`.

---

## 7. Path Resolution & Security

1. Server strips leading slashes and resolves the canonical real path:
   `target = os.path.realpath(os.path.join(abs_root, rel_path))`
2. **Containment:** Canonical path MUST be within the web root:
   `os.path.commonpath([abs_root, target]) == abs_root`
3. Traversal attempts (e.g. `../../etc/passwd`) MUST be rejected with **`400 Bad Request`**.
4. If target is a directory, server checks for `index.html`. If absent, server returns `404 Not Found`.

---

## 8. Error & Connection Handling

- **Loss of Synchronization:** A server MUST close the TCP connection immediately if:
  1. EOF occurs before reading the complete 7-byte header.
  2. EOF occurs before reading the declared `Payload Length` bytes.
  3. Declared `Payload Length` exceeds 16,777,215 bytes.
- **Recoverable Malformed Requests:** If framing is intact but request contents violate rules (invalid path, unknown header ID, truncated header block), the server MUST return `400 Bad Request` and remain open for the next request.
- **File System Errors:** Unreadable files (permissions) return `403 Forbidden`. Files exceeding 16 MiB return `500 Internal Server Error`.
- **Client Exit Codes:** `0` for 2xx responses, `1` for 4xx/5xx responses, `2` for network/socket errors.

---

## 9. Concrete Worked Example

### Request: `GET /hello.txt` (Stream ID = 1)
**Header (7 bytes):** `00 00 1F 01 00 00 01`  
- `00 00 1F` : Payload Length = 31 bytes
- `01`       : Frame Type = REQUEST (0x01)
- `00`       : Flags = none
- `00 01`    : Stream ID = 1

**Payload (31 bytes):** `01 00 0A 2F 68 65 6C 6C 6F 2E 74 78 74 01 01 00 0E 6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30`  
- `01`       : Method = GET (0x01)
- `00 0A`    : Path Length = 10 bytes
- `2F 68 65 6C 6C 6F 2E 74 78 74` : `"/hello.txt"`
- `01`       : Header Count = 1
- `01`       : Header 1 Name ID = 0x01 (`host`)
- `00 0E`    : Header 1 Value Length = 14 bytes
- `6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30` : `"localhost:9000"`

### Response: `200 OK` (Stream ID = 1, Body: `Hello BHTTP/1!\n`)
**Header (7 bytes):** `00 00 1F 02 00 00 01`  
- `00 00 1F` : Payload Length = 31 bytes
- `02`       : Frame Type = RESPONSE (0x02)
- `00`       : Flags = none
- `00 01`    : Stream ID = 1

**Payload (31 bytes):** `00 C8 01 07 00 0A 62 73 65 72 76 65 2F 31 2E 30 48 65 6C 6C 6F 20 42 48 54 54 50 2F 31 21 0A`  
- `00 C8`    : Status = 200 OK
- `01`       : Header Count = 1
- `07`       : Header 1 Name ID = 0x07 (`server`)
- `00 0A`    : Header 1 Value Length = 10 bytes
- `62 73 65 72 76 65 2F 31 2E 30` : `"bserve/1.0"`
- `48 65 6C 6C 6F 20 42 48 54 54 50 2F 31 21 0A` : Body = `"Hello BHTTP/1!\n"` (15 bytes)
