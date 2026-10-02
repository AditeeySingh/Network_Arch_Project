# BHTTP/1 Protocol Specification (v1.0)
Transport: Persistent TCP | Byte Order: Big-Endian | Header: Fixed 7 Bytes

## 1. Frame Header & Unknown-Frame Rule
Every frame begins with a fixed 7-byte binary header followed by Payload Length bytes:

| Field | Offset | Width | Description |
| :--- | :---: | :---: | :--- |
| **Payload Length** | 0..2 | 3B (24b) | Payload size in bytes (0..16,777,215). Excludes 7-byte header. |
| **Frame Type** | 3 | 1B (8b) | `0x01` = REQUEST, `0x02` = RESPONSE. All other types are UNKNOWN. |
| **Flags** | 4 | 1B (8b) | Bit 0: `END_STREAM`. Bits 1..7: Reserved (senders set to 0; receivers ignore). |
| **Stream ID** | 5..6 | 2B (16b) | Correlation tag (1..65,535). Stream ID 0 is reserved. |

- **Rules:** The client chooses Stream IDs (starts at 1, increments per request, wraps from 65,535 to 1). Server MUST echo the Stream ID in its response. TCP connections are persistent; reading 0 bytes at a 7-byte boundary signals clean closure.
- **Unknown Frames:** Any frame with Type != 0x01 and != 0x02 is UNKNOWN. Receivers MUST read and discard Payload Length bytes in streaming chunks and continue processing subsequent frames.
- **Width Defense:** 24b length matches HTTP/2 max negotiable frame size (RFC 7540 SETTINGS_MAX_FRAME_SIZE: 2^24-1) allowing 16 MiB transfers without continuation frames. 16b Stream ID saves 2 bytes per frame (22.2% saving over HTTP/2 9-byte header).

## 2. Compact Header Encoding
Headers consist of a 1-byte Header Count (0..255) followed by that many serialized header entries:
- **Static Table (1..10):** 1:host, 2:user-agent, 3:content-type, 4:content-length, 5:connection, 6:accept, 7:server, 8:date, 9:last-modified, 10:etag.
- **Indexed Entry (1 <= ID <= 10):** `[1B Name ID] [2B Value Length (BE)] [Value Bytes (UTF-8)]`
- **Literal Entry (ID == 0x00):** `[0x00] [1B Name Len] [Name Bytes (lowercase ASCII)] [2B Val Len (BE)] [Val Bytes]`
- **Rules:** Literal names MUST be lowercase ASCII (`[a-z0-9_-]`). Duplicate headers are allowed and MUST preserve order. IDs 0x0B..0xFF are malformed (`400 Bad Request`).

## 3. Frame Payloads & Security
- **REQUEST (Type 0x01):** `[1B Method] [2B Path Length (BE)] [Path Bytes (UTF-8)] [1B Hdr Count] [Headers...]`
  Method: `0x01` GET, `0x02` HEAD. Unsupported methods return `405 Method Not Allowed` with `allow: GET, HEAD`. Path must start with `/` and contain no NUL bytes (1..4096 bytes).
- **RESPONSE (Type 0x02):** `[2B Status Code (BE)] [1B Hdr Count] [Headers...] [Body Bytes]`
  Status: `200` OK, `400` Bad Request, `403` Forbidden, `404` Not Found, `405` Method Not Allowed, `500` Internal Error. Body is raw binary (`Length = Payload Length - Offset of Body`). HEAD responses MUST have 0 body bytes and MUST include `content-length`.
- **Traversal Defense:** Server resolves `realpath(join(root, path))`. Canonical path MUST reside inside root (`commonpath == root`). Traversal attempts (`../`, `/../../etc/passwd`) MUST return `400 Bad Request`. Missing files or directories without `index.html` return `404 Not Found`. Permissions errors return `403 Forbidden`. Files > 16 MiB return `500 Internal Error`.
- **Errors & Sync:** Incomplete headers, truncated payloads, or length > 16 MiB close TCP immediately. Malformed requests with intact framing return `400 Bad Request` and keep TCP open. Client exits `0` on 2xx, `1` on 4xx/5xx, `2` on socket error.

## 4. Concrete Worked Example
- **Request (56 bytes, Stream 1):** `GET /hello.txt` (Headers: `host: localhost:9000`, `user-agent: bcurl/1.0`, `accept: */*`)
```
00 00 31 01 00 00 01 01 00 0A 2F 68 65 6C 6C 6F 2E 74 78 74 03 01 00 0E 6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30 02 00 09 62 63 75 72 6C 2F 31 2E 30 06 00 03 2A 2F 2A
```
- **Response (56 bytes, Stream 1):** `200 OK` (Headers: `server: bserve/1.0`, `content-type: text/plain`, `content-length: 15`, Body: `"Hello BHTTP/1!\n"`)
```
00 00 31 02 00 00 01 00 C8 03 07 00 0A 62 73 65 72 76 65 2F 31 2E 30 03 00 0A 74 65 78 74 2F 70 6C 61 69 6E 04 00 02 31 35 48 65 6C 6C 6F 20 42 48 54 54 50 2F 31 21 0A
```
