# BHTTP/1 Protocol Specification

**Status:** Final | **Version:** 1.0 | **Transport:** TCP | **Byte Order:** Network Byte Order (Big-Endian)

---

## 1. Transport Model & Invariant 7-Byte Frame Header

BHTTP/1 operates over persistent TCP. Message boundaries are strictly delimited by a 7-byte binary header followed by a variable-length payload:

| Field | Offset | Width | Type | Description |
| :--- | :---: | :---: | :---: | :--- |
| **Payload Length** | 0..2 | 3 Bytes (24b) | Big-Endian uint | Size of payload in bytes (0 to 16,777,215). Excludes the 7-byte header. |
| **Frame Type** | 3 | 1 Byte (8b) | uint8 | `0x01` = REQUEST, `0x02` = RESPONSE. All other values are UNKNOWN. |
| **Flags** | 4 | 1 Byte (8b) | bitfield | Bit 0 (`0x01`): `END_STREAM`. Bits 1..7: Reserved (senders set to 0; receivers MUST ignore). |
| **Stream ID** | 5..6 | 2 Bytes (16b) | Big-Endian uint | Transaction correlation tag (1..65,535). Stream ID 0 is reserved. |

- **Stream ID Assignment:** The client chooses Stream IDs, starting at 1, incrementing per request and wrapping from 65,535 to 1. The server MUST echo the request Stream ID in its corresponding response.
- **Field Width Defense:** 24-bit length allows transferring files up to 16 MiB in a single frame without continuation/reassembly overhead, matching HTTP/2's maximum negotiated frame limit (RFC 7540 `SETTINGS_MAX_FRAME_SIZE` of 2^24 - 1 bytes). A 16-bit Stream ID saves 2 bytes per frame over HTTP/2's 31-bit ID (7 vs 9 bytes, a 22.2% header bandwidth saving), providing 65,535 sequential request-response cycles on persistent connections.
- **Connection Rules:** Connections are persistent. Reading 0 bytes at a 7-byte header boundary indicates clean connection termination by the peer.

---

## 2. Unknown-Frame Forward Compatibility Rule

Any frame type other than `0x01` (REQUEST) and `0x02` (RESPONSE) is **UNKNOWN**.
A receiver encountering an unknown frame MUST:
1. Parse `Payload Length` from the 7-byte header.
2. Read and discard exactly `Payload Length` bytes from TCP in streaming chunks without memory buffering.
3. Continue processing subsequent frames on the persistent connection without desynchronizing.

---

## 3. Compact Header Encoding

Headers consist of a 1-byte `Header Count` (0..255) followed by serialized header entries:
- **Static Name Table (IDs 1..10):** `1: host`, `2: user-agent`, `3: content-type`, `4: content-length`, `5: connection`, `6: accept`, `7: server`, `8: date`, `9: last-modified`, `10: etag`.
- **Indexed Entry (`1 <= ID <= 10`):** `[1B Name ID] [2B Value Length (BE)] [Value Bytes (UTF-8)]`
- **Literal Entry (`ID == 0x00`):** `[0x00] [1B Name Length] [Name Bytes (lowercase ASCII)] [2B Value Length (BE)] [Value Bytes (UTF-8)]`
- **Literal Names:** Literal header names MUST be lowercase ASCII (`[a-z0-9_-]`).
- **Duplicates & Ordering:** Duplicate headers are permitted and receivers MUST preserve their transmission order.
- **Invalid IDs:** Name IDs `0x0B`..`0xFF` are malformed and MUST be rejected with `400 Bad Request`.

---

## 4. Request Frame Format (`Type = 0x01`)

Payload layout: `[1B Method] [2B Path Length (BE)] [Path Bytes (UTF-8)] [1B Header Count] [Headers ...]`
- **Method (1 byte):** `0x01` = GET, `0x02` = HEAD. Unsupported methods (e.g. POST `0x03`) MUST return `405 Method Not Allowed` with header `allow: GET, HEAD`.
- **Path Length (2 bytes, Big-Endian):** Path size in bytes (1 to 4096 bytes).
- **Path Bytes (UTF-8):** Must begin with `/` and MUST NOT contain NUL (`0x00`) bytes.

---

## 5. Response Frame Format (`Type = 0x02`)

Payload layout: `[2B Status Code (BE)] [1B Header Count] [Headers ...] [Body Bytes]`
- **Status Code (2 bytes, Big-Endian):** `200` (OK), `400` (Bad Request), `403` (Forbidden), `404` (Not Found), `405` (Method Not Allowed), `500` (Internal Server Error).
- **Body Bytes:** Raw binary data. `Body Length = Payload Length - (3 + Total Headers Size)`. Never NUL-terminated.
- **HEAD Responses:** HEAD responses MUST have `Body Length = 0` and MUST include the `content-length` header indicating the size of the target file in bytes.

---

## 6. Path Resolution & Traversal Security

1. Server canonicalizes requested path: `target = realpath(join(web_root, rel_path))`.
2. **Containment:** Canonical path MUST be within root: `commonpath([web_root, target]) == web_root`.
3. Traversal attempts (`../`, `/../../etc/passwd`) MUST be rejected with **`400 Bad Request`**.
4. **Resource Availability:** If the target resource does not exist on disk, the server MUST return `404 Not Found`. If the target resolves to a directory, the server checks for `index.html`; if absent, it returns `404 Not Found`.

---

## 7. Error & Connection Handling

- **Loss of Synchronization:** A receiver MUST close TCP immediately if: (1) EOF occurs mid-header, (2) EOF occurs before reading declared `Payload Length`, or (3) `Payload Length` exceeds 16,777,215 bytes.
- **Recoverable Errors:** Validly framed requests with semantic violations (invalid path, unknown header ID) return `400 Bad Request` and leave TCP open for subsequent requests.
- **Client Exit Codes:** `0` for 2xx responses, `1` for 4xx/5xx responses, `2` for network/socket errors.

---

## 8. Concrete Worked Example (Live Exchange)

*(Full byte-by-byte annotated hexdump available in `HEXDUMP.md`)*

- **Request `GET /hello.txt` (Stream 1, 56 bytes total):**
  - Header (7B): `00 00 31 01 00 00 01` (Len=49, Type=REQUEST, Flags=0, StreamID=1)
  - Payload (49B): `01 00 0A` (`GET`, len 10) `2F 68 65 6C 6C 6F 2E 74 78 74` (`/hello.txt`) `03` (3 headers: `host: localhost:9000`, `user-agent: bcurl/1.0`, `accept: */*`).
- **Response `200 OK` (Stream 1, 56 bytes total):**
  - Header (7B): `00 00 31 02 00 00 01` (Len=49, Type=RESPONSE, Flags=0, StreamID=1)
  - Payload (49B): `00 C8` (200 OK) `03` (3 headers: `server: bserve/1.0`, `content-type: text/plain`, `content-length: 15`) `48 65 6C 6C 6F 20 42 48 54 54 50 2F 31 21 0A` (Body: `"Hello BHTTP/1!\n"`).



