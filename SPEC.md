# BHTTP/1 Protocol Specification

**Status:** Final  
**Version:** 1.0  
**Transport:** TCP  
**Byte Order:** Network Byte Order (Big-Endian)  

---

## 1. Overview and Architecture

BHTTP/1 (Binary HTTP Version 1) is a compact, binary-framed, application-layer protocol inspired by HTTP semantics. It operates directly over a reliable byte-stream transport (TCP).

Unlike HTTP/1.1's text-based representation, BHTTP/1 uses fixed-width binary frame headers, explicit length-delimited payloads, indexed header compression, and strict frame-skipping rules. This eliminates message boundary ambiguity, prevents request smuggling, and enables forward-compatible protocol evolution.

```
+-------------------------------------------------------------+
|                     Application Layer                       |
|               (bserve / bcurl / File Assets)                |
+-------------------------------------------------------------+
|                      BHTTP/1 Protocol                       |
|   - 7-Byte Fixed Frame Header                               |
|   - Length-Prefixed Payload (Up to 16 MiB)                  |
|   - Frame Types: REQUEST (0x01), RESPONSE (0x02)            |
|   - Static-Table Indexed Headers (HPACK Mechanism 1 & 2)    |
|   - Stream ID Correlation & Connection Persistence          |
+-------------------------------------------------------------+
|                      Transport (TCP)                        |
|       (Reliable, In-Order, Arbitrary Stream Fragmentation)   |
+-------------------------------------------------------------+
```

---

## 2. TCP Transport and Framing Model

1. **Byte Stream Nature:** TCP delivers an unstructured stream of bytes. Receivers MUST NOT assume that one `recv()` or `read()` call corresponds to one BHTTP/1 frame. A single frame may be fragmented across multiple TCP packets, or multiple frames may arrive coalesced within a single TCP packet.
2. **Exact Framing:** Every frame begins with a fixed 7-byte frame header. Receivers MUST read exactly 7 bytes to determine the frame's payload length, type, flags, and stream ID before reading exactly `Payload Length` bytes of payload.
3. **Connection Persistence:** A TCP connection is persistent by default. Multiple sequential requests and responses MAY be exchanged over a single TCP connection without reconnecting.
4. **Clean Connection Termination:** A peer closes the TCP connection when finished. A receiver reading 0 bytes at a frame boundary (offset 0 of the 7-byte header) MUST treat this as normal connection closure, not an error.

---

## 3. Fixed Frame Header Layout

Every BHTTP/1 frame MUST start with the 7-byte fixed header:

```
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-----------------------------------------------+---------------+
 |                Payload Length (24)            |Frame Type (8) |
 +---------------+-------------------------------+---------------+
 |   Flags (8)   |                Stream ID (16)                 |
 +---------------+-----------------------------------------------+
```

### Field Definitions

| Field | Width | Offset | Type | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Payload Length** | 3 Bytes (24 bits) | 0..2 | Unsigned int (Big-Endian) | Length of the frame payload in bytes (0 to 16,777,215). Does not include the 7-byte header itself. Maximum permitted payload is 16,777,215 bytes (16 MiB). |
| **Frame Type** | 1 Byte (8 bits) | 3 | Unsigned int | Identifies the frame purpose. Defined types: `0x01` (REQUEST), `0x02` (RESPONSE). Types `0x03`..`0xFE` are reserved for extension. `0xFF` is reserved. |
| **Flags** | 1 Byte (8 bits) | 4 | Bitfield | Bit 0 (`0x01`): `END_STREAM` (indicates sender has concluded its transmission for this stream or connection). Bits 1..7: Reserved (MUST be set to 0 by sender, ignored by receiver). |
| **Stream ID** | 2 Bytes (16 bits) | 5..6 | Unsigned int (Big-Endian) | Identifier (1 to 65535) used to correlate requests and responses across persistent connections. A response MUST mirror the Stream ID of the corresponding request. Stream ID 0 is reserved for connection-level signaling. |

### Architectural Rationale for 7-Byte Width

- **24-bit Payload Length (3 bytes):** Identical to HTTP/2 (`RFC 7540`). Provides a generous 16 MiB capacity for transmitting web assets in single frames while saving 25% overhead compared to 32-bit fields and preventing integer overflow attacks.
- **8-bit Type (1 byte):** Allows 256 distinct frame types, leaving ample room for future versions.
- **8-bit Flags (1 byte):** Provides 8 binary control signals per frame.
- **16-bit Stream ID (2 bytes):** Allows up to 65,535 sequential or concurrent transactions per TCP session.
- **Total: 7 bytes.** Prime, compact, and deterministic.

---

## 4. Frame Types and Forward Compatibility

### Frame Type Registry

| Type Byte | Name | Valid Direction | Description |
| :--- | :--- | :--- | :--- |
| `0x01` | **REQUEST** | Client -> Server | Initiates an HTTP-like request. |
| `0x02` | **RESPONSE** | Server -> Client | Delivers status, headers, and body. |
| `0x03`..`0xFE` | **RESERVED / EXTENSION** | Bidirectional | Reserved for future extensions (e.g., PING, METADATA, CANCEL). |
| `0xFF` | **RESERVED** | N/A | Reserved for experimental testing. |

### Mandatory Unknown-Frame Rule (Forward Compatibility)

> **CRITICAL REQUIREMENT:** If a receiver (client or server) encounters a frame whose `Frame Type` is not recognized, the receiver **MUST NOT** terminate the TCP connection, crash, or enter an undefined state.
> 
> Instead, the receiver **MUST**:
> 1. Read the 7-byte header and parse `Payload Length`.
> 2. Read exactly `Payload Length` bytes from the TCP stream.
> 3. Discard the unknown payload entirely.
> 4. Continue parsing the subsequent frame from the TCP stream.

This rule guarantees version-2 extensibility without breaking version-1 peers.

---

## 5. Header Encoding (BHTTP/1 Compact Static Table & Literal Names)

BHTTP/1 employs a compact binary header encoding inspired by HPACK concepts (specifically adopting a predefined static name table and length-prefixed literal headers for a lightweight binary protocol, rather than full RFC 7541 HPACK).

### Static Header Table

The 10 most common HTTP header names are numbered `1` through `10`:

| ID (Hex) | ID (Dec) | Header Name (Canonical Lowercase) |
| :--- | :--- | :--- |
| `0x01` | 1 | `host` |
| `0x02` | 2 | `user-agent` |
| `0x03` | 3 | `content-type` |
| `0x04` | 4 | `content-length` |
| `0x05` | 5 | `connection` |
| `0x06` | 6 | `accept` |
| `0x07` | 7 | `server` |
| `0x08` | 8 | `date` |
| `0x09` | 9 | `last-modified` |
| `0x0A` | 10 | `etag` |

### Header Representation

A frame payload containing headers specifies `Header Count` (1 byte, 0..255), followed by `Header Count` header entries.

Each header entry uses one of two binary layouts:

#### Case A: Predefined Indexed Header (`1 <= Name ID <= 10`)

When the header name exists in the static table, only a 1-byte ID is sent instead of transmitting the full string:

```
 +---------------+-------------------------------+-----------------------+
 |  Name ID (8)  |       Value Length (16)       |  Value Bytes (UTF-8)  |
 |   (0x01..0x0A)|          Big-Endian           |     (Variable)        |
 +---------------+-------------------------------+-----------------------+
```

1. **Name ID** (1 byte): Static table index `0x01`..`0x0A`.
2. **Value Length** (2 bytes, big-endian unsigned integer): Length of the value in bytes (0 to 65,535).
3. **Value Bytes** (Variable): UTF-8 encoded string of the header value.

#### Case B: Literal Custom Header (`Name ID == 0x00`)

When sending a header name not present in the static table:

```
 +---------------+---------------+-----------------------+-------------------------------+-----------------------+
 |  Name ID (8)  |Name Length (8)|  Name Bytes (UTF-8)   |       Value Length (16)       |  Value Bytes (UTF-8)  |
 |    (0x00)     |  (1..255)     |      (Variable)       |          Big-Endian           |     (Variable)        |
 +---------------+---------------+-----------------------+-------------------------------+-----------------------+
```

1. **Name ID** (1 byte): MUST be `0x00`.
2. **Name Length** (1 byte, unsigned integer): Length of header name in bytes (1 to 255).
3. **Name Bytes** (Variable): UTF-8 encoded lowercase string.
4. **Value Length** (2 bytes, big-endian unsigned integer): Length of header value in bytes.
5. **Value Bytes** (Variable): UTF-8 encoded string.

*Rules:*
- Header names are case-insensitive and MUST be transmitted in lowercase.
- Header values are UTF-8 strings.
- Unknown Name IDs in range `0x0B`..`0xFF` are malformed (MUST trigger 400 Bad Request).
- Duplicate header names are permitted; the receiver preserves receipt order.

---

## 6. Request Frame Format (`Type = 0x01`)

The payload of a `REQUEST` frame contains the method, requested path, and optional request headers.

```
 +---------------+-------------------------------+-----------------------+
 |  Method (8)   |       Path Length (16)        |   Path Bytes (UTF-8)  |
 +---------------+-------------------------------+-----------------------+
 | Hdr Count (8) | Header Entries (0 or more, encoded per Section 5) ... |
 +---------------+-------------------------------------------------------+
```

### Request Payload Layout

1. **Method ID (1 byte):**
   - `0x01` = `GET`
   - `0x02` = `HEAD`
   - `0x03` = `POST`
   - Other values are unsupported. Server replies with status `400` (or `405`).
2. **Path Length (2 bytes, Big-Endian):** Length of requested path in bytes ($1 \le \text{Path Length} \le 4096$).
3. **Path Bytes (Variable):** UTF-8 encoded URL path (e.g., `/index.html`).
   - MUST begin with `/`.
   - MUST NOT contain NUL (`0x00`) bytes.
4. **Header Count (1 byte):** Number of headers following ($0 \le N \le 255$).
5. **Header Block:** $N$ serialized header entries according to Section 5.

---

## 7. Response Frame Format (`Type = 0x02`)

The payload of a `RESPONSE` frame contains the status code, response headers, and arbitrary raw body bytes.

```
 +-------------------------------+---------------+-------------------------------------------------------+
 |        Status Code (16)       | Hdr Count (8) | Header Entries (0 or more, encoded per Section 5) ... |
 +-------------------------------+---------------+-------------------------------------------------------+
 | Body Bytes (Raw Binary, Length = Payload Length - Offset of Body) ...                                 |
 +-------------------------------------------------------------------------------------------------------+
```

### Response Payload Layout

1. **Status Code (2 bytes, Big-Endian):** 16-bit HTTP-like numeric status:
   - `200` (`0x00C8`): OK
   - `400` (`0x0190`): Bad Request (malformed frame, invalid encoding, path violation)
   - `404` (`0x0194`): Not Found (resource does not exist)
   - `405` (`0x0195`): Method Not Allowed
   - `500` (`0x01F4`): Internal Server Error
2. **Header Count (1 byte):** Number of headers following ($0 \le N \le 255$).
3. **Header Block:** $N$ serialized header entries according to Section 5.
4. **Body Bytes (Variable):**
   - The body consists of ALL remaining bytes in the frame payload.
   - $\text{Body Length} = \text{Payload Length} - (\text{Size of Status} + \text{Size of Header Count} + \text{Total Headers Size})$.
   - Body bytes are arbitrary raw binary data (images, HTML, plain text, compiled binaries).
   - Bodies are NEVER NUL-terminated.
   - If $\text{Body Length} == 0$, the response body is empty.

---

## 8. Path Resolution and Traversal Security

When the server receives a path in a `REQUEST` frame:

1. **Leading Slash:** The path must begin with `/`. If not, the server treats it as malformed (returns 400).
2. **NUL Byte Defense:** If the path contains `0x00` anywhere, the request MUST be rejected with 400.
3. **Path Normalization:** The server strips leading slashes, resolves relative directory segments (`.` and `..`), and joins the path to the configured root directory.
4. **Traversal Containment Check:**
   The absolute canonical path of the requested file MUST start with the absolute canonical path of the web root directory:
   $$\text{realpath}(\text{target}) \subseteq \text{realpath}(\text{web\_root})$$
   Any attempt to traverse outside the web root (e.g., `../../etc/passwd`, `/../secret.txt`) MUST be rejected immediately with `400 Bad Request` or `404 Not Found`. BHTTP/1 standardizes on **400 Bad Request** for path traversal attempts.
5. **Directory Default:** If the target resolves to a directory, the server checks for `index.html` within that directory. If present, it serves `index.html`; otherwise, it returns `404 Not Found`.

---

## 9. Malformed Frame Handling

A frame is **malformed** if its binary structure violates the specification. This is distinct from an unknown frame type (which is validly framed and must be skipped).

A server encountering a malformed frame MUST respond with a `RESPONSE` frame carrying `Status Code 400` and close the connection if stream synchronization has been lost.

### Malformed Conditions

1. **Truncated Header:** TCP stream closes before 7 header bytes are read.
2. **Premature Payload EOF:** TCP stream closes before `Payload Length` bytes are read.
3. **Oversized Payload:** `Payload Length` exceeds 16,777,215 bytes (or server-configured safety limit).
4. **Truncated Request Payload:** Payload is shorter than 3 bytes (Method + Path Length) or shorter than $3 + \text{Path Length} + 1$.
5. **Invalid Method:** Method byte is not in `[0x01, 0x02, 0x03]`.
6. **Invalid Path:** Path contains NUL bytes, fails UTF-8 decoding, or fails to begin with `/`.
7. **Malformed Headers:** Header Count claims more headers than payload bytes provide, or Name ID is out of range ($> 10$), or string value length exceeds remaining payload.

---

## 10. Client CLI and Behavior (`bcurl`)

### Invocation
```bash
./bcurl [-v] <host>:<port><path>
```
*Example:*
```bash
./bcurl -v localhost:9000/index.html
```

### Execution Rules

1. **Connection:** Parse target host, port, and path. Open exactly ONE TCP connection. NEVER open a second connection for the request.
2. **Request Construction:** Construct a BHTTP/1 `REQUEST` frame with Stream ID `1`, Method `0x01` (`GET`), the specified path, and standard headers (`host: <host>:<port>`, `user-agent: bcurl/1.0`).
3. **Verbose Hexdump (`-v`):** When `-v` is provided, print an annotated byte-by-byte hexadecimal dump of all transmitted and received frames to `stderr`.
4. **Body Output:** Write the raw response body bytes directly to `stdout`. Do NOT write headers, frame bytes, or diagnostic text to `stdout`.
5. **Exit Codes:**
   - Exit `0` for 2xx responses (e.g., 200 OK).
   - Exit non-zero (`1` or matching HTTP status code) for 4xx and 5xx responses.

---

## 11. Server CLI and Behavior (`bserve`)

### Invocation
```bash
./bserve <web_root> <port>
```
*Example:*
```bash
./bserve ./www 9000
```

### Execution Rules

1. Bind a TCP listening socket to the specified port.
2. Accept incoming client connections.
3. Handle requests persistently in a loop:
   - Read 7-byte header.
   - If 0 bytes read on first read, peer closed connection cleanly; exit loop.
   - Read full payload length.
   - If frame type is unknown, discard payload and continue loop.
   - If frame is valid `REQUEST`, map path safely to `web_root`.
   - Send `RESPONSE` frame with matching Stream ID.
4. Keep the TCP connection open for subsequent requests.

---

## 12. Concrete Binary Example

### Request: `GET /hello.txt` (Stream ID = 1)

**Header (7 bytes):**
- `00 00 1E` : Payload Length = 30 bytes
- `01`       : Frame Type = REQUEST (0x01)
- `00`       : Flags = none
- `00 01`    : Stream ID = 1

**Payload (30 bytes):**
- `01`       : Method = GET (0x01)
- `00 0A`    : Path Length = 10 bytes
- `2F 68 65 6C 6C 6F 2E 74 78 74` : `/hello.txt`
- `01`       : Header Count = 1
- `01`       : Header 1 Name ID = 0x01 (`host`)
- `00 0E`    : Header 1 Value Length = 14 bytes
- `6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30` : `localhost:9000`

### Response: `200 OK` (Stream ID = 1, Body: `Hello BHTTP/1!\n`)

**Header (7 bytes):**
- `00 00 24` : Payload Length = 36 bytes
- `02`       : Frame Type = RESPONSE (0x02)
- `00`       : Flags = none
- `00 01`    : Stream ID = 1

**Payload (36 bytes):**
- `00 C8`    : Status = 200 OK
- `01`       : Header Count = 1
- `07`       : Header 1 Name ID = 0x07 (`server`)
- `00 0F`    : Header 1 Value Length = 15 bytes
- `62 73 65 72 76 65 2D 62 68 74 74 70 2F 31 2E 30` : `bserve-bhttp/1.0`
- `48 65 6C 6C 6F 20 42 48 54 54 50 2F 31 21 0A` : Body = `Hello BHTTP/1!\n` (15 bytes)
