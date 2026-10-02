# BHTTP/1 Annotated Hexadecimal Exchange Dump

This document contains a complete, byte-by-byte annotated hexadecimal dump of an authentic BHTTP/1 live exchange between `bcurl` and `bserve` captured directly over a live TCP connection on `localhost:9000` requesting `/hello.txt`.

---

## 1. Raw Captured Byte Sequences

### Client Request Frame (56 bytes)
```
00 00 31 01 00 00 01 01 00 0A 2F 68 65 6C 6C 6F
2E 74 78 74 03 01 00 0E 6C 6F 63 61 6C 68 6F 73
74 3A 39 30 30 30 02 00 09 62 63 75 72 6C 2F 31
2E 30 06 00 03 2A 2F 2A
```

### Server Response Frame (56 bytes)
```
00 00 31 02 00 00 01 00 C8 03 07 00 0A 62 73 65
72 76 65 2F 31 2E 30 03 00 0A 74 65 78 74 2F 70
6C 61 69 6E 04 00 02 31 35 48 65 6C 6C 6F 20 42
48 54 54 50 2F 31 21 0A
```

---

## 2. Annotated Request Frame Breakdown

```
Command: ./bcurl -v localhost:9000/hello.txt
Stream ID: 1
Total Frame Size: 56 bytes (7-byte header + 49-byte payload)
```

| Offset (Hex) | Length | Raw Hex Bytes | Protocol Field | Value / Interpretation | Specification Reference |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `0000..0002` | 3 B | `00 00 31` | Payload Length | 49 bytes (Big-Endian) | SPEC Section 3 |
| `0003` | 1 B | `01` | Frame Type | `0x01` (`TYPE_REQUEST`) | SPEC Section 3 & 4 |
| `0004` | 1 B | `00` | Flags | `0x00` (`FLAG_NONE`) | SPEC Section 3 |
| `0005..0006` | 2 B | `00 01` | Stream ID | `1` (Big-Endian) | SPEC Section 3 |
| `0007` | 1 B | `01` | Method ID | `0x01` (`GET`) | SPEC Section 6 |
| `0008..0009` | 2 B | `00 0A` | Path Length | 10 bytes (Big-Endian) | SPEC Section 6 |
| `000A..0013` | 10 B | `2F 68 65 6C 6C 6F 2E 74 78 74` | Path Bytes | `"/hello.txt"` (UTF-8 ASCII) | SPEC Section 6 |
| `0014` | 1 B | `03` | Header Count | 3 headers | SPEC Section 5 & 6 |
| `0015` | 1 B | `01` | Header 1 Name ID | `0x01` (`host` in static table) | SPEC Section 5 (Static Table) |
| `0016..0017` | 2 B | `00 0E` | Header 1 Value Length | 14 bytes (Big-Endian) | SPEC Section 5 |
| `0018..0025` | 14 B | `6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30` | Header 1 Value | `"localhost:9000"` (UTF-8 ASCII) | SPEC Section 5 |
| `0026` | 1 B | `02` | Header 2 Name ID | `0x02` (`user-agent` in static table) | SPEC Section 5 (Static Table) |
| `0027..0028` | 2 B | `00 09` | Header 2 Value Length | 9 bytes (Big-Endian) | SPEC Section 5 |
| `0029..0031` | 9 B | `62 63 75 72 6C 2F 31 2E 30` | Header 2 Value | `"bcurl/1.0"` (UTF-8 ASCII) | SPEC Section 5 |
| `0032` | 1 B | `06` | Header 3 Name ID | `0x06` (`accept` in static table) | SPEC Section 5 (Static Table) |
| `0033..0034` | 2 B | `00 03` | Header 3 Value Length | 3 bytes (Big-Endian) | SPEC Section 5 |
| `0035..0037` | 3 B | `2A 2F 2A` | Header 3 Value | `"*/*"` (UTF-8 ASCII) | SPEC Section 5 |

### Visual Layout Diagram (Request)
```
+-----------------------------------------------+---------------+
|           Payload Length: 49 (0x000031)       | Type: 0x01    |
+---------------+-------------------------------+---------------+
| Flags: 0x00   |               Stream ID: 1 (0x0001)           |
+---------------+-------------------------------+---------------+
| Method: GET   |     Path Length: 10 (0x000A)  | "/hello.txt"  |
+---------------+-------------------------------+---------------+
| Hdr Count: 3  | Id: 0x01(host)| Val Len: 14   | "localhost... |
+---------------+---------------+---------------+---------------+
| Id:0x02(agent)| Val Len: 9    | "bcurl/1.0"   | Id:0x06(acc)  |
+---------------+---------------+---------------+---------------+
| Val Len: 3    | "*/*"         |
+---------------+---------------+
```

---

## 3. Annotated Response Frame Breakdown

```
Status: 200 OK
Stream ID: 1
Total Frame Size: 56 bytes (7-byte header + 49-byte payload)
```

| Offset (Hex) | Length | Raw Hex Bytes | Protocol Field | Value / Interpretation | Specification Reference |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `0000..0002` | 3 B | `00 00 31` | Payload Length | 49 bytes (Big-Endian) | SPEC Section 3 |
| `0003` | 1 B | `02` | Frame Type | `0x02` (`TYPE_RESPONSE`) | SPEC Section 3 & 4 |
| `0004` | 1 B | `00` | Flags | `0x00` (`FLAG_NONE`) | SPEC Section 3 |
| `0005..0006` | 2 B | `00 01` | Stream ID | `1` (Echoing request Stream ID) | SPEC Section 3 |
| `0007..0008` | 2 B | `00 C8` | Status Code | 200 OK (0x00C8, Big-Endian) | SPEC Section 7 |
| `0009` | 1 B | `03` | Header Count | 3 headers | SPEC Section 5 & 7 |
| `000A` | 1 B | `07` | Header 1 Name ID | `0x07` (`server` in static table) | SPEC Section 5 (Static Table) |
| `000B..000C` | 2 B | `00 0A` | Header 1 Value Length | 10 bytes (Big-Endian) | SPEC Section 5 |
| `000D..0016` | 10 B | `62 73 65 72 76 65 2F 31 2E 30` | Header 1 Value | `"bserve/1.0"` (UTF-8 ASCII) | SPEC Section 5 |
| `0017` | 1 B | `03` | Header 2 Name ID | `0x03` (`content-type` in static table) | SPEC Section 5 (Static Table) |
| `0018..0019` | 2 B | `00 0A` | Header 2 Value Length | 10 bytes (Big-Endian) | SPEC Section 5 |
| `001A..0023` | 10 B | `74 65 78 74 2F 70 6C 61 69 6E` | Header 2 Value | `"text/plain"` (UTF-8 ASCII) | SPEC Section 5 |
| `0024` | 1 B | `04` | Header 3 Name ID | `0x04` (`content-length` in static table)| SPEC Section 5 (Static Table) |
| `0025..0026` | 2 B | `00 02` | Header 3 Value Length | 2 bytes (Big-Endian) | SPEC Section 5 |
| `0027..0028` | 2 B | `31 35` | Header 3 Value | `"15"` (UTF-8 ASCII) | SPEC Section 5 |
| `0029..0037` | 15 B | `48 65 6C 6C 6F 20 42 48 54 54 50 2F 31 21 0A` | Body Bytes | `"Hello BHTTP/1!\n"` (Raw binary bytes) | SPEC Section 7 |

### Visual Layout Diagram (Response)
```
+-----------------------------------------------+---------------+
|           Payload Length: 49 (0x000031)       | Type: 0x02    |
+---------------+-------------------------------+---------------+
| Flags: 0x00   |               Stream ID: 1 (0x0001)           |
+---------------+---------------+-------------------------------+
| Status Code: 200 (0x00C8)     | Hdr Count: 3  | Id:0x07(serv) |
+---------------+---------------+---------------+---------------+
| Val Len: 10   | "bserve/1.0"  | Id:0x03(type) | Val Len: 10   |
+---------------+---------------+---------------+---------------+
| "text/plain"  | Id:0x04(len)  | Val Len: 2    | "15"          |
+---------------+---------------+---------------+---------------+
| Body (15 bytes): "Hello BHTTP/1!\n"                           |
+---------------------------------------------------------------+
```

---

## 4. Verification Check

- $\text{Total Response Payload Length} = 49\text{ bytes}$.
- $\text{Offset of Body} = 2\text{ (Status)} + 1\text{ (Hdr Count)} + (1 + 2 + 10)\text{ [Hdr 1]} + (1 + 2 + 10)\text{ [Hdr 2]} + (1 + 2 + 2)\text{ [Hdr 3]} = 34\text{ bytes}$.
- $\text{Body Length} = 49 - 34 = 15\text{ bytes}$.
- $\text{Body Bytes} = \text{"Hello BHTTP/1!\textbackslash n"}$ (length matches exactly 15 bytes).
- No NUL-terminators are used anywhere in the body.
