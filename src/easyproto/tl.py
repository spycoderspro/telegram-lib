"""Schema-driven TL encoding, without generated client dependencies.

The vendored schema is versioned with the package. Constructors are available as
``types.inputPeerSelf()`` and requests as ``functions.messages.sendMessage(...)``.
"""
from __future__ import annotations

import gzip
import io
import re
import struct
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from typing import Any

from .errors import ProtocolError

VECTOR = 0x1CB5C415
GZIP = 0x3072CFA1
MAX_BYTES = 16 * 1024 * 1024
MAX_ITEMS = 100_000


class TLObject:
    __slots__ = ("name", "fields")

    def __init__(self, constructor: str, /, **fields: Any) -> None:
        self.name = constructor
        self.fields = fields

    def __getattr__(self, name: str) -> Any:
        try:
            return self.fields[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def get(self, name: str, default: Any = None) -> Any:
        return self.fields.get(name, default)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TLObject) and (self.name, self.fields) == (other.name, other.fields)

    def __repr__(self) -> str:
        # Auth/session objects should not accidentally disclose their contents.
        return f"TLObject({self.name!r}, fields={list(self.fields)!r})"


@dataclass(frozen=True)
class Field:
    name: str
    type: str
    flag: str | None = None
    bit: int = 0


@dataclass(frozen=True)
class Definition:
    name: str
    id: int
    fields: tuple[Field, ...]
    result: str
    function: bool


def pack_bytes(value: bytes) -> bytes:
    n = len(value)
    if n > 0xFFFFFF:
        raise ValueError("TL bytes exceed the 24-bit length limit")
    header = bytes([n]) if n < 254 else b"\xfe" + n.to_bytes(3, "little")
    return header + value + b"\0" * (-(len(header) + n) % 4)


class Reader:
    def __init__(self, data: bytes) -> None:
        if len(data) > MAX_BYTES:
            raise ProtocolError("TL message exceeds size limit")
        self.stream = io.BytesIO(data)

    def read(self, n: int) -> bytes:
        if n < 0 or len(data := self.stream.read(n)) != n:
            raise ProtocolError("Truncated TL data")
        return data

    def unpack(self, fmt: str) -> Any:
        return struct.unpack(fmt, self.read(struct.calcsize(fmt)))[0]

    def bytes(self) -> bytes:
        first = self.read(1)[0]
        if first == 255:
            raise ProtocolError("Invalid TL bytes length")
        n, header = first, 1
        if first == 254:
            n, header = int.from_bytes(self.read(3), "little"), 4
            if n < 254:
                raise ProtocolError("Noncanonical TL bytes length")
        if n > MAX_BYTES:
            raise ProtocolError("TL bytes exceed size limit")
        result = self.read(n)
        if any(self.read(-(header + n) % 4)):
            raise ProtocolError("Nonzero TL alignment padding")
        return result

    def remaining(self) -> int:
        return len(self.stream.getbuffer()) - self.stream.tell()


class Schema:
    def __init__(self, *sources: str) -> None:
        self.by_name: dict[str, Definition] = {}
        self.by_id: dict[int, Definition] = {}
        self.layer = 0
        for source in sources:
            function = False
            if match := re.search(r"// LAYER (\d+)", source):
                self.layer = int(match[1])
            source = re.sub(r"//[^\n]*", "", source)
            for statement in source.split(";"):
                statement = statement.strip()
                for section in re.findall(r"---(functions|types)---", statement):
                    function = section == "functions"
                statement = re.sub(r"---(?:functions|types)---", "", statement).strip()
                match = re.fullmatch(r"([\w.]+)#([0-9a-fA-F]+)\s*(.*?)\s*=\s*(.+)", statement, re.S)
                if not match or match[1] == "vector":
                    continue
                name, code, args, result = match.groups()
                args = re.sub(r"\{[^}]*\}", "", args)
                fields = []
                for token in args.split():
                    if ":" not in token:
                        raise ValueError(f"Unsupported schema argument: {token}")
                    field_name, field_type = token.split(":", 1)
                    flag, bit = None, 0
                    if optional := re.fullmatch(r"(\w+)\.(\d+)\?(.+)", field_type):
                        flag, bit, field_type = optional[1], int(optional[2]), optional[3]
                    fields.append(Field(field_name, field_type, flag, bit))
                definition = Definition(name, int(code, 16), tuple(fields), result.strip(), function)
                self.by_name[name] = definition
                self.by_id[definition.id] = definition

    def definition(self, obj: TLObject) -> Definition:
        try:
            return self.by_name[obj.name]
        except KeyError as exc:
            raise ValueError(f"Unknown TL constructor: {obj.name}") from exc

    def result_type(self, request: TLObject) -> str:
        definition = self.definition(request)
        return self.result_type(request.query) if definition.result == "X" else definition.result

    def encode(self, obj: TLObject) -> bytes:
        definition = self.definition(obj)
        known = {f.name for f in definition.fields if f.type != "#"}
        if unknown := set(obj.fields) - known:
            raise TypeError(f"Unknown {obj.name} fields: {sorted(unknown)}")
        flags = {f.name: 0 for f in definition.fields if f.type == "#"}
        for field in definition.fields:
            if field.flag:
                value = obj.fields.get(field.name)
                present = value is True if field.type == "true" else value is not None
                if present:
                    flags[field.flag] |= 1 << field.bit
        out = bytearray(struct.pack("<I", definition.id))
        for field in definition.fields:
            if field.type == "#":
                out += struct.pack("<I", flags[field.name])
                continue
            if field.flag:
                if not flags[field.flag] & (1 << field.bit):
                    continue
                if field.type == "true":
                    continue
            if field.name not in obj.fields or obj.fields[field.name] is None:
                raise TypeError(f"Missing {obj.name}.{field.name} (possibly a shared flag)")
            out += self._encode_value(obj.fields[field.name], field.type)
        return bytes(out)

    def _encode_value(self, value: Any, kind: str) -> bytes:
        if kind in ("int", "long", "#"):
            bits = 64 if kind == "long" else 32
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"Expected TL {kind}")
            if not -(1 << (bits - 1)) <= value < (1 << bits):
                raise ValueError(f"TL {kind} out of range")
            return (value % (1 << bits)).to_bytes(bits // 8, "little")
        if kind == "double":
            return struct.pack("<d", value)
        if kind in ("int128", "int256"):
            width = int(kind[3:]) // 8
            if not isinstance(value, bytes) or len(value) != width:
                raise ValueError(f"{kind} requires {width} bytes")
            return value
        if kind in ("string", "bytes"):
            if kind == "string" and isinstance(value, str):
                value = value.encode("utf-8")
            if not isinstance(value, bytes):
                raise TypeError(f"Expected TL {kind}")
            return pack_bytes(value)
        if vector := re.fullmatch(r"([Vv]ector)<(.+)>", kind):
            if len(value) > MAX_ITEMS:
                raise ValueError("Too many vector elements")
            prefix = struct.pack("<I", VECTOR) if vector[1] == "Vector" else b""
            return prefix + struct.pack("<i", len(value)) + b"".join(self._encode_value(v, vector[2]) for v in value)
        if kind == "Bool" and isinstance(value, bool):
            return struct.pack("<I", 0x997275B5 if value else 0xBC799737)
        if not isinstance(value, TLObject):
            raise TypeError(f"Expected TL object for {kind}")
        definition = self.definition(value)
        if kind not in ("Object", "!X", "X") and definition.result != kind and definition.name != kind:
            raise TypeError(f"{value.name} is {definition.result}, expected {kind}")
        encoded = self.encode(value)
        # Lowercase constructor names in bare vectors omit their constructor ID.
        return encoded[4:] if kind == definition.name else encoded

    def decode(self, data: bytes, kind: str = "Object") -> Any:
        reader = Reader(data)
        obj = self.read(reader, kind)
        if reader.remaining():
            raise ProtocolError("Trailing TL data")
        return obj

    def read(self, reader: Reader, kind: str = "Object", depth: int = 0) -> Any:
        if depth > 100:
            raise ProtocolError("TL nesting exceeds limit")
        formats = {"int": "<i", "long": "<q", "#": "<I", "double": "<d"}
        if kind in formats:
            return reader.unpack(formats[kind])
        if kind in ("int128", "int256"):
            return reader.read(int(kind[3:]) // 8)
        if kind in ("bytes", "string"):
            data = reader.bytes()
            # Handshake fields called 'string' contain binary data, not UTF-8.
            try:
                return data.decode("utf-8") if kind == "string" else data
            except UnicodeDecodeError as exc:
                raise ProtocolError("Invalid UTF-8 TL string") from exc
        if vector := re.fullmatch(r"([Vv]ector)<(.+)>", kind):
            if vector[1] == "Vector":
                code = reader.unpack("<I")
                if code == GZIP:
                    return self._packed(reader, kind, depth)
                if code != VECTOR:
                    raise ProtocolError("Missing vector constructor")
            n = reader.unpack("<i")
            if not 0 <= n <= MAX_ITEMS:
                raise ProtocolError("Invalid TL vector length")
            return [self.read(reader, vector[2], depth + 1) for _ in range(n)]
        bare = self.by_name.get(kind)
        code = bare.id if bare else reader.unpack("<I")
        if code == GZIP:
            return self._packed(reader, kind, depth)
        if code in (0x997275B5, 0xBC799737):
            if kind not in ("Object", "X", "!X", "Bool", "boolTrue", "boolFalse"):
                raise ProtocolError(f"Unexpected Bool, expected {kind}")
            return code == 0x997275B5
        definition = self.by_id.get(code)
        if definition is None:
            raise ProtocolError(f"Unknown TL constructor 0x{code:08x} at layer {self.layer}")
        if kind not in ("Object", "X", "!X") and definition.result != kind and definition.name != kind:
            # RPC errors are a valid alternative result for any request.
            if definition.name != "rpc_error":
                raise ProtocolError(f"Unexpected {definition.name}, expected {kind}")
        values: dict[str, Any] = {}
        flags: dict[str, int] = {}
        for field in definition.fields:
            if field.type == "#":
                flags[field.name] = reader.unpack("<I")
            elif field.flag and not flags[field.flag] & (1 << field.bit):
                values[field.name] = False if field.type == "true" else None
            elif field.type == "true":
                values[field.name] = True
            else:
                # MTProto uses 'string' for arbitrary bytes in its core schema.
                binary = definition.name in _BINARY_FIELDS and field.name in _BINARY_FIELDS[definition.name]
                values[field.name] = self.read(reader, "bytes" if binary else field.type, depth + 1)
        return TLObject(definition.name, **values)

    def _packed(self, reader: Reader, kind: str, depth: int) -> Any:
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(reader.bytes())) as stream:
                data = stream.read(MAX_BYTES + 1)
        except (OSError, EOFError) as exc:
            raise ProtocolError("Invalid compressed TL data") from exc
        if len(data) > MAX_BYTES:
            raise ProtocolError("Expanded gzip exceeds limit")
        inner = Reader(data)
        obj = self.read(inner, kind, depth + 1)
        if inner.remaining():
            raise ProtocolError("Trailing compressed TL data")
        return obj


_BINARY_FIELDS = {
    "resPQ": {"pq"}, "server_DH_params_ok": {"encrypted_answer"},
    "server_DH_inner_data": {"dh_prime", "g_a"}, "p_q_inner_data_dc": {"pq", "p", "q"},
    "req_DH_params": {"p", "q", "encrypted_data"},
    "client_DH_inner_data": {"g_b"}, "set_client_DH_params": {"encrypted_data"},
    "msgs_state_info": {"info"}, "msgs_all_info": {"info"},
}


@lru_cache(maxsize=1)
def default_schema() -> Schema:
    root = files("easyproto").joinpath("schemas")
    return Schema(root.joinpath("mtproto.tl").read_text(), root.joinpath("api.tl").read_text())


class Namespace:
    def __init__(self, prefix: str = "") -> None:
        self.prefix = prefix

    def __getattr__(self, name: str) -> Namespace:
        return Namespace(f"{self.prefix}.{name}" if self.prefix else name)

    def __call__(self, /, **kwargs: Any) -> TLObject:
        obj = TLObject(self.prefix, **kwargs)
        default_schema().encode(obj)  # Fail on missing/unknown arguments immediately.
        return obj


types = Namespace()
functions = Namespace()
