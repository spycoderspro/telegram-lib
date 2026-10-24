import hashlib
import json
import struct
from importlib.resources import files

import pytest

from easyproto import API_LAYER, TLObject, default_schema, functions, types
from easyproto.errors import ProtocolError
from easyproto.tl import Reader, Schema, pack_bytes


@pytest.mark.parametrize('size', [0, 1, 3, 4, 253, 254, 255, 4096])
def test_tl_bytes_boundaries(size):
    value = bytes([0xAB]) * size
    encoded = pack_bytes(value)
    assert len(encoded) % 4 == 0
    assert encoded[:1] == bytes([size]) if size < 254 else encoded[:4] == b'\xfe' + size.to_bytes(3, 'little')
    reader = Reader(encoded)
    assert reader.bytes() == value
    assert reader.remaining() == 0


def test_send_message_wire_vector():
    value = functions.messages.sendMessage(peer=types.inputPeerSelf(), message='hi', random_id=1, silent=True)
    # Constructor + flags bit 5 + inputPeerSelf + TL string + random_id.
    assert default_schema().encode(value).hex() == '628ff4fe20000000c97ea07d026869000100000000000000'


def test_binary_handshake_fields_are_not_utf8():
    value = TLObject('resPQ', nonce=bytes(16), server_nonce=bytes(16), pq=b'\xff\x80', server_public_key_fingerprints=[-1])
    assert default_schema().decode(default_schema().encode(value)) == value


def test_shared_flags_must_have_all_fields():
    # views and forwards share flags.10 in the actual layer-232 Message schema.
    with pytest.raises(TypeError, match='forwards'):
        types.message(id=1, peer_id=types.peerUser(user_id=2), date=0, message='hi', views=1)


def test_optional_zero_empty_and_false():
    schema = Schema('sample#abcdef01 flags:# yes:flags.0?true number:flags.1?int text:flags.2?string = Sample;')
    value = TLObject('sample', yes=False, number=0, text='')
    assert schema.decode(schema.encode(value)) == value


@pytest.mark.parametrize('data', [b'', b'\x01\0\0', b'\xff\0\0\0', b'\xfe\x01\0\0x\0\0\0', b'\x01x\x01\0'])
def test_invalid_bytes_fail(data):
    with pytest.raises(ProtocolError):
        Reader(data).bytes()


def test_negative_vector_and_unknown_constructor_fail():
    with pytest.raises(ProtocolError):
        default_schema().decode(struct.pack('<Ii', 0x1CB5C415, -1), 'Vector<User>')
    with pytest.raises(ProtocolError, match='Unknown'):
        default_schema().decode(b'\x12\x34\x56\x78')


def test_argument_and_type_validation():
    with pytest.raises(TypeError, match='Unknown'):
        functions.messages.sendMessage(peer=types.inputPeerSelf(), message='hi', random_id=1, typo=True)
    with pytest.raises(TypeError, match='expected InputPeer'):
        functions.messages.sendMessage(peer=types.inputUserSelf(), message='hi', random_id=1)


def test_self_flag_and_nested_gzip_bound():
    import gzip
    schema=default_schema()
    user=types.user(id=42,self=True)
    assert schema.decode(schema.encode(user)).get('self') is True
    data=struct.pack('<Ii',0x1CB5C415,1)+schema.encode(user)
    packed=struct.pack('<I',0x3072CFA1)+pack_bytes(gzip.compress(data))
    assert schema.decode(packed,'Vector<User>')[0].id==42
    for _ in range(102):
        packed=struct.pack('<I',0x3072CFA1)+pack_bytes(gzip.compress(packed))
    with pytest.raises(ProtocolError,match='nesting'): schema.decode(packed,'Vector<User>')


def test_schema_provenance_and_layer():
    root = files('easyproto').joinpath('schemas')
    provenance = json.loads(root.joinpath('provenance.json').read_text())
    assert API_LAYER == provenance['layer'] == 232
    assert len(default_schema().by_name) > 2600
    for filename, metadata in provenance['files'].items():
        assert hashlib.sha256(root.joinpath(filename).read_bytes()).hexdigest() == metadata['sha256']


def test_every_api_declaration_can_encode_and_decode():
    schema = default_schema()
    alternatives = {}
    for definition in schema.by_name.values():
        if not definition.function:
            alternatives.setdefault(definition.result, []).append(definition)
    for candidates in alternatives.values():
        candidates.sort(key=lambda d: sum(not f.flag and f.type != '#' for f in d.fields))

    def sample(kind, stack):
        if kind in ('int', 'long', '#'): return 0
        if kind == 'double': return 1.25
        if kind == 'int128': return bytes(16)
        if kind == 'int256': return bytes(32)
        if kind == 'bytes': return b''
        if kind == 'string': return ''
        if kind == 'Bool': return True
        if kind.startswith(('Vector<', 'vector<')): return []
        if kind in ('!X', 'X', 'Object'): return functions.help.getConfig()
        candidates = [schema.by_name[kind]] if kind in schema.by_name else alternatives.get(kind, [])
        for definition in candidates:
            if definition.name in stack: continue
            try:
                return construct(definition, stack)
            except ValueError:
                continue
        raise ValueError(f'No finite constructor for {kind}')

    def construct(definition, stack):
        return TLObject(definition.name, **{f.name: sample(f.type, stack | {definition.name})
                        for f in definition.fields if not f.flag and f.type != '#'})

    for definition in schema.by_name.values():
        # Core handwritten pseudo-types without IDs never enter this registry.
        value = construct(definition, set())
        encoded = schema.encode(value)
        decoded = schema.decode(encoded)
        assert (schema._encode_value(decoded, 'Bool') if isinstance(decoded, bool) else schema.encode(decoded)) == encoded, definition.name
