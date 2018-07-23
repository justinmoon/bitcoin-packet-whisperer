import socket
import time
import io
import struct
import random
import datetime
import math

from utils import (
    little_endian_to_int, 
    int_to_little_endian, 
    read_varint, 
    encode_varint,
    read_varstr, 
    encode_varstr,
    double_sha256,
    read_bool,
    make_nonce,
    consume_stream,
    encode_command,
    parse_command,

    read_varint_async,
)

NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
MY_VERSION = 70015  # past bip-31 for ping/pong
NODE_NETWORK = (1 << 0)
NODE_WITNESS = (1 << 3)
USER_AGENT = b"/some-cool-software/"
MY_RELAY = 1 # from version 70001 onwards, fRelay should be appended to version messages (BIP37)

PEER = ("35.187.200.6", 8333)

inv_map = {
    0: "ERROR",
    1: "MSG_TX",
    2: "MSG_BLOCK",
    3: "MSG_FILTERED_BLOCK",
    4: "MSG_CMPCT_BLOCK",
}



class Message:

    def __init__(self, command, payload):
        self.command = command
        self.payload = payload

    def __repr__(self):
        return f'<Message {self.command} {self.payload} >'

    @classmethod
    def parse(cls, s):
        magic = consume_stream(s, 4)
        if magic != NETWORK_MAGIC:
            raise ValueError('magic is not right')

        command = parse_command(consume_stream(s, 12))
        payload_length = little_endian_to_int(consume_stream(s, 4))
        checksum = consume_stream(s, 4)
        payload = consume_stream(s, payload_length)
        calculated_checksum = double_sha256(payload)[:4]

        if calculated_checksum != checksum:
            raise RuntimeError('checksum does not match')

        if payload_length != len(payload):
            raise RuntimeError("Tried to read {payload_length} bytes, only received {len(payload)} bytes")

        return cls(command, payload)

    def serialize(self):
        result = NETWORK_MAGIC
        result += encode_command(self.command)
        result += int_to_little_endian(len(self.payload), 4)
        result += double_sha256(self.payload)[:4]
        result += self.payload
        return result

    def __repr__(self):
        return f"<Message {self.command} {self.payload}>"


class Address:

    def __init__(self, services, ip, port, time):
        self.services = services
        self.ip = ip
        self.port = port
        self.time = time

    # FIXME this is wrong. parsing payloads won't by async. it will be reading a BytesIO blob ...
    @classmethod
    async def parse(cls, s, version_msg=False):
        # Documentation says that the `time` field ins't present in version messages ...
        if version_msg:
            time = None
        else:
            time = little_endian_to_int(await s.read(4))
        services = little_endian_to_int(await s.read(8))
        # FIXME
        _ = await s.read(12)
        ip = await s.read(4)
        port = little_endian_to_int(await s.read(2))
        return cls(services, ip, port, time)

    def serialize(self, version_msg=False):
        msg = b""
        # FIXME: What's the right condition here
        if self.time:
            msg += int_to_little_endian(self.time, 4)
        msg += int_to_little_endian(self.services, 8)
        msg += int_to_little_endian(self.ip, 16)
        msg += int_to_little_endian(self.port, 2)
        return msg

    def __repr__(self):
        return f"<Address {self.ip}:{self.port}>"


class Version:

    command = b'version'

    def __init__(self, version, services, timestamp, addr_recv, addr_from, nonce, user_agent, start_height, relay):
        self.version = version
        self.services = services
        self.timestamp = timestamp
        self.addr_recv = addr_recv
        # Seems addr_from is ignored https://bitcoin.stackexchange.com/questions/73015/what-is-the-purpose-of-addr-from-and-addr-recv-in-version-message
        self.addr_from = addr_from
        self.nonce = nonce
        self.user_agent = user_agent
        self.start_height = start_height
        self.relay = relay

    @classmethod
    def parse(cls, s):
        version = little_endian_to_int(s.read(4))
        services = little_endian_to_int(s.read(8))
        timestamp = little_endian_to_int(s.read(8))
        addr_recv = Address.parse(io.BytesIO(s.read(26)), version_msg=True)
        addr_from = Address.parse(io.BytesIO(s.read(26)), version_msg=True)
        nonce = little_endian_to_int(s.read(8))
        user_agent = read_varstr(s)  # Should we convert stuff like to to strings?
        start_height = little_endian_to_int(s.read(4))
        relay = little_endian_to_int(s.read(1))
        return cls(version, services, timestamp, addr_recv, addr_from, nonce, user_agent, start_height, relay)

    def serialize(self):
        msg = b""
        msg += int_to_little_endian(self.version, 4)
        msg += int_to_little_endian(self.services, 8)
        msg += int_to_little_endian(self.timestamp, 8)
        msg += self.addr_recv.serialize()
        msg += self.addr_from.serialize()
        msg += int_to_little_endian(self.nonce, 8)
        msg += encode_varstr(self.user_agent)
        msg += int_to_little_endian(self.start_height, 4)
        msg += int_to_little_endian(self.relay, 1)
        return msg


class Verack:

    command = b'verack'

    @classmethod
    def parse(cls, s):
        return cls()

    def serialize(self):
        return b""


class GetAddr:

    command = b'getaddr'

    @classmethod
    def parse(cls, s):
        return cls()

    def serialize(self):
        return b""


class Addr:
    command = b"addr"

    def __init__(self, addresses):
        self.addresses = addresses

    @classmethod
    async def parse(cls, s):
        count = await read_varint_async(s)
        addresses = []
        for _ in range(1):
            # FIXME
            throwaway_timestamp = await s.read(8)
            addresses.append(await Address.parse(s))
        return cls(addresses)

    def serialize(self):
        pass
    
    def __repr__(self):
        return f"<Addr {len(self.addresses)}>"
