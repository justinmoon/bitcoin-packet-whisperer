"""
Prior Art:
* https://github.com/petertodd/python-bitcoinlib/blob/master/examples/send-addrs-msg.py
* https://github.com/jimmysong/pb-exercises/blob/master/session7/connect.py
"""
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
)


PORT = 8333
NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
server_ip = "35.187.200.6"  # same as jimmy's
MY_VERSION = 70015  # past bip-31 for ping/pong
NODE_NETWORK = (1 << 0)
NODE_WITNESS = (1 << 3)
USER_AGENT = b"/some-cool-software/"
MY_RELAY = 1 # from version 70001 onwards, fRelay should be appended to version messages (BIP37)

PEER = ("35.187.200.6", 8333)

def construct_version_msg():
    version = MY_VERSION
    services = 1024 + 8 + 4 + 2 + 1  # turn 'em all on
    timestamp = math.floor(datetime.datetime.utcnow().timestamp())
    addr_recv = Address(services=services, ip=0, port=0, time=None)
    addr_from = Address(services=services, ip=0, port=0, time=None)
    nonce = make_nonce(8)
    user_agent = USER_AGENT
    # FIXME
    start_height = 1
    relay = 1
    v = Version(version, services, timestamp, addr_recv, addr_from, nonce, user_agent, start_height, relay)
    # FIXME: string padding is becoming a PITA
    command = b'version\x00\x00\x00\x00\x00'
    payload = v.serialize()
    msg = Message(command, payload)
    return msg


def connect():
    sock = socket.socket()
    sock.connect(PEER)

    version_msg = construct_version_msg()
    sock.send(version_msg.serialize())

    return sock


def recv_msg(sock):
    magic = sock.recv(4)
    if magic == b'':
        raise ValueError()
    if magic != NETWORK_MAGIC:
        print(f"Magic not right: {magic} != {NETWORK_MAGIC}")
        raise RuntimeError('magic is not right')

    command = sock.recv(12)
    payload_length = little_endian_to_int(sock.recv(4))
    checksum = sock.recv(4)
    payload = sock.recv(payload_length)
    calculated_checksum = double_sha256(payload)[:4]

    if calculated_checksum != checksum:
        print(f"Checksums don't match: {calculated_checksum} != {checksum}")
        raise RuntimeError('checksum does not match')
    
    return Message(command, payload)


class Address:

    def __init__(self, services, ip, port, time):
        self.services = services
        self.ip = ip
        self.port = port
        self.time = time

    @classmethod
    def parse(cls, s, version_msg=False):
        # Documentation says that the `time` field ins't present in version messages ...
        if version_msg:
            time = None
        else:
            time = little_endian_to_int(s.read(4))
        services = little_endian_to_int(s.read(8))
        ip = little_endian_to_int(s.read(16))
        port = little_endian_to_int(s.read(2))
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

class Message:

    def __init__(self, command, payload):
        self.command = command
        self.payload = payload

    def __repr__(self):
        return '{}: {}'.format(
            self.command.decode('ascii'),
            self.payload.hex(),
        )

    @classmethod
    def parse(cls, s):
        '''Takes a stream and creates a Message'''
        # FROM HERE https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure
        # check the network magic NETWORK_MAGIC
        # FIXME: this is unusable code (recv vs recv ...)
        magic = s.recv(4)
        if magic != NETWORK_MAGIC:
            raise RuntimeError('magic is not right')
        # command 12 bytes
        command = s.recv(12)
        # payload length 4 bytes, little endian
        payload_length = little_endian_to_int(s.recv(4))
        # checksum 4 bytes, first four of double-sha256 of payload
        checksum = s.recv(4)
        # payload is of length payload_length
        payload = s.recv(payload_length)
        # verify checksum
        calculated_checksum = double_sha256(payload)[:4]
        if calculated_checksum != checksum:
            raise RuntimeError('checksum does not match')
        return cls(command, payload)

    def serialize(self):
        '''Returns the byte serialization of the entire network message'''
        # add the network magic NETWORK_MAGIC
        result = NETWORK_MAGIC
        # command 12 bytes
        result += self.command
        # payload length 4 bytes, little endian
        result += int_to_little_endian(len(self.payload), 4)
        # checksum 4 bytes, first four of double-sha256 of payload
        result += double_sha256(self.payload)[:4]
        # payload
        result += self.payload
        return result

    def __repr__(self):
        return f"<Message {self.command} {self.payload}>"

class Version:

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


def main_loop(sock):
    while True:
        try:
            msg = Message.parse(sock)
            handle_message(msg, sock)
        except RuntimeError as e:
            continue

        print(repr(msg))


def handle_version_msg(payload, sock):
    version_msg = Version.parse(payload)
    print(version_msg)


def handle_verack_msg(payload, sock):
    print('Received Verack')
    command = b'verack\x00\x00\x00\x00\x00\x00'
    payload = b''
    my_verack_msg = Message(command, payload)
    sock.send(my_verack_msg.serialize())


def handle_message(msg, sock):
    handler_map = {
        b'version': handle_version_msg,
        b'verack': handle_verack_msg,
    }
    command = msg.command.replace(b'\x00', b'')
    handler = handler_map.get(command)
    if handler:
        payload_stream = io.BytesIO(msg.payload)
        handler(payload_stream, sock)
    print()


def main():
    sock = connect()
    try:
        main_loop(sock)
    except KeyboardInterrupt:
        sock.close()


if __name__ == '__main__':
    main()
