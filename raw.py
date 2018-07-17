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

from utils import (
    little_endian_to_int, 
    int_to_little_endian, 
    read_varint, 
    read_varstr, 
    double_sha256,
    read_bool,
    read_services,
)


PORT = 8333
NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
server_ip = "35.187.200.6"  # same as jimmy's
MY_VERSION = 70015  # past bip-31 for ping/pong
NODE_NETWORK = (1 << 0)
NODE_WITNESS = (1 << 3)
MY_SUBVERSION = b"/justins-cool-software/"
MY_RELAY = 1 # from version 70001 onwards, fRelay should be appended to version messages (BIP37)


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
    
    # cleanup ... should do this elsewhere
    command = command.replace(b'\x00', b'')
    payload = io.BytesIO(payload)

    return command, payload


class Address:

    def __init__(self, services, ip, port, time=None):
        self.services = services
        self.ip = ip
        self.port = port
        self.time = time

    @classmethod
    def parse(cls, s, version_msg=False):
        # if version_msg ...
        services = read_services(s)
        ip = s.read(16)
        port = little_endian_to_int(s.read(2))
        return


class NetworkEnvelope:

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
        '''Takes a stream and creates a NetworkEnvelope'''
        # FROM HERE https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure
        # check the network magic NETWORK_MAGIC
        magic = s.read(4)
        if magic != NETWORK_MAGIC:
            raise RuntimeError('magic is not right')
        # command 12 bytes
        command = s.read(12)
        # payload length 4 bytes, little endian
        payload_length = little_endian_to_int(s.read(4))
        # checksum 4 bytes, first four of double-sha256 of payload
        checksum = s.read(4)
        # payload is of length payload_length
        payload = s.read(payload_length)
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


class Version:

    def __init__(self, version, services, timestamp, addr_recv, addr_from, nonce, user_agent, start_height, relay):
        self.version = version
        self.services = services
        self.timestamp = timestamp
        self.addr_recv = addr_recv
        self.addr_from = addr_from
        self.nonce = nonce
        self.user_agent = user_agent
        self.start_height = start_height
        self.relay = relay

    @classmethod
    def parse(cls, s):
        version = little_endian_to_int(s.read(4))
        services = read_services(s)
        timestamp = little_endian_to_int(s.read(8))
        addr_recv = Address.parse(io.BytesIO(s.read(26)))
        addr_from = Address.parse(io.BytesIO(s.read(26)))
        nonce = little_endian_to_int(s.read(8))
        user_agent = read_varstr(s)
        start_height = little_endian_to_int(s.read(4))
        relay = little_endian_to_int(s.read(1))
        return cls(version, services, timestamp, addr_recv, addr_from, nonce, user_agent, start_height, relay)

    def serialize(self):
        pass

def loop(sock):
    while True:
        try:
            command, payload = recv_msg(sock)
        except RuntimeError as e:
            continue

        print(f"{command} - {payload}")


def main():
    sock = connect()
    # send_getblocks(sock)
    try:
        loop(sock)
    except KeyboardInterrupt:
        sock.close()


if __name__ == '__main__':
    main()
