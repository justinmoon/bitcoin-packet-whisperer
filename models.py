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
        return f'<Message {self.command} {self.payload} >'

    @classmethod
    def parse(cls, s):
        magic = consume_stream(s, 4)
        if magic != NETWORK_MAGIC:
            raise RuntimeError('magic is not right')

        command = consume_stream(s, 12)
        payload_length = little_endian_to_int(consume_stream(s, 4))
        checksum = consume_stream(s, 4)
        payload = consume_stream(s, payload_length)
        calculated_checksum = double_sha256(payload)[:4]

        if calculated_checksum != checksum:
            raise RuntimeError('checksum does not match')

        return cls(command, payload)

    def serialize(self):
        result = NETWORK_MAGIC
        result += self.command
        result += int_to_little_endian(len(self.payload), 4)
        result += double_sha256(self.payload)[:4]
        result += self.payload
        return result

    def __repr__(self):
        return f"<Message {self.command} {self.payload}>"

class Version:

    command = b'version\x00\x00\x00\x00\x00\x00'

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

    command = b'verack\x00\x00\x00\x00\x00\x00'

    @classmethod
    def parse(cls, s):
        return cls()

    def serialize(self):
        return b""


class InventoryItem:

    def __init__(self, type_, hash_):
        self.type = type_
        self.hash = hash_
        if type_ != 1:
            print ("\n\n\nGOT SOMETHING SPECIAL!!!!!\n\n\n")

    @classmethod
    def parse(cls, s):
        type_ = little_endian_to_int(s.read(4))
        hash_ = s.read(32)
        return cls(type_, hash_)

    def serialize(self):
        msg = b""
        msg += int_to_little_endian(self.type, 4)
        msg += self.hash
        return msg
    
    def __repr__(self):
        return f"<InvItem {inv_map[self.type]} {self.hash}>"


class InventoryVector:
    command = b"inv\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    def __init__(self, items=None):
        if items is None:
            self.items = []
        else:
            self.items = items

    @classmethod
    def parse(cls, s):
        count = read_varint(s)
        items = [InventoryItem.parse(s) for _ in range(count)]
        return cls(items)

    def serialize(self):
        pass

    def __repr__(self):
        return f"<InvVec {repr(self.items)}>"


class GetData:
    command = b"getdata\x00\x00\x00\x00\x00"

    def __init__(self, items=None):
        if items is None:
            self.items = []
        else:
            self.items = items

    @classmethod
    def parse(cls, s):
        pass

    def serialize(self):
        msg = encode_varint(len(self.items))
        for item in self.items:
            msg += item.serialize()
        return msg


    def __repr__(self):
        return f"<Getdata {repr(self.inv)}>"


class GetBlocks:

    command = b"getblocks"

    def __init__(self, locator, hashstop=0):
        self.locator = locator
        self.hashstop = hashstop

    @classmethod
    def parse(cls, s):
        pass

    def serialize(self):
        msg = self.locator.serialize()
        msg += int_to_little_endian(self.hashstop, 32)
        return msg
    

class GetHeaders:

    command = b"getheaders"

    def __init__(self, locator, hashstop=0):
        self.locator = locator
        self.hashstop = hashstop

    @classmethod
    def parse(cls, s):
        pass

    def serialize(self):
        msg = self.locator.serialize()
        msg += int_to_little_endian(self.hashstop, 32)
        return msg


class BlockLocator:

    def __init__(self, items=None, version=MY_VERSION):
        # self.items is a list of block hashes ... not sure on data type
        if items:
            self.items = items
        else:
            self.items = []
        # this probably shouldn't be so mutable
        self.version = version

    @classmethod
    def parse(cls, s):
        pass

    def serialize(self):
        msg = int_to_little_endian(self.version, 4)
        msg += encode_varint(len(self.items))
        for hash_ in self.items:
            msg += hash_
        return msg
    

class Tx:

    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet

    def __repr__(self):
        return '<Tx version: {} ntx_ins: {} tx_outs: {} nlocktime: {}>'.format(
            self.version,
            ','.join([repr(t) for t in self.tx_ins]),
            ','.join([repr(t) for t in self.tx_outs]),
            self.locktime,
        )

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the transaction at the start
        return a Tx object
        '''
        # s.read(n) will return n bytes
        # version has 4 bytes, little-endian, interpret as int
        version = little_endian_to_int(s.read(4))
        # num_inputs is a varint, use read_varint(s)
        num_inputs = read_varint(s)
        # each input needs parsing
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        # num_outputs is a varint, use read_varint(s)
        num_outputs = read_varint(s)
        # each output needs parsing
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        # locktime is 4 bytes, little-endian
        locktime = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(version, inputs, outputs, locktime)


class TxIn:

    def __init__(self, prev_tx, prev_index, script_sig, sequence):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        self.script_sig = script_sig  # TODO parse it
        self.sequence = sequence

    def __repr__(self):
        return '<TxIn {}:{}>'.format(
            self.prev_tx.hex(),
            self.prev_index,
        )

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_input at the start
        return a TxIn object
        '''
        # s.read(n) will return n bytes
        # prev_tx is 32 bytes, little endian
        prev_tx = s.read(32)[::-1]
        # prev_index is 4 bytes, little endian, interpret as int
        prev_index = little_endian_to_int(s.read(4))
        # script_sig is a variable field (length followed by the data)
        # get the length by using read_varint(s)
        script_sig_length = read_varint(s)
        script_sig = s.read(script_sig_length)
        # sequence is 4 bytes, little-endian, interpret as int
        sequence = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(prev_tx, prev_index, script_sig, sequence)


class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey  # TODO parse it

    def __repr__(self):
        return '<TxOut {}:{}>'.format(self.amount, self.script_pubkey)

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_output at the start
        return a TxOut object
        '''
        # s.read(n) will return n bytes
        # amount is 8 bytes, little endian, interpret as int
        amount = little_endian_to_int(s.read(8))
        # script_pubkey is a variable field (length followed by the data)
        # get the length by using read_varint(s)
        script_pubkey_length = read_varint(s)
        script_pubkey = s.read(script_pubkey_length)
        # return an instance of the class (cls(...))
        return cls(amount, script_pubkey)
