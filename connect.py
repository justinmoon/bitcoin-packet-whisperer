"""
Prior Art:
* https://github.com/petertodd/python-bitcoinlib/blob/master/examples/send-addrs-msg.py
* https://github.com/jimmysong/pb-exercises/blob/master/session7/connect.py
"""
import socket, time, bitcoin, hashlib, io, struct
from bitcoin.messages import msg_version, msg_verack, msg_addr, msg_getdata, msg_headers
from bitcoin.net import CAddress, CInv

from models import Tx
from utils import little_endian_to_int, int_to_little_endian, read_varint, double_sha256


PORT = 8333
NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
server_ip = "91.107.64.143"
server_ip = "104.198.92.164"
#server_ip = "73.61.50.116"
bitcoin.SelectParams('mainnet') 
MY_VERSION = 70015  # past bip-31 for ping/pong


def version_pkt(client_ip, server_ip):
    # https://en.bitcoin.it/wiki/Protocol_documentation#version
    msg = msg_version()
    msg.nVersion = MY_VERSION
    msg.addrTo.ip = server_ip
    msg.addrTo.port = PORT
    msg.addrFrom.ip = client_ip
    msg.addrFrom.port = PORT

    return msg

def addr_pkt( str_addrs ):
    # https://en.bitcoin.it/wiki/Protocol_documentation#addr
    msg = msg_addr()
    addrs = []
    for i in str_addrs:
        addr = CAddress()
        addr.port = 18333
        addr.nTime = int(time.time())
        addr.ip = i

        addrs.append( addr )
    msg.addrs = addrs
    return msg


def getdata_pkt( inv_vec ):
    msg = msg_getdata()
    msg.inv = inv_vec
    return msg


def read_inv(stream):
    # https://en.bitcoin.it/wiki/Protocol_documentation#inv
    cinv = CInv()
    cinv.type = little_endian_to_int(stream.read(4))
    cinv.hash = stream.read(32)
    return cinv


def ser_compact_size(l):
    r = b""
    if l < 253:
        r = struct.pack("B", l)
    elif l < 0x10000:
        r = struct.pack("<BH", 253, l)
    elif l < 0x100000000:
        r = struct.pack("<BI", 254, l)
    else:
        r = struct.pack("<BQ", 255, l)
    return r


def deser_compact_size(f):
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return nit


def deser_uint256(f):
    r = 0
    for i in range(8):
        t = struct.unpack("<I", f.read(4))[0]
        r += t << (i * 32)
    return r


def deser_uint256_vector(f):
    nit = deser_compact_size(f)
    r = []
    for i in range(nit):
        t = deser_uint256(f)
        r.append(t)
    return r

def ser_uint256_vector(l):
    r = ser_compact_size(len(l))
    for i in l:
        r += ser_uint256(i)
    return r


def ser_uint256(u):
    rs = b""
    for i in range(8):
        rs += struct.pack("<I", u & 0xFFFFFFFF)
        u >>= 32
    return rs


class msg_pong():
    command = b"pong"

    def __init__(self, nonce=0):
        self.nonce = nonce

    def deserialize(self, f):
        self.nonce = struct.unpack("<Q", f.read(8))[0]

    def serialize(self):
        r = b""
        r += struct.pack("<Q", self.nonce)
        return r

    def __repr__(self):
        return "msg_pong(nonce=%08x)" % self.nonce


class msg_getheaders():
    command = b"getheaders"

    def __init__(self):
        self.locator = CBlockLocator()
        self.hashstop = 0

    def deserialize(self, f):
        self.locator = CBlockLocator()
        self.locator.deserialize(f)
        self.hashstop = deser_uint256(f)

    def serialize(self):
        r = b""
        r += self.locator.serialize()
        r += ser_uint256(self.hashstop)
        return r

    def __repr__(self):
        return "msg_getheaders(locator=%s, stop=%064x)" \
            % (repr(self.locator), self.hashstop)


class msg_getblocks():
    command = b"getblocks"

    def __init__(self):
        self.locator = CBlockLocator()
        self.hashstop = 0

    def deserialize(self, f):
        self.locator = CBlockLocator()
        self.locator.deserialize(f)
        self.hashstop = deser_uint256(f)

    def serialize(self):
        r = b""
        r += self.locator.serialize()
        r += ser_uint256(self.hashstop)
        return r

    def __repr__(self):
        return "msg_getblocks(locator=%s hashstop=%064x)" \
            % (repr(self.locator), self.hashstop)


class msg_sendcmpct():
    command = b"sendcmpct"

    def __init__(self):
        self.announce = False
        self.version = 1

    def deserialize(self, f):
        self.announce = struct.unpack("<?", f.read(1))[0]
        self.version = struct.unpack("<Q", f.read(8))[0]

    def serialize(self):
        r = b""
        r += struct.pack("<?", self.announce)
        r += struct.pack("<Q", self.version)
        return r

    def __repr__(self):
        return "msg_sendcmpct(announce=%s, version=%lu)" % (self.announce, self.version)


class CBlockLocator():
    def __init__(self):
        self.nVersion = MY_VERSION
        self.vHave = []

    def deserialize(self, f):
        self.nVersion = struct.unpack("<i", f.read(4))[0]
        self.vHave = deser_uint256_vector(f)

    def serialize(self):
        r = b""
        r += struct.pack("<i", self.nVersion)
        r += ser_uint256_vector(self.vHave)
        return r

    def __repr__(self):
        return "CBlockLocator(nVersion=%i vHave=%s)" \
            % (self.nVersion, repr(self.vHave))

def connect():
    sock = socket.socket()

    client_ip = "192.168.0.13"

    sock.connect( (server_ip,PORT) )

    # Send Version packet
    # https://en.bitcoin.it/wiki/Protocol_documentation#version
    pkt = version_pkt(client_ip, server_ip)
    sock.send( pkt.to_bytes() )

    # Get Version reply
    data = sock.recv(1924)
    #stream = io.BytesIO(data)
    something = msg_version.from_bytes(data)

    # Send Verack
    # https://en.bitcoin.it/wiki/Protocol_documentation#verack
    sock.send( msg_verack().to_bytes() )

    # Get Verack reply
    print(' Received "verack" message', sock.recv(1024))

    return sock


def get_headers():
    # version (4) int
    # hashcount varinto
    # block locator 32+ string
    # hash stop 32
    pass


def send_getheaders(sock):
    # Seems getblocks must be emitted in response to a version msg ...
    # msg = msg_getblocks()
    msg = msg_getheaders()

    start_hash = "0000000000000000000e6e93e7389fa2e03313c513d12d56014b2599d2ca9701"
    end_hash = "00000000000000000022c9d5b152aefffc766a1a49a57ac0c0e4b0ad534cf394"

    start_hash = int(start_hash, 16)
    end_hash = int(end_hash, 16)
    end_hash = 0 # to get everything

    vHave = [start_hash]

    msg.locator.vHave = vHave
    msg.hashstop = end_hash

    print(msg.serialize())
    sock.send(msg.serialize())



def send_getblocks(sock):
    # Seems getblocks must be emitted in response to a version msg ...
    # msg = msg_getblocks()
    msg = msg_getblocks()

    start_hash = b"0000000000000000000e6e93e7389fa2e03313c513d12d56014b2599d2ca9701"

    # second block ever
    start_hash = b"00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
    start_hash = int(start_hash, 16)

    vHave = [start_hash]
    msg.locator.vHave = vHave

    serialized = msg.serialize()
    sock.send(serialized)


def test():
    sock = socket.socket()
    sock.connect((server_ip, PORT))
    


def read_msg(stream):
    # https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure

    # FIXME: make this a class

    magic = stream.read(4)
    if magic == b'':
        raise ValueError()
    if magic != NETWORK_MAGIC:
        print(f"Magic not right: {magic} != {NETWORK_MAGIC}")
        raise RuntimeError('magic is not right')

    command = stream.read(12)
    payload_length = little_endian_to_int(stream.read(4))
    checksum = stream.read(4)
    payload = stream.read(payload_length)
    calculated_checksum = double_sha256(payload)[:4]

    if calculated_checksum != checksum:
        print(f"Checksums don't match: {calculated_checksum} != {checksum}")
        raise RuntimeError('checksum does not match')

    return command, payload



def read_inv_vec(inv_stream):
    count = read_varint(inv_stream)

    vec = []
    for _ in range(count):
        vec.append(read_inv(inv_stream))

    return vec



def main_loop(sock):
    sent = False
    iterations = 0
    while True:
        data = sock.recv(1024)  # FIXME 1024 is arbitrary, works
        stream = io.BytesIO(data)

        try:
            command, payload = read_msg(stream)
        except RuntimeError as e:
            continue

        if command.startswith(b'inv'):
            inv_vec = read_inv_vec(io.BytesIO(payload))
            print(inv_vec)
            msg = msg_getdata()
            msg.inv = inv_vec
            print('Sending inv packet')
            sock.send(msg.to_bytes())
            if not sent:
                # send_getblocks(sock)
                sent = True

        elif command.startswith(b'tx'):
            print('handled tx')
            payload_stream = io.BytesIO(payload)
            tx = Tx.parse(payload_stream)
            # print(f'Received {tx}')

        elif command.startswith(b'addr'):
            print('Unhandled "addr" message')

        elif command.startswith(b'ping'):
            print('Unhandled "ping" message')

        elif command.startswith(b'sendheaders'):
            print('sendheaders')
            msg = msg_headers()
            sock.send(msg.to_bytes())

        elif command.startswith(b'sendcmpct'):
            print('sendcmpct')
            msg = msg_sendcmpct().deserialize(io.BytesIO(payload))
            import pdb; pdb.set_trace()
            # sock.send(msg.to_bytes())

        else:
            print(f"Unhandled {command} command")
            sock.send(msg_pong().serialize())

        if iterations == 10:
            send_getblocks(sock)
        iterations += 1 
        print()


def main():
    sock = connect()
    try:
        main_loop(sock)
    except (ValueError, KeyboardInterrupt):
        sock.close()



if __name__ == '__main__':
    main()
