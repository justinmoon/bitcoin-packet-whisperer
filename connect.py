"""
Prior Art:
* https://github.com/petertodd/python-bitcoinlib/blob/master/examples/send-addrs-msg.py
* https://github.com/jimmysong/pb-exercises/blob/master/session7/connect.py
"""
import socket, time, bitcoin, hashlib, io
from bitcoin.messages import msg_version, msg_verack, msg_addr, msg_getdata
from bitcoin.net import CAddress, CInv


from models import Tx
from utils import little_endian_to_int, int_to_little_endian, read_varint, double_sha256


PORT = 8333
NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
bitcoin.SelectParams('mainnet') 


def version_pkt(client_ip, server_ip):
    # https://en.bitcoin.it/wiki/Protocol_documentation#version
    msg = msg_version()
    msg.nVersion = 70002
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


def connect():
    sock = socket.socket()

    server_ip = "91.107.64.143"
    client_ip = "192.168.0.13"

    sock.connect( (server_ip,PORT) )

    # Send Version packet
    # https://en.bitcoin.it/wiki/Protocol_documentation#version
    pkt = version_pkt(client_ip, server_ip)
    sock.send( pkt.to_bytes() )

    # Get Version reply
    print('Received "version" message', sock.recv(1924))

    # Send Verack
    # https://en.bitcoin.it/wiki/Protocol_documentation#verack
    sock.send( msg_verack().to_bytes() )

    # Get Verack reply
    print(' Received "verack" message', sock.recv(1024))

    return sock


def read_msg(stream):
    # https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure

    # FIXME: make this a class

    magic = stream.read(4)
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
    while True:
        data = sock.recv(1024)  # FIXME 1024 is arbitrary, works
        stream = io.BytesIO(data)

        try:
            command, payload = read_msg(stream)
        except RuntimeError as e:
            continue

        if command.startswith(b'inv'):
            inv_vec = read_inv_vec(io.BytesIO(payload))
            msg = msg_getdata()
            msg.inv = inv_vec
            print('Sending inv packet')
            sock.send(msg.to_bytes())

        elif command.startswith(b'tx'):
            payload_stream = io.BytesIO(payload)
            tx = Tx.parse(payload_stream)
            print(f'Received {tx}')

        else:
            print(f"Unhandled {command} command")

        print()


def main():
    sock = connect()
    main_loop(sock)


if __name__ == '__main__':
    main()
