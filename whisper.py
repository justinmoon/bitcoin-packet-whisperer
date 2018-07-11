"""
Adapted from:
* https://github.com/petertodd/python-bitcoinlib/blob/master/examples/send-addrs-msg.py
* https://github.com/jimmysong/pb-exercises/blob/master/session7/helper.py
"""
import socket, time, bitcoin, hashlib
from bitcoin.messages import msg_version, msg_verack, msg_addr, msg_getdata
from bitcoin.net import CAddress, CInv


PORT = 8333
NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'

bitcoin.SelectParams('mainnet') 


def little_endian_to_int(b):
    return int.from_bytes(b, 'little')


def int_to_little_endian(n, length):
    return n.to_bytes(length, 'little')


def double_sha256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def read_varint(s):
    # https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
    i = s.read(1)[0]
    if i == 0xfd:
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        # 0xff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i


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

def getdata_pkt( inv ):
    # https://en.bitcoin.it/wiki/Protocol_documentation#getdata
    msg = msg_getdata()
    for type_, hash_ in inv:
        cinv = CInv()
        cinv.type = type_
        cinv.hash = hash_
        msg.inv.append(cinv)
    return msg


def read_inv(stream):
    # https://en.bitcoin.it/wiki/Protocol_documentation#inv
    type_ = little_endian_to_int(stream.read(4))
    hash_ = stream.read(32)
    return (type_, hash_)


def connect():
    s = socket.socket()

    # The old server_ip value didn't work
    server_ip = "91.107.64.143"
    # Copied from python-bitcoinlib example
    client_ip = "192.168.0.13"

    s.connect( (server_ip,PORT) )

    # Send Version packet
    s.send( version_pkt(client_ip, server_ip).to_bytes() )

    # Get Version reply
    # TODO: Should we do something with it?
    # TODO: Print something useful
    print(s.recv(1924))

    # Send Verack
    # https://en.bitcoin.it/wiki/Protocol_documentation#verack
    s.send( msg_verack().to_bytes() )

    # Get Verack
    # TODO: Should we do something with it?
    print(s.recv(1024))

    # Send Addrs
    # FIXME: what address is this?
    s.send( addr_pkt(["252.11.1.2", "EEEE:7777:8888:AAAA::1"]).to_bytes() )
    return s


def main_loop(s):
    while True:
        data = s.recv(1024)
        import io
        stream = io.BytesIO(data)

        # FIXME: write helper function
        # https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure
        magic = stream.read(4)
        if magic != NETWORK_MAGIC:
            # FIXME broken
            print(f"{magic} != {NETWORK_MAGIC}")
            print()
            continue
            #raise RuntimeError('magic is not right')
        command = stream.read(12)
        payload_length = little_endian_to_int(stream.read(4))
        checksum = stream.read(4)
        payload = stream.read(payload_length)
        calculated_checksum = double_sha256(payload)[:4]

        # FIXME broken
        # print(calculated_checksum, checksum)
        # if calculated_checksum != checksum:
        #     raise RuntimeError('checksum does not match')

        # FIXME: write handle_inv()
        if command.startswith(b'inv'):
            inv_stream = io.BytesIO(payload)
            count = read_varint(inv_stream)
            inv_vec = []
            for _ in range(count):
                inv_vec.append(read_inv(inv_stream))
            pkt = getdata_pkt(inv_vec)
            print('sending inv packet')
            s.send(pkt.to_bytes())

            

        print(command)
        #print(payload)
        print()


def main():
    s = connect()
    main_loop(s)


if __name__ == '__main__':
    main()
