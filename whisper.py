#!/usr/bin/env python3

import socket, time, bitcoin, hashlib
from bitcoin.messages import msg_version, msg_verack, msg_addr, msg_getdata
from bitcoin.net import CAddress, CInv

PORT = 8333

bitcoin.SelectParams('mainnet') 


def little_endian_to_int(b):
    return int.from_bytes(b, 'little')


def int_to_little_endian(n, length):
    return n.to_bytes(length, 'little')


def double_sha256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def read_varint(s):
    '''read_varint reads a variable integer from a stream'''
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
    msg = msg_version()
    msg.nVersion = 70002
    msg.addrTo.ip = server_ip
    msg.addrTo.port = PORT
    msg.addrFrom.ip = client_ip
    msg.addrFrom.port = PORT

    return msg

def addr_pkt( str_addrs ):
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
    msg = msg_getdata()
    for type_, hash_ in inv:
        cinv = CInv()
        cinv.type = type_
        cinv.hash = hash_
        msg.inv.append(cinv)
    return msg


s = socket.socket()

# The old server_ip value didn't work
server_ip = "91.107.64.143"
client_ip = "192.168.0.13"

s.connect( (server_ip,PORT) )

# Send Version packet
s.send( version_pkt(client_ip, server_ip).to_bytes() )

# Get Version reply
print(s.recv(1924))

# Send Verack
s.send( msg_verack().to_bytes() )
# Get Verack
print(s.recv(1024))

# Send Addrs
s.send( addr_pkt(["252.11.1.2", "EEEE:7777:8888:AAAA::1"]).to_bytes() )

b'inv\x00\x00\x00\x00\x00\x00\x00\x00\x00'

def read_inv(stream):
    type_ = little_endian_to_int(stream.read(4))
    hash_ = stream.read(32)
    return (type_, hash_)

NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'

while True:
    data = s.recv(1024)
    import io
    stream = io.BytesIO(data)
    magic = stream.read(4)
    if magic != NETWORK_MAGIC:
        print(f"{magic} != {NETWORK_MAGIC}")
        print()
        continue
        #raise RuntimeError('magic is not right')
    command = stream.read(12)
    payload_length = little_endian_to_int(stream.read(4))
    checksum = stream.read(4)
    payload = stream.read(payload_length)
    calculated_checksum = double_sha256(payload)[:4]

    # FIXME
    # print(calculated_checksum, checksum)
    # if calculated_checksum != checksum:
    #     raise RuntimeError('checksum does not match')

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

time.sleep(1) 
s.close()

# debug log on the server should look like:
# accepted connection 192.168.0.13:39979
# send version message: version 70002, blocks=317947, us=****, them=0.0.0.0:0, peer=192.168.0.13:39979
# receive version message: /pythonbitcoin0.0.1/: version 70002, blocks=-1, us=192.168.0.149:18333, them=192.168.0.13:18333, peer=192.168.0.13:39979
# Added 2 addresses from 192.168.0.13: 3 tried, 1706 new
# disconnecting node 192.168.0.13:39979


