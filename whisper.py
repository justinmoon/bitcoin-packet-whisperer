"""
Adapted from:
* https://github.com/petertodd/python-bitcoinlib/blob/master/examples/send-addrs-msg.py
* https://github.com/jimmysong/pb-exercises/blob/master/session7/helper.py

Notes:
* It doesn't seem like python-bitcoinlib can really read incoming messages ...
* It's very annoying how python-bitcoinlib's "msg" objects have arbitrarily named data attributes.
Sometimes it's `msg.tx` or `msg.addr` or msg.inv` ...
"""
import socket, time, bitcoin, hashlib
from bitcoin.messages import msg_version, msg_verack, msg_addr, msg_getdata, MsgSerializable
from bitcoin.net import CAddress, CInv


PORT = 8333
NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'

bitcoin.SelectParams('mainnet') 


txns = []
addrs = []


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
    # so annoying how this lib doesn't use constructors ...
    msg = msg_getdata()
    msg.inv = inv_vec
    return msg

def connect():
    s = socket.socket()

    # The old server_ip value didn't work
    server_ip = "91.107.64.143"
    # Copied from python-bitcoinlib example
    client_ip = "192.168.0.13"

    s.connect( (server_ip,PORT) )

    # Send Version packet
    s.send( version_pkt(client_ip, server_ip).to_bytes() )
    print('Sent "ver" message')

    # Get Version reply
    # TODO: Should we do something with it? How to read it?
    ver = s.recv(1924)
    print('Received "ver" message')

    # Send Verack
    # https://en.bitcoin.it/wiki/Protocol_documentation#verack
    s.send( msg_verack().to_bytes() )

    # Get Verack
    # TODO: Should we do something with it? How to read it?
    verack = s.recv(1024)
    print('Received "verack" message')

    # Send Addrs
    # FIXME: what address is this?
    s.send( addr_pkt(["252.11.1.2", "EEEE:7777:8888:AAAA::1"]).to_bytes() )
    print('Sent "verack" message')
    
    return s


def main_loop(s):
    iterations = 0

    while True:
        print()

        data = s.recv(1024* 100)

        try:
            # FIXME: this is broken. Can I just stream from the socket???
            msg = MsgSerializable.from_bytes(data)
        except Exception as e:
            print(f'Message deserialization failed: {e}')
            continue

        if msg.command == b'inv':
            # https://en.bitcoin.it/wiki/Protocol_documentation#getdata
            # msg.inv is actually an inv_vec
            m = getdata_pkt(msg.inv)
            s.send(m.to_bytes())
            print(f'Sent "inv" message: {msg.inv}')

        if msg.command == b'tx':
            txns.append(msg.tx)
            print(f'Received "tx": {msg.tx}')

        if msg.command == b'addr':
            addrs.extend(msg.addrs)
            print(f'Received "addrs": {msg.addrs}')

        # HACK
        iterations += 1
        if iterations % 10 == 0:
            print(f"#txns: {len(txns)}")
            print(f"#addrs: {len(addrs)}")


def main():
    s = connect()
    main_loop(s)


if __name__ == '__main__':
    main()
