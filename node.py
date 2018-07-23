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
    make_nonce,
    services_int_to_dict,
    encode_command,
    int_to_little_endian,
)

from models import (
    Message,
    Address,
    Version,
    Verack,
    InventoryVector,
    InventoryItem,
    GetData,
    BlockLocator,
    GetHeaders,
    GetBlocks,
    Block,
    Headers,
    Tx,
    TxIn,
    TxOut,
)


NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
MY_VERSION = 70015  # past bip-31 for ping/pong
NODE_NETWORK = (1 << 0)
NODE_WITNESS = (1 << 3)
USER_AGENT = b"/some-cool-software/"
MY_RELAY = 1 # from version 70001 onwards, fRelay should be appended to version messages (BIP37)

PEER = ("35.187.200.6", 8333)


genesis = int("00000000000000000013424801fbec52484d7211c223beec97f02236a9b6ee03", 16)

# just stores the integer representation of the headers
blocks = [genesis]


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

    command = encode_command(b'version')
    payload = v.serialize()
    msg = Message(command, payload)
    return msg


def connect():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.connect(PEER)
    return sock


def send_version_msg(sock):
    version_msg = construct_version_msg()
    print('serialized version ', version_msg.serialize())
    sock.send(version_msg.serialize())


def construct_block_locator():
    step = 1
    height = len(blocks) - 1
    hashes = []

    while height >= 0:
        if len(hashes) >= 10:
            step *= 2
        header = blocks[height]
        hashes.append(header)
        height -= step

    if not blocks.index(genesis):
        blocks.append(genesis)

    return BlockLocator(items=hashes)
    

def construct_block_locator_for_blocks():
    step = 1
    height = len(blocks) - 1
    hashes = []

    while height >= 0:
        if len(hashes) >= 10:
            step *= 2
        header = blocks[height]
        hashes.append(header)
        height -= step

    if not blocks.index(genesis):
        blocks.append(genesis)

    return BlockLocator(items=hashes)


def send_getheaders(sock):
    locator = construct_block_locator()
    getheaders = GetHeaders(locator)
    msg = Message(getheaders.command, getheaders.serialize())
    sock.send(msg.serialize())
    print('sent getheaders')


def send_getblocks(sock):
    locator = construct_block_locator_for_blocks()
    getblocks = GetBlocks(locator)
    msg = Message(getblocks.command, getblocks.serialize())
    sock.send(msg.serialize())
    print('sent getblocks')


def handle_version(payload, sock):
    version_msg = Version.parse(payload)
    print(services_int_to_dict(version_msg.services))
    print(version_msg)


def handle_verack(payload, sock):
    print('Received Verack')
    verack = Verack()
    msg = Message(verack.command, verack.serialize())
    sock.send(msg.serialize())

    # FIXME just here for now ...
    send_getheaders(sock)


def handle_inv(payload, sock):
    inv_vec = InventoryVector.parse(payload)
    getdata = GetData(items=inv_vec.items)
    msg = Message(getdata.command, getdata.serialize())
    sock.send(msg.serialize())
    print("sent getdata")

def update_blocks(block_headers):
    for header in block_headers.headers:
        # this is naive ...
        # we add it to the blocks if prev_block is our current tip
        if header.prev_block == blocks[-1]:
            blocks.append(header.pow())
        else:
            break

def handle_headers(payload, sock):
    block_headers = Headers.parse(payload)
    print(f'{len(block_headers.headers)} new headers')
    update_blocks(block_headers)

    # after 500 headers, get the blocks
    if len(blocks) < 500:
        send_getheaders(sock)
    else:
        items = [InventoryItem(2, int_to_little_endian(hash_, 32)) for hash_ in blocks[:10]]
        getdata = GetData(items=items)
        msg = Message(getdata.command, getdata.serialize())
        sock.send(msg.serialize())

    print(f'We now have {len(blocks)} headers')


def handle_block(payload, sock):
    block = Block.parse(payload)
    print(block)


def handle_tx(payload, sock):
    tx = Tx.parse(payload)
    print("Received Tx: ", tx)


def handle_msg(msg, sock):
    handler_map = {
        b'version': handle_version,
        b'verack': handle_verack,
        b'inv': handle_inv,
        b'tx': handle_tx,
        b'block': handle_block,
        b'headers': handle_headers,
    }
    handler = handler_map.get(msg.command)
    if handler:
        payload_stream = io.BytesIO(msg.payload)
        handler(payload_stream, sock)
    else:
        print(f"Unhandled command={msg.command}")


def main_loop(sock):
    while True:
        try:
            msg = Message.parse(sock)
            handle_msg(msg, sock)
        except RuntimeError as e:
            print(e)
            continue
        print()


def main():
    sock = connect()
    send_version_msg(sock)
    try:
        main_loop(sock)
    except KeyboardInterrupt:
        sock.close()


if __name__ == '__main__':
    main()
