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
)

from models import (
    Message,
    Address,
    Version,
    Verack,
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
    return sock

def send_version_msg(sock):
    version_msg = construct_version_msg()
    sock.send(version_msg.serialize())


def handle_version(payload, sock):
    version_msg = Version.parse(payload)
    print(version_msg)


def handle_verack(payload, sock):
    print('Received Verack')
    verack = Verack()
    msg = Message(verack.command, verack.serialize())
    sock.send(msg.serialize())


def handle_msg(msg, sock):
    handler_map = {
        b'version': handle_version,
        b'verack': handle_verack,
    }
    command = msg.command.replace(b'\x00', b'')
    handler = handler_map.get(command)
    if handler:
        payload_stream = io.BytesIO(msg.payload)
        handler(payload_stream, sock)
    else:
        print(f"Unhandled command={command} payload-{msg.payload}")


def main_loop(sock):
    while True:
        try:
            msg = Message.parse(sock)
            handle_msg(msg, sock)
        except RuntimeError as e:
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
