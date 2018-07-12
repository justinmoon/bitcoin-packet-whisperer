"""
Adapted from:
* https://github.com/petertodd/python-bitcoinlib/blob/master/examples/send-addrs-msg.py
* https://github.com/jimmysong/pb-exercises/blob/master/session7/helper.py

Notes:
* It doesn't seem like python-bitcoinlib can really read incoming messages ...
* It's very annoying how python-bitcoinlib's "msg" objects have arbitrarily named data attributes.
Sometimes it's `msg.tx` or `msg.addr` or msg.inv` ...
* How can I tell how many bytes to read beforehand???
"""
import socket, time, bitcoin, hashlib
from io import BytesIO
from bitcoin.messages import msg_version, msg_verack, msg_addr, msg_getdata, MsgSerializable
from bitcoin.net import CAddress, CInv


PORT = 8333
NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'

bitcoin.SelectParams('mainnet') 


txns = []
addrs = []


### utils ####


def version_pkt(client_ip, server_ip):
    # https://en.bitcoin.it/wiki/Protocol_documentation#version
    msg = msg_version()
    msg.nVersion = 70002
    msg.addrTo.ip = server_ip
    msg.addrTo.port = PORT
    msg.addrFrom.ip = client_ip
    msg.addrFrom.port = PORT

    return msg


def int_to_little_endian(n, length):
    '''endian_to_little_endian takes an integer and returns the little-endian
    byte sequence of length'''
    # use the to_bytes method of n
    return n.to_bytes(length, 'little')

def little_endian_to_int(b):
    return int.from_bytes(b, 'little')

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


### networking ###


def connect(server_ip):
    s = socket.socket()

    client_ip = "192.168.0.13"

    s.connect( (server_ip, PORT) )

    # Send Version packet
    s.send( version_pkt(client_ip, server_ip).to_bytes() )
    print('Sent "ver" message')

    return s


def read(s):
    magic = s.recv(4)
    if magic != NETWORK_MAGIC:
        raise RuntimeError('Network Magic not at beginning of stream')
    command = s.recv(12)
    payload_length = little_endian_to_int(s.recv(4))
    checksum = s.recv(4)
    payload = s.recv(payload_length)
    # check the checksum
    if double_sha256(payload)[:4] != checksum:
        raise RuntimeError('Payload and Checksum do not match')
    return command, payload



def log(s):
    while True:
        try:
            command, payload = read(s)
            print(command, payload)
        except RuntimeError as e:
            print('error reading from socket')



def fancy(s):
    while True:
        try:
            command, payload = read(s)
            print(command, payload)
        except RuntimeError as e:
            print('error reading from socket')

        continue

        if command.startswith(b'inv'):

            print('!!!')

            stream = BytesIO(payload)
            count = read_varint(stream)

            for _ in range(count):
                command = stream.read(4)
                payload = stream.read(32)
                e = NetworkEnvelope(command, payload)

                msg = e.serialize()
                print(f'Sending {e}')
                try:
                    s.send(msg)
                except Exception as e:
                    print(e)



def main():
    ip = '39.104.83.148'
    ip = '190.210.234.38'

    s = connect(ip)
    log(s)


if __name__ == '__main__':
    main()
