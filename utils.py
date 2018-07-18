import hashlib, struct, hashlib, random


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


def encode_varint(i):
    '''encodes an integer as a varint'''
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8)
    else:
        raise RuntimeError('integer too large: {}'.format(i))


def read_varstr(s):
    length = read_varint(s)
    string = s.read(length)
    return string


def encode_varstr(s):
    length = len(s)
    return encode_varint(length) + s


def read_bool(s):
    int_ = little_endian_to_int(s.read(1))
    bool_ = bool(int_)
    return bool_


def check_bit(number, index):
    """See if the bit at `index` in binary representation of `number` is on"""
    mask = 1 << index
    return bool(number & mask)


def services_int_to_dict(n):
    return {
        'NODE_NETWORK': check_bit(n, 0),           # 1
        'NODE_GETUTXO': check_bit(n, 1),           # 2
        'NODE_BLOOM': check_bit(n, 2),             # 4
        'NODE_WITNESS': check_bit(n, 3),           # 8
        'NODE_NETWORK_LIMITED': check_bit(n, 10),  # 1024
    }

def make_nonce(bytes_of_entropy):
    bits_of_entropy = 8 * bytes_of_entropy
    ceiling = 1 << bits_of_entropy
    return random.randint(0, ceiling)


def consume_stream(s, n):
    if hasattr(s, 'read'):
        return s.read(n)
    elif hasattr(s, 'recv'):
        return s.recv(n)
    else:
        raise RuntimeError("Can't consume stream")


def encode_command(cmd):
    padding_needed = 12 - len(cmd)
    padding = b"\x00" * padding_needed
    return cmd + padding
