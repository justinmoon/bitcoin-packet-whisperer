import hashlib, struct, hashlib


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


# TODO: class?
def read_services(s):
    services = little_endian_to_int(s.read(8))
    return {
        'NODE_NETWORK': check_bit(services, 0),          # 1
        'NODE_GETUTXO': check_bit(services, 1),          # 2
        'NODE_BLOOM': check_bit(services, 2),            # 4
        'NODE_WITNESS': check_bit(services, 3),          # 8
        'NODE_NETWORK_LIMITED': check_bit(services, 10),  # 1024
    }


def encode_services(s):
    number = sum([
        int(s['NODE_NETWORK']) * 1,
        int(s['NODE_GETUTXO']) * 2,
        int(s['NODE_BLOOM']) * 4,
        int(s['NODE_WITNESS']) * 8,
        int(s['NODE_NETWORK_LIMITED']) * 1024,
    ])
    return int_to_little_endian(number, 8)
