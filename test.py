import io

import raw
import utils
import test_data as td


def test_parse_version():
    raw_version_msg = td.VERSION
    version_msg_bytestream = io.BytesIO(raw_version_msg)
    msg = raw.Message.parse(version_msg_bytestream)
    payload_bytestream = io.BytesIO(msg.payload)
    version_msg = raw.Version.parse(payload_bytestream)

    assert version_msg.version == 70015

    assert version_msg.services['NODE_NETWORK'] == True
    assert version_msg.services['NODE_GETUTXO'] == False
    assert version_msg.services['NODE_BLOOM'] == True
    assert version_msg.services['NODE_WITNESS'] == True
    assert version_msg.services['NODE_NETWORK_LIMITED'] == True

    assert version_msg.timestamp == 1531774979

    # FIXME
    assert version_msg.addr_recv is not None
    assert version_msg.addr_from is not None

    assert version_msg.nonce == 2665238372255235644

    assert version_msg.user_agent == b'/Satoshi:0.16.0/'

    assert version_msg.start_height == 532195

    assert version_msg.relay == 1

    # Parsing & serialization produce same bytestring
    serialized = version_msg.serialize()
    assert msg.payload == serialized


def test_parse_verack():
    #verack_msg = raw.Version.parse(td.VERACK)
    raise NotImplementedError()


def test_read_services():
    services_int = 1024 + 8 + 2
    bit_length = services_int.bit_length()
    little_endian = utils.int_to_little_endian(services_int, bit_length)
    s = io.BytesIO(little_endian)
    services_dict = utils.read_services(s)

    assert services_dict["NODE_NETWORK"] == False
    assert services_dict["NODE_GETUTXO"] == True
    assert services_dict["NODE_BLOOM"] == False
    assert services_dict["NODE_WITNESS"] == True
    assert services_dict["NODE_NETWORK_LIMITED"] == True


