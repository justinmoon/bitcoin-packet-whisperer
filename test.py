import io

import raw
import utils
import test_data as td


def test_parse_version():
    raw_version_msg = td.VERSION
    version_msg_bytestream = io.BytesIO(raw_version_msg)
    envelope = raw.NetworkEnvelope.parse(version_msg_bytestream)
    payload_bytestream = io.BytesIO(envelope.payload)
    version_msg = raw.Version.parse(payload_bytestream)

    assert version_msg.version == 70015
    assert version_msg.services['NODE_NETWORK'] == 1
    assert version_msg.services['NODE_GETUTXO'] == 0


def test_parse_verack():
    verack_msg = raw.Version.parse(td.VERACK)


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


