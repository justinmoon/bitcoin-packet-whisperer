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

    services_dict = utils.services_int_to_dict(version_msg.services)
    assert services_dict['NODE_NETWORK'] == True
    assert services_dict['NODE_GETUTXO'] == False
    assert services_dict['NODE_BLOOM'] == True
    assert services_dict['NODE_WITNESS'] == True
    assert services_dict['NODE_NETWORK_LIMITED'] == True

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
