import asyncio

from async_models import Message, NETWORK_MAGIC, Addr, GetAddr
from utils import double_sha256, int_to_little_endian, little_endian_to_int


VERSION = bytes.fromhex(
    "f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001"
)
VERACK = bytes.fromhex("f9beb4d976657261636b000000000000000000005df6e0e2")

first_host = "35.187.200.6"
port = 8333

last_host = "176.9.113.254"


async def read_message(reader):
    magic = await reader.read(4)
    if magic != NETWORK_MAGIC:
        raise RuntimeError("Network Magic not at beginning of stream")
    command = await reader.read(12)
    payload_length = little_endian_to_int(await reader.read(4))
    checksum = await reader.read(4)
    payload = await reader.read(payload_length)
    if double_sha256(payload)[:4] != checksum:
        raise RuntimeError("Payload and Checksum do not match")
    return Message(command, payload)


async def handle_message(msg, reader, writer, host):
    if msg.command.startswith(b"version"):
        writer.write(VERACK)
        return f"({host}) sent verack"
    if msg.command.startswith(b"verack"):
        return f"({host}) received verack"
    if msg.command.startswith(b"addr"):
        print("addr payload: ", msg.payload)
        addr = await Addr.parse(reader)
        print(addr.addresses)
        for address in addr.addresses:
            # FIXME: check whether we're already connected
            import pdb; pdb.set_trace()
            asyncio.ensure_future(connect(address.ip, address.port))
        return msg.payload
    else:
        command = msg.command.replace(b"\x00", b"")
        return f"received {command} from {host}"


async def connect(host, port, bootstrap=False):
    reader, writer = await asyncio.open_connection(host, port)
    print(f"({host}) connected")
    writer.write(VERSION)
    msg = await read_message(reader)
    print(f"({host}) {msg}")
    res = await handle_message(msg, reader, writer, host)
    print(f"({host}) {res}")

    if bootstrap:
        # create another task and add it to the loop
        asyncio.ensure_future(connect(last_host, port))

    # ask for their list of peers ... doesn't seem to do anything ...
    getaddr = GetAddr()
    getaddr_msg = Message(command=getaddr.command, payload=getaddr.serialize())
    writer.write(getaddr.serialize())
    print(f"({host}) sent getaddr")

    await loop(host, port, reader, writer)


async def loop(host, port, reader, writer):
    # recursively read the next message from this peer
    msg = await read_message(reader)
    res = await handle_message(msg, reader, writer, host)
    print(res)
    await loop(host, port, reader, writer)


async def main():
    task = connect(first_host, port, bootstrap=True)
    await asyncio.gather(task)


if __name__ == "__main__":
    asyncio.run(main())
