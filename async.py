import asyncio

from async_models import Message, NETWORK_MAGIC
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


async def handle_message(env, writer, host):
    if env.command.startswith(b"version"):
        writer.write(VERACK)
        return f"({host}) sent verack"
    if env.command.startswith(b"verack"):
        return f"({host}) received verack"
    if env.command.startswith(b"addr"):
        return env.payload
    else:
        command = env.command.replace(b"\x00", b"")
        return f"received {command} from {host}"


async def connect(host, port, bootstrap=False):
    reader, writer = await asyncio.open_connection(host, port)
    print(f"({host}) connected")
    writer.write(VERSION)
    env = await read_message(reader)
    print(f"({host}) {env}")
    response = await handle_message(env, writer, host)
    print(f"({host}) {response}")

    if bootstrap:
        # create another task and add it to the loop
        asyncio.ensure_future(connect(last_host, port))

    await loop(host, port, reader, writer)


async def loop(host, port, reader, writer):
    # recursively read the next message from this peer
    envelope = await read_message(reader)
    msg = await handle_message(envelope, writer, host)
    print(msg)
    await loop(host, port, reader, writer)


async def main():
    task = connect(first_host, port, bootstrap=True)
    await asyncio.gather(task)


if __name__ == "__main__":
    asyncio.run(main())
