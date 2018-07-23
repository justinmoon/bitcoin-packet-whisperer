import io
import unittest
import asyncio
from unittest.mock import Mock
from async_models import Address, Addr
from test_data import ADDR2

def get_mock_coro(return_value):
    @asyncio.coroutine
    def mock_coro(*args, **kwargs):
        return return_value

    return Mock(wraps=mock_coro)


class ImGoingToBeMocked:
    @asyncio.coroutine
    def yeah_im_not_going_to_run(self):
        yield from asyncio.sleep(1)
        return "sup"

class ImBeingTested:
    def __init__(self, hidude):
        self.hidude = hidude

    @asyncio.coroutine
    def i_call_other_coroutines(self):
        return (yield from self.hidude.yeah_im_not_going_to_run())

class TestImBeingTested(unittest.TestCase):

    def test_i_call_other_coroutines(self):
        mocked = Mock(ImGoingToBeMocked)
        mocked.yeah_im_not_going_to_run = get_mock_coro(1)
        ibt = ImBeingTested(mocked)

        ret = asyncio.get_event_loop().run_until_complete(ibt.i_call_other_coroutines())
        self.assertEqual(mocked.yeah_im_not_going_to_run.call_count, 1)


class ReaderMock:

    def __init__(self, bytestring):
        self.buffer = io.BytesIO(bytestring)

    @asyncio.coroutine
    def read(self, n):
        return self.buffer.read(n)
        


class TestAddr(unittest.TestCase):

    def test_parse(self):
        reader = Mock(ReaderMock)
        addr = asyncio.get_event_loop().run_until_complete(Addr.parse(reader))
        print(addr)


