import asyncio, asynctest
import io
import mock 
import pytest
from pytest_mock import mocker 

import test_data

# content of test_module.py
import os.path
def getssh(): # pseudo application code
    return os.path.join(os.path.expanduser("~admin"), '.ssh')

def foo(monkeypatch):
    def mockreturn(path):
        return '/abc'
    monkeypatch.setattr(os.path, 'expanduser', mockreturn)
    x = getssh()
    assert x == '/abc/.ssh'

data = io.BytesIO(test_data.VERSION)

async def read(n):
    global data
    return data.read(n)



def test_reader(mocker):
    mocker.patch.object(reader, 'read') 
    manager.sub_method.return_value = 120 



class With_Reusable_Loop_TestCase(asynctest.TestCase):
    use_default_loop = True

    forbid_get_event_loop = False

    def test_read_message(self, monkeypatch):

        
