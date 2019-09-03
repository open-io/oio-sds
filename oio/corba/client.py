#!/usr/bin/env python

from random import choice, shuffle
import oio.corba
from oio.corba.action import Randomizer
from oio.conscience.client import LbClient

if __name__ == '__main__':
    # Poll an available beanstalkd
    lb = LbClient({'namespace': 'OPENIO'})
    target = lb.poll('beanstalkd')
    target = 'beanstalk://' + target[0]['addr']
    # Push the RPC to it, the synchronous way
    client = oio.corba.ClientSync("127.0.0.1:6005")
    rc = client.execute(target, Randomizer())
    print repr(rc)
    # Let's try the same, the async way.
    # We submit 10 commands and wait them as a batch
    client = oio.corba.ClientAsync("127.0.0.1:6005")
    pending = list()
    for i in range(10):
        id_ = client.start(target, Randomizer())
        pending.append(id_)
    shuffle(pending)
    for id_ in pending:
        rc = client.join(id_)
        print repr(rc)

