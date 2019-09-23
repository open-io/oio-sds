#!/usr/bin/env python

from random import choice, shuffle
import oio.xcute
from oio.xcute.action import Randomizer, Iterator, BlobMover
from oio.conscience.client import LbClient

if __name__ == '__main__':
    # Poll an available beanstalkd
    config = {'namespace': 'OPENIO'}
    lb = LbClient(config)
    target = lb.poll('beanstalkd')
    target = 'beanstalk://' + target[0]['addr']
    # Iteration request
    client = oio.xcute.Stream("127.0.0.1:6005")
    id_ = client.kick(target, BlobMover('OPENIO', '127.0.0.1:6010', None))
    print repr(id_)
    for item in iter(client):
        print repr(item)
    #   id_ = client.kick(target, Iterator(0, 10))
    #   for item in iter(client):
    #       print item
    #   # Single synchronous request
    #   client = oio.xcute.ClientSync("127.0.0.1:6005")
    #   rc = client.execute(target, Randomizer())
    #   print repr(rc)
    #   # Let's try the same, the async way.
    #   # We submit 10 commands and wait them as a batch
    #   client = oio.xcute.ClientAsync("127.0.0.1:6005")
    #   pending = list()
    #   for i in range(10):
    #       id_ = client.start(target, Randomizer())
    #       pending.append(id_)
    #   shuffle(pending)
    #   for id_ in pending:
    #       rc = client.join(id_)
    #       print repr(rc)
