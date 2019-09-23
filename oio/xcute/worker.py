#/us/bin/env python

from oio import xcute

def source_factory(url):
    return xcute.BeanstalkdSource(url, "worker")

if __name__ == '__main__':
    sink = xcute.BeanstalkdSink()
    xcute.Worker("127.0.0.1:6005", source_factory, sink).run()
