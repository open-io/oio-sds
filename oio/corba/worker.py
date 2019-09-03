#/us/bin/env python

import oio.corba

if __name__ == '__main__':
    source = oio.corba.BeanstalkdSource("127.0.0.1:6005", "worker")
    sink = oio.corba.BeanstalkdSink()
    oio.corba.Worker(source, sink).run()
