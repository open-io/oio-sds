#!/usr/bin/env python

import eventlet
import traceback
from oio.ecp import ECDriver

def _concurrent_test():
    for i in range(10):
        print "concurent_function"

def print_result(fn, data):
        try:
            fragments = fn(data)
            #print "OK", len(fragments)
        except Exception as ex:
            traceback.print_exc()

def main():
    driver = ECDriver(ec_type="liberasurecode_rs_vand", k=6, m=3)
    pool = eventlet.GreenPool()
    data = "0" * 1024 * 1024
    for i in range(1024):
        pool.spawn(print_result, driver.encode, data)
    pool.waitall()

if __name__ == '__main__':
    main()
