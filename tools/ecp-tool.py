#!/usr/bin/env python

from oio import ecp

def main():
    for algo in (ecp.algo_LIBERASURECODE_RS_VAND,
                 ecp.algo_JERASURE_RS_VAND,
                 ecp.algo_JERASURE_RS_CAUCHY,
                 ecp.algo_ISA_L_RS_VAND,
                 ecp.algo_ISA_L_RS_CAUCHY,
                 ecp.algo_SHSS,
                 ecp.algo_LIBPHAZR):
        try:
            f = ecp.encode(algo, 6, 3, "plop")
            print "OK", repr(f)
        except Exception as ex:
            print "ERROR", repr(ex)

if __name__ == '__main__':
    main()
