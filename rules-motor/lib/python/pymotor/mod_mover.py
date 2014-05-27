import ctypes
import pygrid.sqlx as sqlx
import os.path as ospath

def move_chunk(path):
	print "Moving chunk to another rawx"


def move_container(ns_name, cid):
	print "Moving container " + cid + " to another meta2"
	ns_name = ctypes.c_char_p(ns_name)
	cid = ctypes.c_char_p(cid)
	lib = ctypes.cdll.LoadLibrary("librulesmotorpy2c.so")
	rc = lib.motor_move_container(ns_name, cid)
	return bool(rc)

def move_sqlx(ns_name, sqlx_addr, path, cid, type):
	url=ospath.join(ns_name, cid);
	print "Moving sqlx database (" + url + "|" + type + ") to another sqlx"
	#rc = sqlx.move_base(url, type, None, True); # no delete src file, but a "699|'backup error: SQLITE_?'\n" appears
	rc = sqlx.move_base(url, type, None, True); # delete src file
	return bool(rc)



