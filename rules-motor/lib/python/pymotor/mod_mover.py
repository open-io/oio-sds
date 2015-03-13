import ctypes
import pygrid.sqlx as sqlx
import os.path as ospath

def move_chunk(path):
	print "Moving chunk to another rawx"
	return False

def move_container(ns_name, cid):
	print "Moving container " + cid + " to another meta2 : not implemented"
	return False

def move_sqlx(ns_name, sqlx_addr, path, cid, type):
	url=ospath.join(ns_name, cid);
	print "Moving sqlx database (" + url + "|" + type + ") to another sqlx"
	#rc = sqlx.move_base(url, type, None, True); # no delete src file, but a "699|'backup error: SQLITE_?'\n" appears
	rc = sqlx.move_base(url, type, None, True); # delete src file
	return bool(rc)



