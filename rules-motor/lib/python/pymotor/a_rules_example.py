"""Rules script demonstration
Available modules:
	pymotor.mod_general
	pymotor.mod_crawler"""

test = "test string"
# -------------------------------------------------------------------
# needed modules
# -------------------------------------------------------------------

import pymotor.mod_general as mod_general
import pymotor.mod_crawler as mod_crawler
import time

# -------------------------------------------------------------------
# type dispatcher
# -------------------------------------------------------------------

def main(raw_data, typeID):
	"""Single entrance of this script
	0	: reserved for meta0
	1	: reserved for meta1
	2	: reserved for meta2(meta2-crawler)
	3	: reserved for rawx(chunk-crawler)"""
	if typeID == 0:
		pass
	elif typeID == 1:
		pass
	elif typeID == 2:
		container = mod_crawler.Container(raw_data)
		container_rules(container)
	elif typeID == 3:
		print raw_data
		chunk = mod_crawler.Chunk(raw_data)
		chunk_rules(chunk)

# -------------------------------------------------------------------
# rules for the containers found in meta2 crawler
# -------------------------------------------------------------------

def container_rules(container):
	"""Rules for datas found by meta2-crawler"""
	if mod_general.do_it_between(0, 0):
		container.sqlite_pragma_check()
	pass
		

# -------------------------------------------------------------------
# rules for the chunks found in chunk crawler
# -------------------------------------------------------------------

def chunk_rules(chunk):
	"""Rules for datas found by chunk-crawler"""
	if mod_general.do_it_between(0, 0):
		if chunk.is_older_than(chunk.mtime, 3):
			chunk.verify_chunk_size()
			print chunk.content.creation_time
#			chunk.compress("ZLIB", 512000, 1)
#			chunk.decompress(1)
