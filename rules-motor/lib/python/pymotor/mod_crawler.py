"""Module dedicated to chunk-crawler"""

# -------------------------------------------------------------------
# import the modules
# -------------------------------------------------------------------

import ctypes, time
import os
import sqlite3

from urllib import unquote;

from pygrid.locate import ContainerLocator
from pygrid.utils import ContainerId, Metadata
from pygrid.asn1 import create_srvinfo
from pygrid.services import Meta2
from pygrid.gridd import make_gridd_from_addr

import 	pymotor.mod_compression as mod_compression
import 	pymotor.mod_general as mod_general
import  pymotor.mod_mover as mod_mover
import  pymotor.mod_client as mod_client
import  pymotor.mod_check as mod_check
from	pymotor.print_decor import PrintDecor

# -------------------------------------------------------------------
# Data structures 
# -------------------------------------------------------------------

class ContentTextInfoS(ctypes.Structure):
	"""C structure class: content_text_info_s"""
	_fields_ = [("container_id", ctypes.c_char_p),
			("path", ctypes.c_char_p),
			("size", ctypes.c_char_p),
			("chunk_nb", ctypes.c_char_p),
			("metadata", ctypes.c_char_p),
			("system_metadata", ctypes.c_char_p)]

class ChunkTextInfoS(ctypes.Structure):
	"""C structure class: chunk_text_info_s"""
	_fields_ = [("id", ctypes.c_char_p),
			("path", ctypes.c_char_p),
			("size", ctypes.c_char_p),
			("position", ctypes.c_char_p),
			("hash", ctypes.c_char_p),
			("metadata", ctypes.c_char_p),
			("container_id", ctypes.c_char_p)]

class CrawlerChunkDataPackS(ctypes.Structure):
	"""C structure class: crawler_chunk_data_pack_s"""
	_fields_ = [("content_info", ctypes.POINTER(ContentTextInfoS)),
			("chunk_info", ctypes.POINTER(ChunkTextInfoS)),
			("atime", ctypes.c_long),
			("ctime", ctypes.c_long),
			("mtime", ctypes.c_long),
			("chunk_path", ctypes.c_char_p)]


class Sqlx:
	"""Class Sqlx for sqlx-crawler datas
Defined members:
	namespace		: the namespace
	path            : path of the sqlx sqlite db file
	seq             : sequence of container
	cid             : container_id (hexa --> ascii)
	type            : type of bdd (ex: "sqlx.test")
	sqlx_url		: url of the sqlx service
	path			: path of the sqlx sqlite db file
	"""
	def __init__(self, raw_data):
		"""Initialize class Sqlx for sqlx-crawler datas"""
		self.namespace = raw_data['ns_name']
		self.path = raw_data['sqlx_path']
		self.seq = raw_data['sqlx_seq']
		self.cid = raw_data['sqlx_cid']
		self.type = raw_data['sqlx_type']
		self.sqlx_url = raw_data['sqlx_url']

	def migrate(self):
		print "Migrating sqlx database " + self.path + "|" + self.cid + "|" + self.type
		elttype=self.type.split(".")
		len_elttype=len(elttype)
		if (len_elttype>0):
			if (elttype[len_elttype-1]=="migrated"):
				raise Exception("sqlx basefile %s not valid bdd to migrate", self.path)
				
		if (mod_mover.move_sqlx(self.namespace, self.sqlx_url, self.path, self.cid, self.type)):
			os.rename(self.path, self.path + ".migrated")
			print "sqlx basefile ", self.path, " migrated and renamed"





class Container:
	"""Class Container for meta2-crawler datas
Defined members:
	namespace		: the namespace
	meta2_url		: url of the meta2 service
	id			: id of the container
	path			: path of the container sqlite db file
	conn			: a sqlite connection to the db
	"""
	def __init__(self, raw_data):
		"""Initialize class Container for container-crawler datas"""
		self.namespace = raw_data['ns_name']
		self.meta2_url = raw_data['meta2_url']
		self.id = raw_data['container_id']
		self.path = raw_data['container_path']
		try:
			self.conn = sqlite3.connect(self.path)
		except BaseException:
			print "Failed to open base at %s" % self.path
			raise

	def sqlite_pragma_check(self):
		cursor = self.conn.cursor()
		try:
			cursor.execute("""PRAGMA integrity_check""")
			for row in cursor:
				stat = "%s%s%s" % (PrintDecor.BACK_LIGHT_GREEN, row[0], PrintDecor.END)
				print "Container PRAGMA integrity check result: %s" % (stat)
		except:
			stat = stat = "%s%s%s" % (PrintDecor.BACK_RED, "nok", PrintDecor.END)
			print "Container PRAGMA integrity check result: %s" % (stat)
			os.rename(self.path, self.path + ".corrupted")
			print "Container has been renamed to %s.corrupted" % (self.path)

		self.conn.commit()
		cursor.close()
		pass

	def sqlite_vacuum(self):
		cursor = self.conn.cursor()
		cursor.execute("""VACUUM""")
		for row in cursor:
			print row
		self.conn.commit()
		cursor.close()
		pass

	def locate(self):
		containerLoc = ContainerLocator()
		srv, = containerLoc.locate(self.namespace, ContainerId(hexa=self.id))
		return create_srvinfo(self.namespace, 'meta2', srv)

	def migrate(self):
		print "Migrating container ", self.path
		if mod_mover.move_container(self.namespace, self.id):
			os.rename(self.path, self.path + ".migrated")
			print "Container", self.path, "migrated and renamed"


class Content:
	"""Class Content for C structure content_textinfoi
Defined members:
	chunk_number 	: the number of chunks that the content has
	size		: size of the content
	container_id	: id of the container which contains the content
	name		: name of the content
	system_metadata : some system metadata of the content
	metadata	: some metadata of the content
	chunk_method 	: chunk method
	mime_type	: the mime type
	creation_time	: the ctime of a content
	"""
	def __init__(self, raw_data):
		"""Initialize Content for C structure content_textinfo"""
		self.namespace = raw_data['ns_name']
		self.chunk_number = raw_data['content_info']['chunk_nb']
		self.size = raw_data['content_info']['content_size']
		self.container_id = raw_data['content_info']['container_id']
		self.name = raw_data['content_info']['path']
		self.metadata = None
		self.mime_type = None
		self.creation_time = None
		self.chunk_method = None
		if 'system_metadata' in raw_data['content_info']:
			if not raw_data['content_info']['system_metadata'] is None:
				subsysmeta = parse_metadata(raw_data['content_info']['system_metadata'])
				if 'chunk-method' in subsysmeta:
					self.chunk_method = subsysmeta['chunk-method']
				if 'mime-type' in subsysmeta:
					self.mime_type = subsysmeta['mime-type']
				if 'creation-date' in subsysmeta:
					self.creation_time = float(subsysmeta['creation-date'])
		if 'metadata' in raw_data['content_info']:
			if not raw_data['content_info']['metadata'] is None:
				m = raw_data['content_info']['metadata']
				m = unquote(m)
				self.metadata = parse_metadata(m)

	def delete(self):
		"""Delete content"""
		mod_client.delete_content(self)

	def set_storage_policy(self, policy):
		"""Change the storage_policy of a content"""
		cid = ContainerId(hexa=self.container_id)
		containerLoc = ContainerLocator()
		addr, = containerLoc.locate(self.namespace, cid)
		meta2 = Meta2(self.namespace, make_gridd_from_addr(addr))
		content_stat, = list(meta2.stat_content_v2(cid, self.name))
		sys_metadata = Metadata(content_stat.get_metadata_system())
		if sys_metadata.getValue("storage-policy") is not policy:
			sys_metadata.add("storage-policy", policy)
			meta2.modify_content_sysmetadata(cid, self.name, sys_metadata)

	def check_storage_policy(self):
		"""Check content is really stored as defined by his storage_plicy"""
		mod_check.check_storage_policy(self)

class Chunk:
	"""Class Chunk for chunk-crawler datas
Defined members:
	namespace		: the namespace
	atime			: chunk access time
	ctime			: chunk create time
	mtime			: chunk modified time
	id			: chunk id
	hash			: chunk hash
	path			: chunk path
	container_id		: id of the container which contains the chunk
	compression		: metadata about compression of the chunk
	size			: chunk size
	compressedsize		: chunk size after have been compressed
	position		: position of the chunk in the content
	last_scanned_time	: a time stamp marks last scanned time of the motor
	metadata		: metadata of a chunk
	content			: the content which contains the chunk"""
	def __init__(self, raw_data):
		"""Initialize class Chunk for chunk-crawler datas"""
		self.namespace = raw_data['ns_name']
		self.atime = raw_data['atime']
		self.ctime = raw_data['ctime']
		self.mtime = raw_data['mtime']
		self.content = Content(raw_data)

		self.id = raw_data['chunk_info']['id']
		self.hash = raw_data['chunk_info']['hash']
		self.path = raw_data['chunk_path']
		self.container_id = raw_data['chunk_info']['container_id']
		self.compression = raw_data['chunk_info']['metadatacompress']
		self.compressedsize = raw_data['chunk_info']['compressedsize']
		self.position = raw_data['chunk_info']['position']
		self.size = raw_data['chunk_info']['size']
		self.metadata = raw_data['chunk_info']['metadata']
	
	
	def compress(self, algo, bsize, preserve):
		"""High-level compression, takes 4 arguments.
	algo	 : a string as arguments which specifies the compression algorithm to be used
		   it should be either LZO or ZLIB
	bsize	 : the block size of compression
	preserve : 1 preserve the mtime, 0 doesn't

example:
	chunk.compress("LZO", 512000, 1)
	This will compress the data by the algorithm LZO with a compression block size 512000KB
	and preserve the original mtime.
	
	chunk.compress("ZLIB", 256000, 0)
	This will compress the data by the algorithm ZLIB with a compression block size 256000KB
	and the mtime will be updated."""
	
		mod_compression.compress_chunk(self.path, self.compressedsize, algo, bsize, preserve)


	def decompress(self, preserve):
		"""High-level decompression, takes 2 arguments.
	preserve : 1 preserve the mtime, 0 doesn't
		
example:
	chunk.decompress(1)
	This will decompress the data while its original mtime is preserved.
	
	chunk.decompress(0)
	This will decompress the data and update its mtime."""

		mod_compression.decompress_chunk(self.path, self.compressedsize, preserve)


	def verify_chunk_size(self):
		"""Verify the chunk integrity by size, takes one argument
	
example:
	chunk.verify_chunk_size()
	If size is correct, True will be returned otherwise False is returned."""
		try:
			chunk_size = os.path.getsize(self.path)
		except OSError:
			print "Failed to get the chunk_size"
			return None
		if self.compressedsize:
			if chunk_size == int(self.compressedsize):
				print "chunk_size is correct!"
				return True
			else:
				print "Size not correct, this will be handled"
				return False
		else:
			if chunk_size == int(self.size):
				print "chunk_size is correct!"
				return True
			else:
				print "Size not correct, this will be handled"
				return False

	def is_older_than(self, time_to_compare, days):
		"""If the passed time argument is older than x days from now,
return True, otherwise False"""
		return mod_general.is_older_than(time_to_compare, days)

	def is_younger_than(self, time_to_compare, days):
		"""If the passed time argument is older than x days from now,
return True, otherwise False"""
		return mod_general.is_younger_than(time_to_compare, days)

# -------------------------------------------------------------------
# Auxiliary functions
# -------------------------------------------------------------------

# Parse system metadata
def parse_metadata(orig):
	result = dict()
	for kv in orig.split(';',-1):
		if not kv:
			continue
		k,sep,v = kv.partition('=')
		if sep is None or not sep:
			sep, v = '', ''
		k = k.strip(' \'"')
		v = v.strip(' \'"')
		result[k] = v
	return result

# Transfer the Python datablock to C struct
def datablock2cstruct(datablock):
	"""convert a chunk_crawler datablock from python diction to c structure"""
	content_info = ContentTextInfoS(datablock['content_info']['container_id'],
							datablock['content_info']['path'],
							datablock['content_info']['content_size'],
							datablock['content_info']['chunk_nb'],
							datablock['content_info']['metadata'],
							datablock['content_info']['system_metadata'])
	chunk_info = ChunkTextInfoS(datablock['chunk_info']['id'],
					datablock['chunk_info']['path'],
					datablock['chunk_info']['size'],
					datablock['chunk_info']['position'],
					datablock['chunk_info']['hash'],
					datablock['chunk_info']['metadata'],
					datablock['chunk_info']['container_id'])
	content_info = ctypes.pointer(content_info)
	chunk_info = ctypes.pointer(chunk_info)
	c_datablock = CrawlerChunkDataPackS(content_info, chunk_info, datablock['atime'], datablock['ctime'], datablock['mtime'], datablock['chunk_path'])
	c_datablock = ctypes.pointer(c_datablock)
	return c_datablock
	

# a test function for c libs
def struct_test(datablock):
	"""just a test function"""
	c_struct = datablock2cstruct(datablock)
	lib = ctypes.cdll.LoadLibrary("librulesmotorpy2c.so")
	lib.content_info_test(c_struct)


# verify the hash of a chunk
#def verify_chunk_hash(datablock):
#	"""verify the chunk integrity by hash"""
#	try:
#		f = open(datablock['chunk_path'])
#	except IOError:
#		print "verify_chunk_hash: can't open the file"
#		return None
#	sha256 = hashlib.sha256()
#	buf_size = 2**10
#	while True:
#		data = f.read(buf_size)
#		if not data:
#			break
#		sha256.update(data)
#	print sha256.hexdigest()
