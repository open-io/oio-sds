# Filename: compresion_func_mod.py

import ctypes

def compress_chunk(path, compressedsize, algo, bsize, preserve):
	if not compressedsize:
		chunk_path = ctypes.c_char_p(path)
		algo = ctypes.c_char_p(algo)
		bsize = ctypes.c_int(bsize)
		preserve = ctypes.c_int(preserve)
		lib = ctypes.cdll.LoadLibrary("librulesmotorpy2c.so")
		lib.motor_compress_chunk(chunk_path, algo, bsize, preserve)
	else:
		print "already compressed"


def decompress_chunk(path, compressedsize, preserve):
	if compressedsize:
		chunk_path = ctypes.c_char_p(path)
		preserve = ctypes.c_int(preserve)
		lib = ctypes.cdll.LoadLibrary("librulesmotorpy2c.so")
		lib.motor_decompress_chunk(chunk_path, preserve)
	else:
		print "already decompressed"
