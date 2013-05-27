# Copyright (C) 2013 AtoS Worldline
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
