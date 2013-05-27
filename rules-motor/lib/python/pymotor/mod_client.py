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

import ctypes

def delete_content(content):
	ns = ctypes.c_char_p(content.namespace)
	container_id = ctypes.c_char_p(content.container_id)
	content_name = ctypes.c_char_p(content.name)
	lib = ctypes.cdll.LoadLibrary("librulesmotorpy2c.so")
	lib.motor_delete_content(ns, container_id, content_name)
