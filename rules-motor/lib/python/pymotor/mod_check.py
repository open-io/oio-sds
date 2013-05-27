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

def check_storage_policy(content):
        print "Checking storage policy of content "+content.namespace+"/"+content.container_id+"/"+content.name
        ns_name = ctypes.c_char_p(content.namespace)
        cid = ctypes.c_char_p(content.container_id)
	cname = ctypes.c_char_p(content.name)
        lib = ctypes.cdll.LoadLibrary("librulesmotorpy2c.so")
        lib.motor_check_storage_policy(ns_name, cid, cname)
