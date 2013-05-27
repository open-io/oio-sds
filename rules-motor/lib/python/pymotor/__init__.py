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

"""python part of Dynamic Rules Engine"""
__name__='pymotor'

class Log4cStream(object):
	def __init__(self):
		self.buffer = ''
		self.lib = ctypes.cdll.LoadLibrary("librulesmotorpy2c.so")
	def write(self,msg):
		self.buffer = self.buffer + msg
		if '\n' in self.buffer:
			self.flush()
	def flush(self):
		self.lib.motor_log("grid.crawler", 1, self.buffer.replace("\n","\\n"))
		self.buffer = ''

import ctypes, logging, sys
sys.stdout = Log4cStream()

logging.basicConfig(format='%(message)s', level=logging.DEBUG, stream=Log4cStream())

