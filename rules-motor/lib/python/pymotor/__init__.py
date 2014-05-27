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

