##################################################################
#
# listener&reduce
# base class for specific reduceer
#
##################################################################


import sys, io
import time
import syslog, logging
from reduce.tools import ListenerGridAccess, ListenerTools


##################################################################
# config
##################################################################



##################################################################
# MANDATORY key NAME, format JSON
##################################################################



##################################################################
# class ReducerBase
##################################################################
class ReducerBase:

	ACTION_NAME = "default action"

	# init based
	def __init__(self, action_name, bVerbose):
		self.name                = action_name
		self.bVerbose            = bVerbose
		self.collecter_data      = {}	# data reduced or not	
		self.collecter_crawlerid = []   # id of crawl
		self.collecter_sourceid  = []   # id of generator data to reduced or not
		self.lastTimeOfReceivedData = 0.0  # last time of data arrived, for timeout management
		self.timeout             = 0
		self.printmsg(" Initialized")
	

	#return the good list with the idtype. =None if unknown 
	def getID(self, idtype):
		return {
			self.IDTYPE_CRAWL: self.collecter_crawlerid,
			self.IDTYPE_SRC:   self.collecter_sourceid,
			}.get(idtype, None)

##################################################################
    #MANDATORY function
	#get the name of current action (define in class hierited of this
	#return the action_name
	def getName(self):
		return self.name

	#MANDATOREY function
	#clear data reduced
	def clearAll(self):
		self.collecter_data.clear()
		self.manageAccess(self.IDTYPE_CRAWL, self.CMD_RM, -1)
		self.manageAccess(self.IDTYPE_SRC,   self.CMD_RM, -1) 
		self.manageTimeout(True)

	#show debug trace
	def printmsg(self, msg):		
		if self.bVerbose == True:
			print self.ACTION_NAME + ": " + msg
	

##################################################################
	#setTimeOut in seconds, end of reduce...
	def setTimeout(self, timeout_value):
		self.timeout = timeout_value
		self.manageTimeout(True)


	# if bClear == True, set a new value for time, 
	#                   no test timeout
	#           ==False verify timeout
	# return True if Time out elapsed, or if data cleared
	# else return False
	def manageTimeout(self, bClear):
		if bClear == True:
			#reinitialize the timeout timer
			self.lastTimeOfReceivedData = time.time()
			return True
		else:
			# test the timeout timer
			delta = time.time() - self.lastTimeOfReceivedData
			#print "delta=" + str(delta)  + " " + "time.time()=" +  str(time.time()) + " " + "self.lastTimeOfReceivedData=" + str(self.lastTimeOfReceivedData) + " " + "self.timeout=" + str(self.timeout) + " " 
			if delta >= self.timeout:
				self.lastTimeOfReceivedData = time.time()
				return True
			else:
				return False
		
	
##################################################################

	IDTYPE_CRAWL = 1
	IDTYPE_SRC   = 2
	
	CMD_ADD     = 1
	CMD_RM      = 2
	CMD_ISEXIST = 4
	CMD_ISEMPTY = 5
	#idtype: <== IDTYPE_*
	#cmd:    <== CMD_*
	def manageAccess(self, idtype, cmd, id):
		list = self.getID(idtype)
		if list == None:
			return False
		
		if   cmd == self.CMD_ADD:
			if self.manageAccess(idtype, self.CMD_ISEXIST, id) == False:
				list.append(id)

		elif cmd == self.CMD_RM:
			try:
				if id == -1:
					#remove all
					while len(list) > 0 :
						list.pop()
				else:
					list.remove(id)
				
			except:
				logging.debug("none item to remove on list")

		elif cmd == self.CMD_ISEXIST:
			try:
				i = list.index(id)
				return True
			except:
				return False

		elif cmd == self.CMD_ISEMPTY: 
			if len(list) == 0:
				return True
			return False

		else:
			return False
		return True

##################################################################

	#aggregation of result
	#aggregate e value. 
	# SUM the value with previous receuved value
	def aggregate_SUM(self, coll, key, val):
		if coll.has_key(key):
			coll[key] += val
		else:
			coll[key] = val

    #aggregation of result
    #aggregate e value.
    # COUNT the numbre of key appears
	def aggregate_COUNT(self, coll, keyToSave, keyToCount):
		if coll.has_key(keyToSave):
			coll[keyToSave] += 1 
		else:
			coll[keyToSave] = 0

	#aggregation of result
	#aggregate e value.
	# CONCAT value of key if different 
	def aggregate_CONCAT(self, coll, key, val, separator):
		if coll.has_key(key):
			if val not in coll[key]:
				if coll[key] == "":
					coll[key] = val
				else:
					coll[key] += separator + val
		else:
			coll[key] = val

	
	def grid_content_CONCATandRemove(self, namespace, container, listcontentSrc, contentDest):
		grid = ListenerGridAccess(namespace)	
		tool = ListenerTools()	
		listToRemove = []
		buffer = ""
		for content in listcontentSrc:
			path = namespace + "/" + container + "/" + content
			b = grid.get_content(path);
			if b != "":
				self.printmsg("Read content " +  content)
				buffer += b + "\n"
				listToRemove.append(path)
		
		self.printmsg("Create content " + contentDest)
		stream    = io.BytesIO(buffer.encode("utf-8"))
		size      = tool.getSizeStream(stream)
		grid.put_content(namespace + "/" + container + "/" + contentDest, stream, size)
	
		for path in listToRemove:	
			self.printmsg("Remove temp content " + path)
			grid.remove_content(path)


##################################################################
		

	#MANDATORY function, 
	# when call, reduce all datar on collecter_data, with datah for choose
	def reducer(self, datah, datar, collecter_data):
		self.printmsg( " reducer()  Not implemented")

	def finalize(self):
		self.printmsg( " finalize()  Not implemented")

	#MANDATORY function, 
	#when call, convert the structure collecter_data on string and return it
	def dumps(self, collecter_data):
		self.printmsg( " dumps()  Not implemented")
			


