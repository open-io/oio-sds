##################################################################
#
# listener&reduce
#
#===============================================================================
# FORMAT of data on Reduce:go(..) function: JSON
#
# MANDATORY: "HEAD"/KEY name about config, iAND section "DATA"
# ----------
# "HEAD": {
#     "NAME": "action_nam"  -->  the name of proc source msg, define algo of reduce
#     "PID":                --> the pid of  proc src
#     "STATUS":             --> the status of proc src
#     "MSG_ID":             --> counter of msg to received, increase by one each time
#                              for each proc src
# }
# "DATAH": {
# <key/val>                 --> specific key/value for the "HEAD"/"NAME",
#                                data NOT reduce, but used for reduce "DATA" section
#                                     ---
# "DATA": {
# <key/ val>                --> specific key/value for the "HEAD"/"NAME",
#                                data to reduce
# }
#-------------------------------------------------------------------------------
# example:
#{ 
#	"HEAD": { 
#		"PID": 16181, 
#		"STATUS": 0, 
#		"MSG_ID": 19 
#	}, 
#   "DATAH": {
#		"PREFIX": "5C15", 
#		"M1_ID": "127.0.0.1:6002", 
#		"SVC_ID": "", 
#		"SVC_TYPE": ""
#	}
#	"DATAR": { 
#		"SVC_NB_CONTAINER_M2onM1": 0, 
#		"SVC_ERR_REQ_META1": 0, 
#		"M1_NB_PREFIX": 1, 
#		"M1_NB_CONTAINER": 1, 
#		"M1_ERR_BADBDDFILE": 0, 
#		"M1_ERR_BADPREFIX": 0, 
#		"M1_ERR_REQ_META1": 0 
#	} 
#}
#===============================================================================



##################################################################





import sys
import syslog, logging
from reducerBase import ReducerBase
from reduce.reducer_action_list_container_service import ReducerActionListContainerService
from reduce.reducer_action_test_service import ReducerActionTestService


##################################################################
# config
##################################################################


##################################################################
# MANDATORY key NAME, format JSON
##################################################################


##################################################################
# class Reduce
##################################################################
class Reducer:


##################################################################
	#init reduce 
	def __init__(self, bVerbose,  namespace, containerResult):
		self.reduce = {}
		self.bVerbose = bVerbose
		self.reduce[ReducerActionListContainerService.ACTION_NAME] = ReducerActionListContainerService(bVerbose, namespace, containerResult)
		self.reduce[ReducerActionTestService.ACTION_NAME]          = ReducerActionTestService(bVerbose)


	# get the good reducer with the name of the action source
	def getReducer(self, action_name):
		try:
			return self.reduce[action_name]
		except:
			logging.error(str(Reducer) + "error: undefined action_name ["+action_name+"]")
			syslog.syslog(syslog.LOG_ERR, str(Reducer) + "error: undefined action_name ["+action_name+"]")
			return None


##################################################################

	#return an array with the list of action name used with redcer
	def getListActionName(self):
		list = []
		for action in self.reduce:
			list.append(action)
		return list

	
	#for add an id crawl and or idsrc
	#if not add an id, pass ==>None
	def ids_add(self, action_name, idcrawl, idsrc):
		reduce = self.getReducer(action_name)
		if reduce != None:
			if idcrawl != None:
				reduce.manageAccess(ReducerBase.IDTYPE_CRAWL, ReducerBase.CMD_ADD, idcrawl)
			if idsrc != None:
				reduce.manageAccess(ReducerBase.IDTYPE_SRC,   ReducerBase.CMD_ADD, idsrc)
	
	#for remove an id crawl and or idsrc
	#if not rm an id, pass ==>None
	#if rm all,       pass ==> -1
	def ids_rm(self, action_name, idcrawl, idsrc):
		reduce = self.getReducer(action_name)
		if reduce != None:
			if idcrawl != None:
				reduce.manageAccess(ReducerBase.IDTYPE_CRAWL, ReducerBase.CMD_RM, idcrawl)
			if idsrc != None:
				reduce.manageAccess(ReducerBase.IDTYPE_SRC,   ReducerBase.CMD_RM, idsrc)


	# if id_crawl already present  return True, else False	
	def idcrawl_isExist(self, action_name, idcrawl):
		reduce = self.getReducer(action_name)
		if reduce != None:
			return reduce.manageAccess(ReducerBase.IDTYPE_CRAWL, ReducerBase.CMD_ISEXIST, idcrawl)
		return False
	
	# if no id_crawl added, return True, else False
	def idcrawl_isEmpty(self, action_name):
		reduce = self.getReducer(action_name)
		if reduce != None:
			return reduce.manageAccess(ReducerBase.IDTYPE_CRAWL, ReducerBase.CMD_ISEMPTY, None)
		return False

	# if no id_src added, return True, else False
	def idsrc_isEmpty(self, action_name):
		reduce = self.getReducer(action_name)
		if reduce != None:
			return reduce.manageAccess(ReducerBase.IDTYPE_SRC, ReducerBase.CMD_ISEMPTY, None)
		return False


	#itialize data structure about an specific action 
	def clear(self, action_name):
		#clean all data
		reduce = self.getReducer(action_name)
		if reduce != None:
			reduce.clearAll()

	# erase all data from all reducer
	def clearAll(self):
		for action_name in self.reduce:
			reduce = self.reduce[action_name]
			reduce.clearAll()



	#set the timeout value in seconds
	# if action_name == None: set all reducer
	def setTimeout(self, action_name, timeout):
		if action_name == None:
			for action in self.reduce:
				reduce = self.reduce[action]
				reduce.setTimeout(timeout)
		else:
			reduce = self.getReducer(action_name)
			if reduce != None:
				reduce.setTimeout(timeout)


	#return True if timeout was elapsed
	def isTimeout(self, action_name):
		bResult = False
		reduce = self.getReducer(action_name)
		if reduce != None:
			return reduce.manageTimeout(False)
		return bResult
		
	



	# reduce primary function
	# m_head_name: name of source

	# m_datah: data doesn't reduce
	# m_datar: data to reduce
	#}
	def run(self, action_name, m_datah, m_datar):
		bResult = False
		reduce = self.getReducer(action_name)
		if reduce != None:
			reduce.manageTimeout(True)
			reduce.reduce(m_datah, m_datar)
			bResult = True
		return bResult
		
		for tmp_action_name in self.reduce:
			reduce = self.reduce[tmp_action_name]
			if tmp_action_name == action_name:
				reduce.manageTimeout(True)
				reduce.reduce(m_datah, m_datar)
				bResult = True
			else:				
				reduce.manageTimeout(False)
		return bResult
	


	def finalize(self, action_name):
		reduce = self.getReducer(action_name)
		if reduce != None:
			reduce.finalize()


	# get result
	def dumps(self, action_name):
		reduce = self.getReducer(action_name)
		if reduce != None:
			return reduce.dumps()
		else:
			return ""




	



