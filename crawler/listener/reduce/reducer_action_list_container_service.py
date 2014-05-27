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
from reduce.reducerBase import ReducerBase




##################################################################
# config
##################################################################



##################################################################
##################################################################
# class Reduce / action_list_container_service
#
#---------------------------------------
#	ReWrite this class for update with your specific reduce data
#---------------------------------------
#
##################################################################
##################################################################
class ReducerActionListContainerService(ReducerBase):

	ACTION_NAME = "action_list_container"

	#head of data to reduce
	JSON_KEYNAME_ACTLSTCTSVC_HEAD_PREFIX  = "PREFIX"
	JSON_KEYNAME_ACTLSTCTSVC_HEAD_M1ID    = "M1_ID"
	JSON_KEYNAME_ACTLSTCTSVC_HEAD_SVCID   = "SVC_ID"
	JSON_KEYNAME_ACTLSTCTSVC_HEAD_SVCTYPE = "SVC_TYPE"

	JSON_KEYNAME_ACTLSTCTSVC_LISTCONTAINER = "LISTCONTAINER"

	COLLDATA_KEYNAME_HEAD = "HEAD"

		
	#MANDATORY function
	def __init__(self, bVerbose, namespace, containerResult):
		self.namespace       = namespace
		self.containerResult = containerResult
		ReducerBase.__init__(self, self.ACTION_NAME, bVerbose)


	def buildHEAD(self, bBuildM1HHeaderElseSvcHeader, m1url, svcid, svctype): 
		head = {}
		if bBuildM1HHeaderElseSvcHeader == False:
			head[self.JSON_KEYNAME_ACTLSTCTSVC_HEAD_SVCID]  = svcid
			head[self.JSON_KEYNAME_ACTLSTCTSVC_HEAD_SVCTYPE] = svctype
		else:
			head[self.JSON_KEYNAME_ACTLSTCTSVC_HEAD_M1ID]   = m1url
		return head






	#MANDATORY function
	def reduce(self, datah, datar):
		#get header field
		prefix = datah[self.JSON_KEYNAME_ACTLSTCTSVC_HEAD_PREFIX]
		m1url  = datah[self.JSON_KEYNAME_ACTLSTCTSVC_HEAD_M1ID]
		svcid  = datah[self.JSON_KEYNAME_ACTLSTCTSVC_HEAD_SVCID]
		svctype= datah[self.JSON_KEYNAME_ACTLSTCTSVC_HEAD_SVCTYPE]

		#ibuild id [svcID/svcTYPE] for collecter_data		
		id = svctype + "_" + svcid
		
		#select or create collecter for this service
		colldata = {}
		if self.collecter_data.has_key(id):
			colldata = self.collecter_data[id]
		else:
			if id != "_":
				head = self.buildHEAD(False, m1url, svcid, svctype)
				self.collecter_data[id] = {}			
				colldata = self.collecter_data[id]
				colldata[self.COLLDATA_KEYNAME_HEAD] = head
	
		#select or create collecter for META1 service
		idM1 = "META1_" + m1url
		colldataM1 = {}
		if self.collecter_data.has_key(idM1):
			colldataM1 = self.collecter_data[idM1]
		else:
			head = self.buildHEAD(True, m1url, svcid, svctype)
			self.collecter_data[idM1] = {}
			colldataM1 = self.collecter_data[idM1]
			colldataM1[self.COLLDATA_KEYNAME_HEAD] = head
		
		
		#reduce
		#colldata = getCollecterData(m1url, svctype, svcid, collecter_data)
		for key in datar:
			if key == self.JSON_KEYNAME_ACTLSTCTSVC_LISTCONTAINER:
				if id != "_":
					self.aggregate_CONCAT(colldata, key, datar[key], "|")
					self.printmsg("[" + str(id) + "] key, value: [" + key + "]=[" + str(colldata[key]) + "]")
				else:
					self.aggregate_CONCAT(colldataM1, key, datar[key], "|")
					self.printmsg("[" + str(id) + "] key, value: [" + key + "]=[" + str(colldataM1[key]) + "]")
			elif key[:4] == "SVC_":
				if id != "_":
					self.aggregate_SUM(colldata, key, datar[key])
					self.printmsg("[" + str(id) + "] key, value: [" + key + "]=[" + str(colldata[key]) + "]")
			elif key[:3] == "M1_":
				self.aggregate_SUM(colldataM1, key, datar[key])
				self.printmsg("HEAD[" + str(id) + "] key, value: [" + key + "]=[" + str(colldataM1[key]) + "]")

			

	# concatate the container list on content / meta1
	def finalize(self):
		for id in self.collecter_data:
			# list [key, val] / services
			colldata = self.collecter_data[id]
			for key in colldata: 
				if key == self.JSON_KEYNAME_ACTLSTCTSVC_LISTCONTAINER:
					contents = colldata[key]					
					list = contents.split("|")					
					destcontent = []
					
					#search all different final content
					for c in list:
						s,i,f = c.rpartition('_')
						if f != "":
							if s not in destcontent:
								destcontent.append(s)					
					
					#search all content for each destination content		
					listToConcat = []
					for d in destcontent:
						for c in list:
							s,i,f=c.rpartition("_")
							if f != "":
								if d == s:
									listToConcat.append(c)
						self.grid_content_CONCATandRemove(self.namespace,  self.containerResult, listToConcat, d)
										
					#save all destination content
					colldata[key] = ""
					for d in destcontent:
						self.aggregate_CONCAT(colldata, key, d, "|")

	





	def dumps(self):
		resultm1 = ""
		resultsvc = "" 
		result = "";
		for id in self.collecter_data:
			# list [key, val] / services
			colldata = self.collecter_data[id]
			result = "";
			
			#manage self.COLLDATA_KEYNAME_HEAD key first
			collhead = colldata.get(self.COLLDATA_KEYNAME_HEAD, {});
			result += "\n{ "
			for keyh in collhead:
				result += keyh + "=" + collhead[keyh] + "  "
			result += " }:\n"
			
			#manage other key after
			for key in colldata:
				if key != self.COLLDATA_KEYNAME_HEAD:
					result += "    " + key + " = " + str(colldata[key]) + "\n"
			
			#meta1 in first to manage, svc after...
			if id[:6] == "META1_":
				resultm1 += result;
			else:
				resultsvc += result;

		result = resultm1 + resultsvc
		
		return result				
		



