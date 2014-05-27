##################################################################
#
# listener&reduce
#
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
#     "CRAWLER_ID":         --> id ducrawler identifiant le process de crawl
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
#
#
#
##################################################################



import sys, io, random
#import time
#import datetime
#import zmq
import syslog, logging
#from reduce.reducer import Reducer
from pygrid.client import GridStorageClient
from pygrid.utils import GridUrl
from pygrid.exceptions import _GridException, ContainerExists
#from optparse import OptionParser as OptionParser





##################################################################
# class Grid Acces
##################################################################
class ListenerGridAccess:
	#init
	def __init__(self, namespace):
		self.ns      = namespace
		self.client  = GridStorageClient(namespace, nocache=(not "off"))

	def seterr(self, msg):
		return __class__ + msg

	# create containers if does'nt exist
	#return error if an error occurs
	def create_container(self, containerName):
		error = ""
		self.containerName = self.ns + "/" + containerName
		url = GridUrl(self.ns + "/" + containerName)
		
		try:
			self.client.create_container(url.cid)			
		except ContainerExists:  #Container already exists
			pass              
		except _GridException as e:
			return "Failed to CREATE container ["+url.cid.name+"] : "+str(e)
		except:
			return "Failed to CREATE container ["+url.cid.name+"]: Unknown error"
		return ""


	#write a bloc to a ns/container/content
	#path=ns/containerName/contentName
	#stream = io.BytesIO(..)
	#return error if an error occurs
	def put_content(self, path, stream, size):
		if size <= 0:
			return "No put content besause size of stream = 0"
		
		url    = GridUrl(path)			
		#client = self.client.GridStorageClient(self.ns)
		
		try:
			self.client.put_content(url.cid, url.content_name, size, stream)
			
		except Exception as e:
			return "Failed to CREATE content [" + path + "] : "+str(e)
		except:
			return "Failed to CREATE content [" + path + "]: Unknown error"		
		return ""


	#read a bloc from ns/container/content
	#path=ns/containerName/contentName
	#stream = io.BytesIO(..)
	#return the buffer of content
	def get_content(self, path):
		url    = GridUrl(path)
		try:
			return self.client.get_content(url.cid, url.content_name)

		except Exception as e:
			msg = "Failed to GET content [" + path + "] : "+str(e)
			logging.error(msg)
			syslog.syslog(syslog.LOG_ERR, msg)

		except:
			msg = "Failed to GET content [" + path + "]: Unknown error"
			logging.error(msg)
			syslog.syslog(syslog.LOG_ERR, msg)	
		return ""



	#delete a content from ns/container/content
	#path=ns/containerName/contentName
	#return error if an error occurs
	def remove_content(self, path):
		url    = GridUrl(path)
		try:
			self.client.remove_content(url.cid, url.content_name)

		except Exception as e:
			return "Failed to DELETE content [" + path + "] : "+str(e)
		except:
			return "Failed to DELETE content [" + path + "]: Unknown error"
		return ""
	



##################################################################
# class Grid Acces
##################################################################
class ListenerTools:
	#write a file on local disk directory, NO on grid
	def write_file(self, fileName, contentName, texte):
		try:
			f = open(fileName, 'w')
			f.write(texte)
			f.close()
		except Exception as e:
			return "Failed to write file " + fileName + ": " + str(e)
		except:
			return "Failed to write file " + fileName + ": " + " Unknown error"
		return ""

	#stream : IOBase
	def getSizeStream(self, stream):
		stream.seek(0, 2) #SEEK_END
		size = stream.tell()
		stream.seek(0, 0) #SEEK_SET
		return size



