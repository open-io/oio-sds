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
import time
import datetime
import zmq
import syslog, logging, logging.handlers
from reduce.tools import ListenerGridAccess, ListenerTools
from reduce.reducer import Reducer
from optparse import OptionParser as OptionParser

#comment this line for dont show the debug information



################################################################################
# configuration of listener
################################################################################
LST_NAMESVC         = "listener" 
LST_MSGIN_TIMEOUT   = 30000                              # timeout in millisecond
LST_SERVER_ENDPOINT = "127.0.0.1:6150"
LISTENER_RESULT_CONTAINER_NAME = "__ListenerResult__"
LISTENER_RESULT_DIRTMP_NAME    = "/tmp"



################################################################################
# class LISTENER
################################################################################
class Listener:

	#JSON format/constant
	# MANDATORY key NAME, format JSON
	JSON_KEYNAME_HEAD          = "HEAD"
	JSON_KEYNAME_HEAD_NAME     = "SRC_NAME"
	JSON_KEYNAME_HEAD_PID      = "SRC_ID"
	JSON_KEYNAME_HEAD_STATUS   = "STATUS"
	JSON_KEYNAME_HEAD_MSGID    = "MSG_ID"
	JSON_KEYNAME_HEAD_CRAWLERID= "CRAWL_ID"
	JSON_KEYNAME_DATAH         = "DATAH"
	JSON_KEYNAME_DATAR         = "DATAR"

	# specific data about previous header field
	JSON_KEYNAME_HEAD_STATUS_setcrawlerid = "setcrawlerid"
	JSON_KEYNAME_HEAD_STATUS_stopact      = "stopact"
	JSON_KEYNAME_HEAD_STATUS_data         = ""	


	#init queue
	def __init__(self, url, bVerbose, namespace, containerName):
		self.ns      = namespace
		self.containerName = containerName
		
		#init all sub-class
		self.r       = Reducer(bVerbose, namespace, containerName)
		self.logInfo(self.dumpListActionName())
		self.grid    = ListenerGridAccess(namespace)
		self.tool    = ListenerTools()
		self.context = zmq.Context()
		
		#init ZMQ
		self.sock	 = self.context.socket(zmq.PULL)
		self.r.setTimeout(None, LST_MSGIN_TIMEOUT / 1000)
		surl = "tcp://" + url
		self.sock.bind(surl)
		


	#descruct and close queue
	def __del__(self):
		self.context.term()


	def Initialize(self):
		self.r.clearAll()
		error = self.grid.create_container(self.containerName)
		if error != "": 
			self.syslogErr(error)
			return False
		else:
			self.syslogInfo("Container [" + self.containerName  + "] for storage Listener&reduce result is created or already exists")
		return True
				

	def dumpListActionName(self):
		list = self.r.getListActionName()
		d = "Reducer actions used: "
		for action in list:
			d += "\n\t" + action
		return d

	def logdebug(self, msg):
		logging.debug("%s: %s", LST_NAMESVC, msg)

	# logging info...
	def logInfo(self, msg):
		logging.info("%s: %s", LST_NAMESVC, msg)

	def syslogInfo(self, msg):
		self.logInfo(msg)
		syslog.syslog(syslog.LOG_INFO, LST_NAMESVC + ": " + msg)

	# logging error
	def syslogErr(self, msg):
		#print "%s: %s", LST_NAMESVC, msg
		logging.error("%s: %s", LST_NAMESVC, msg)
		syslog.syslog(syslog.LOG_ERR, LST_NAMESVC + ": " + msg)
	

	#build content with result of reducer
	def buildContent(self, sdatetime, result):
		content = "Reduce end date/time: " + sdatetime + " on namespace " + self.ns + "\n"
		content += "\n"
		content += result
		return content
		

	# end process, end reduce
	def endprocess(self, action_name):
		if action_name == "": return False
		try:			
			#finalyze reduce process
			result      = self.r.finalize(action_name)
			
			#get result string			
			result      = self.r.dumps(action_name)
			print "-------------------------------------------------------------"			
			print result
		except Exception as e:
			self.syslogErr("Reduce error :" + str(e))
			return False;
		except:
			self.syslogErr("Unknown Reduce Error :")
			return False;		
	
		if result == "": return False

		# date/heure courante	
		datetimecrt = datetime.datetime.now()
	
		#convet ti to write on content
		sdatetime = datetimecrt.strftime("%02d/%02m/%04Y %02H:%02M:%02S")
		content   = self.buildContent(sdatetime, result)
		stream    = io.BytesIO(content.encode("utf-8"))
		size      = self.tool.getSizeStream(stream)
		
		#build name for new content
		sdatetime   = datetimecrt.strftime("%04Y%02m%02d%02H%02M%02S")
		contentName = sdatetime + "-" + action_name + "-Reduce"
		path        = self.ns + "/" + LISTENER_RESULT_CONTAINER_NAME + "/" + str(contentName)
		
		#write new content on specfoc container
		error = self.grid.put_content(path, stream, size)
		if error != "":			
			fileName=LISTENER_RESULT_DIRTMP_NAME + "/" + contentName
			errorF = self.tool.write_file(fileName, path, result)
			if errorF != "":
				msg = "Reduce result: " + error + " - " + errorF
				self.syslogErr(msg)
			else:
				msg = "Reduce result: " + error + " - Result write on temporarily file [" + fileName + "]"
				self.syslogErr(msg)		
		else:
			msg = "Reduce Result write on content [" + path  + "] with success"
			self.syslogInfo(msg)							
		
		#clear all data and statistique
		self.r.clear(action_name)
		return True;


	#analysed recv message aznd execute it
	#return True if all action are terminated
	def ManageProcess(self, result):
		#extract header of message
		m_head  = result[self.JSON_KEYNAME_HEAD]
		m_head_name      = m_head[self.JSON_KEYNAME_HEAD_NAME]
		m_head_pid       = m_head[self.JSON_KEYNAME_HEAD_PID]
		m_head_status    = m_head[self.JSON_KEYNAME_HEAD_STATUS]
		m_head_msgid     = m_head[self.JSON_KEYNAME_HEAD_MSGID]
		m_head_crawlerid = m_head[self.JSON_KEYNAME_HEAD_CRAWLERID]
		
		#self.logInfo("msg received")

		bResult = False

		#test name of source of message
		if m_head_status != self.JSON_KEYNAME_HEAD_STATUS_data:
			#command to execute
			#save new id to manage autorized message
			if m_head_status == self.JSON_KEYNAME_HEAD_STATUS_setcrawlerid:
				self.logInfo("Message received: command " 
								+ self.JSON_KEYNAME_HEAD_STATUS_setcrawlerid 
								+ "id=" + m_head_crawlerid)
				self.r.ids_add(m_head_name, m_head_crawlerid, None)
			
			#stop process about specific pid generate message data to reduce
			elif m_head_status == self.JSON_KEYNAME_HEAD_STATUS_stopact:
				self.logInfo("end src process pid = " + str(m_head_pid)  + " was received")
				self.r.ids_rm(m_head_name, m_head_crawlerid, m_head_pid)
				
				#verif if allaction are terminated, if True: return True
				if self.r.idcrawl_isEmpty(m_head_name) == True:
					if self.r.idsrc_isEmpty(m_head_name) == True:
						self.logInfo("All src process was received: end reduce")					
						self.endprocess(m_head_name)
						bResult = True;
		
		else:			
			#verif if crawlerid are autorised to reduce data or not: here
			if self.r.idcrawl_isExist(m_head_name, m_head_crawlerid) == False:
				return False

			#execute reduce action
			m_datah = result[self.JSON_KEYNAME_DATAH]
			m_datar = result[self.JSON_KEYNAME_DATAR]
			self.logdebug('listener: recv : [' + str(result) + ']')
			sys.stdout.flush()
			try:
				if self.r.run(m_head_name, m_datah, m_datar) == True:
					# add source of message for manage terminated action
					self.r.ids_add(m_head_name, None, m_head_pid)
				else:
					self.syslogErr("Reduce error : bad [HEAD]/[NAME]=\""+ m_head_name +"\"")				
			except Exception as e:
				self.syslogErr("Reduce error :" + str(e))
			except:
				self.syslogErr("Unknown Reduce Error :")
		
		# timeout management for the others reducers
		self.ManageTimeout(m_head_name)
	
		return bResult


	# browse all educer for test timeout, excepted action_name_excepted
	# action_name_excepted = None: all reducer
	def	ManageTimeout(self, action_name_excepted):
		list_action_name = self.r.getListActionName()
		for action_name in list_action_name:
			if action_name_excepted != action_name:
				if self.r.idcrawl_isEmpty(action_name) == False:
					if self.r.isTimeout(action_name) == True:
						self.logInfo("Listener: timeout action [" + action_name + "]")		
						self.endprocess(action_name)


	# listener function
	def go(self, timeout):
		poll = zmq.Poller()
		poll.register(self.sock, zmq.POLLIN)
		
		self.logInfo("Waiting for incomming message to reduce...")
		
		while True:
			s = dict(poll.poll(timeout))
			if s.get(self.sock) == zmq.POLLIN:
				# get JSON format message
				try:
					result= self.sock.recv_json()
				except Exception as e:
					self.syslogErr("error :" + str(e))
					continue
				except:
					self.syslogErr("Unknown Error :")
					continue
			
				self.ManageProcess(result)
			
			else:
				self.ManageTimeout(None)
		
		self.logdebug("End listening!")
		





################################################################################
def usage(args):
	print 'Usage: ', args[0], "[option(s)] --listener_url=<addIP>:<port> <NS>"
	print ''
	print 'Option(s):'
	print '		-v, --verbose: 		Triggers debugging traces'
	print '     -l, --listenerurl:	listener URL=<addIP>:<port>'
	print ''		
	sys.exit(1)

def main():
	parser = OptionParser()
	parser.add_option('-v', '--verbose', action="store_true", dest="flag_verbose", help='Triggers debugging traces')
	parser.add_option('-l', '--listenerurl', action="store", type="string", dest="listener_url", help='listener URL=<addIP>:<port>')


	(options, args) = parser.parse_args(sys.argv)

	
	# Logging configuration
	g_bverbose = False
	if options.flag_verbose:
		g_bverbose = True
		logging.basicConfig(format='%(asctime)s %(message)s',
							datefmt='%m/%d/%Y %I:%M:%S',
							level=logging.DEBUG)
	else:
		logging.basicConfig(format='%(asctime)s %(message)s',
							datefmt='%m/%d/%Y %I:%M:%S',
							level=logging.INFO)
	
    #save listener URL
	listenerUrl = LST_SERVER_ENDPOINT
	if options.listener_url:	
		listenerUrl = options.listener_url
	logging.info("listenerURL=["+listenerUrl+"]")

	# pb? display usage and quit
	if len(args) < 2:
		usage(args)
	
	# save namespace and containerResult
	namespace = args[1]
	containerResult = LISTENER_RESULT_CONTAINER_NAME

	#init listener and launch it
	list = Listener(listenerUrl, g_bverbose, namespace, containerResult)
	if list.Initialize() == True:
		list.go(LST_MSGIN_TIMEOUT)




if __name__ == '__main__':
	main()




