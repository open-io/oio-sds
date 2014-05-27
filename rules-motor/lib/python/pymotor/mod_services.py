
from pygrid.services import Conscience
from pygrid.locate import ConscienceLocator
from pygrid.gridd import make_gridd_from_addr

class Services:
	def __init__(self, ns):
		self.ns = ns
		cscaddr, = ConscienceLocator().locate(ns, '')
		self.conscience = Conscience(ns, make_gridd_from_addr(cscaddr))
		self.services = {}

	def update(self, srvtype):
		self.services[srvtype] = list(self.conscience.get_services(srvtype))

	def get_ns_average_score(self, srvtype):
		score_total = score_nb = 0
		for srv in self.services[srvtype]:
			score_total += srv.get_score()
			score_nb += 1
		if (score_nb > 0):
			return score_total / score_nb
		else:
			return 0

	def get_srv_score(self, srvinfo):
		for srv in self.services[srvinfo.get_type()]:
			if (srv == srvinfo):
				return srv.get_score()
		return 0
