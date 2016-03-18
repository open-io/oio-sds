
class BaseStat(object):
    """Base class for all service stat"""

    def __init__(self, agent, stat_conf, logger):
        self.agent = agent
        self.stat_conf = stat_conf
        self.logger = logger
        self.configure()

    def configure(self):
        """Configuration handle"""
        pass

    def stat(self):
        """Actually do the service stat"""
        return {}
