import logging
from oio.directory.client import DirectoryClient

LOG = logging.getLogger(__name__)

API_NAME = 'directory'


def make_client(instance):
    endpoint = instance.get_endpoint('directory')
    client = DirectoryClient({"namespace": instance.namespace},
                             session=instance.session,
                             endpoint=endpoint)
    return client


def build_option_parser(parser):
    return parser
