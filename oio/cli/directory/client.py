import logging
from oio.api.directory import DirectoryAPI

LOG = logging.getLogger(__name__)

API_NAME = 'directory'


def make_client(instance):
    endpoint = instance.get_endpoint('directory')
    client = DirectoryAPI(
        session=instance.session,
        endpoint=endpoint,
        namespace=instance.namespace
    )
    return client


def build_option_parser(parser):
    return parser
