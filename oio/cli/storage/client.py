import logging
from oio.api.object_storage import ObjectStorageAPI

LOG = logging.getLogger(__name__)

API_NAME = 'storage'


def make_client(instance):
    endpoint = instance.get_endpoint('storage')
    client = ObjectStorageAPI(
        session=instance.session,
        endpoint=endpoint,
        namespace=instance.namespace
    )
    return client


def build_option_parser(parser):
    return parser
