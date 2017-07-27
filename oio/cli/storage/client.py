from logging import getLogger

LOG = getLogger(__name__)

API_NAME = 'storage'


def make_client(instance):
    from oio.api.object_storage import ObjectStorageApi

    admin_mode = instance.get_admin_mode()
    endpoint = instance.get_endpoint('storage')
    client = ObjectStorageApi(
        session=instance.session,
        endpoint=endpoint,
        namespace=instance.namespace,
        admin_mode=admin_mode
    )
    return client


def build_option_parser(parser):
    return parser
