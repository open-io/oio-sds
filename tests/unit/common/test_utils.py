import unittest
import logging
from cStringIO import StringIO
from oio.common.utils import get_logger


class TestUtils(unittest.TestCase):
    def test_get_logger(self):
        sio = StringIO()
        logger = logging.getLogger('test')
        logger.addHandler(logging.StreamHandler(sio))
        logger = get_logger(None, 'test')
        logger.warn('msg1')
        self.assertEqual(sio.getvalue(), 'msg1\n')
        logger.debug('msg2')
        self.assertEqual(sio.getvalue(), 'msg1\n')
        conf = {'log_level': 'DEBUG'}
        logger = get_logger(conf, 'test')
        logger.debug('msg3')
        self.assertEqual(sio.getvalue(), 'msg1\nmsg3\n')
