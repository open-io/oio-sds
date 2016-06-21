from mock import MagicMock as Mock

from oio.rdir.client import RdirClient
from tests.utils import BaseTestCase, random_id


class TestRdirClient(BaseTestCase):
    def setUp(self):
        super(TestRdirClient, self).setUp()
        self.namespace = self.conf['namespace']
        self.rdir_client = RdirClient({'namespace': self.namespace})
        self.rdir_client._get_rdir_addr = Mock(return_value="0.1.2.3:4567")
        self.container_id_1 = random_id(64)
        self.container_id_2 = random_id(64)
        self.container_id_3 = random_id(64)
        self.content_id_1 = random_id(32)
        self.content_id_2 = random_id(32)
        self.content_id_3 = random_id(32)
        self.chunk_id_1 = random_id(64)
        self.chunk_id_2 = random_id(64)
        self.chunk_id_3 = random_id(64)

    def tearDown(self):
        super(TestRdirClient, self).tearDown()
        del self.rdir_client

    def test_fetch_one_req_post(self):
        self.rdir_client._direct_request = Mock(
            side_effect=[
                (
                    Mock(),
                    [
                        ["%s|%s|%s" %
                         (self.container_id_1, self.content_id_1,
                          self.chunk_id_1), {'mtime': 10}],
                        ["%s|%s|%s" %
                         (self.container_id_2, self.content_id_2,
                             self.chunk_id_2), {'mtime': 20}],
                    ]
                )
            ])
        gen = self.rdir_client.chunk_fetch("volume", limit=2)
        self.assertEqual(
            gen.next(), (self.container_id_1, self.content_id_1,
                         self.chunk_id_1, {'mtime': 10}))
        self.assertEqual(
            gen.next(), (self.container_id_2, self.content_id_2,
                         self.chunk_id_2, {'mtime': 20}))
        self.assertRaises(StopIteration, gen.next)
        self.assertEqual(self.rdir_client._direct_request.call_count, 2)

    def test_fetch_multi_req(self):
        self.rdir_client._direct_request = Mock(
            side_effect=[
                (
                    Mock(),
                    [
                        ["%s|%s|%s" %
                         (self.container_id_1, self.content_id_1,
                             self.chunk_id_1), {'mtime': 10}],
                        ["%s|%s|%s" %
                         (self.container_id_2, self.content_id_2,
                             self.chunk_id_2), {'mtime': 20}],
                    ]
                ),
                (
                    Mock(),
                    [
                        ["%s|%s|%s" %
                         (self.container_id_3, self.content_id_3,
                             self.chunk_id_3), {'mtime': 30}],
                    ]
                )
            ])
        gen = self.rdir_client.chunk_fetch("volume", limit=2)
        self.assertEqual(
            gen.next(), (self.container_id_1, self.content_id_1,
                         self.chunk_id_1, {'mtime': 10}))
        self.assertEqual(
            gen.next(), (self.container_id_2, self.content_id_2,
                         self.chunk_id_2, {'mtime': 20}))
        self.assertEqual(
            gen.next(), (self.container_id_3, self.content_id_3,
                         self.chunk_id_3, {'mtime': 30}))
        self.assertRaises(StopIteration, gen.next)
        self.assertEqual(self.rdir_client._direct_request.call_count, 3)
