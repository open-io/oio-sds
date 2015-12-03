import unittest
from mock import MagicMock as Mock

from oio.rdir.client import RdirClient


class TestRdirClient(unittest.TestCase):
    def setUp(self):
        super(TestRdirClient, self).setUp()
        self.rdir_client = RdirClient({'namespace': "NS"})
        self.rdir_client._get_rdir_addr = Mock(return_value="0.1.2.3:4567")

    def tearDown(self):
        super(TestRdirClient, self).tearDown()
        del self.rdir_client

    def test_fetch_one_req_post(self):
        self.rdir_client._direct_request = Mock(
            side_effect=[
                (
                    Mock(),
                    [
                        ["container1|content1|chunk1", {'mtime': 10}],
                        ["container2|content2|chunk2", {'mtime': 20}]
                    ]
                )
            ])
        gen = self.rdir_client.chunk_fetch("volume", limit=2)
        self.assertEqual(gen.next(),
                         ("container1", "content1", "chunk1", {'mtime': 10}))
        self.assertEqual(gen.next(),
                         ("container2", "content2", "chunk2", {'mtime': 20}))
        self.assertRaises(StopIteration, gen.next)
        self.assertEqual(self.rdir_client._direct_request.call_count, 2)

    def test_fetch_multi_req(self):
        self.rdir_client._direct_request = Mock(
            side_effect=[
                (
                    Mock(),
                    [
                        ["container1|content1|chunk1", {'mtime': 10}],
                        ["container2|content2|chunk2", {'mtime': 20}]
                    ]
                ),
                (
                    Mock(),
                    [
                        ["container3|content3|chunk3", {'mtime': 30}]
                    ]
                )
            ])
        gen = self.rdir_client.chunk_fetch("volume", limit=2)
        # print(gen.next())
        # print(gen.next())
        # print(gen.next())
        self.assertEqual(gen.next(),
                         ("container1", "content1", "chunk1", {'mtime': 10}))
        self.assertEqual(gen.next(),
                         ("container2", "content2", "chunk2", {'mtime': 20}))
        self.assertEqual(gen.next(),
                         ("container3", "content3", "chunk3", {'mtime': 30}))
        self.assertRaises(StopIteration, gen.next)
        self.assertEqual(self.rdir_client._direct_request.call_count, 3)
