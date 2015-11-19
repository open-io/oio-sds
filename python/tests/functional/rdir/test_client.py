from mock import MagicMock as Mock

from oio.rdir.client import RdirClient

from tests.utils import BaseTestCase


class TestRdirClient(BaseTestCase):
    def setUp(self):
        super(TestRdirClient, self).setUp()
        self.rdir_client = RdirClient({'namespace': "NS"})

    def tearDown(self):
        super(TestRdirClient, self).tearDown()
        del self.rdir_client

    def test_fetch_one_req_post(self):
        self.rdir_client._request = Mock(
            side_effect=[
                (
                    Mock(),
                    {
                        "container1|content1|chunk1": {'mtime': 10},
                        "container2|content2|chunk2": {'mtime': 20}
                    }
                )
            ])
        gen = self.rdir_client.fetch("volume", limit=2)
        self.assertEqual(gen.next(),
                         ("container1", "content1", "chunk1", {'mtime': 10}))
        self.assertEqual(gen.next(),
                         ("container2", "content2", "chunk2", {'mtime': 20}))
        self.assertRaises(StopIteration, gen.next)
        self.assertEqual(self.rdir_client._request.call_count, 2)

    def test_fetch_multi_req(self):
        self.rdir_client._request = Mock(
            side_effect=[
                (
                    Mock(),
                    {
                        "container1|content1|chunk1": {'mtime': 10},
                        "container2|content2|chunk2": {'mtime': 20}
                    }
                ),
                (
                    Mock(),
                    {
                        "container3|content3|chunk3": {'mtime': 30}
                    }
                )
            ])
        gen = self.rdir_client.fetch("volume", limit=2)
        self.assertEqual(gen.next(),
                         ("container1", "content1", "chunk1", {'mtime': 10}))
        self.assertEqual(gen.next(),
                         ("container2", "content2", "chunk2", {'mtime': 20}))
        self.assertEqual(gen.next(),
                         ("container3", "content3", "chunk3", {'mtime': 30}))
        self.assertRaises(StopIteration, gen.next)
        self.assertEqual(self.rdir_client._request.call_count, 3)
