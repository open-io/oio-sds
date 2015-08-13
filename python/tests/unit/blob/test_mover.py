import unittest

from mock import MagicMock as Mock

from oio.common import exceptions as exc
from oio.blob.mover import BlobMoverWorker


class FakeBlobMoverWorker(BlobMoverWorker):
    def __init__(self, conf, logger, volume):
        super(FakeBlobMoverWorker, self).__init__(conf, logger, volume)
        self.address = '127.0.0.1:6000'


class TestBlobMover(unittest.TestCase):
    def setUp(self):
        conf = {'namespace': 'NS'}
        self.mover = FakeBlobMoverWorker(conf, None, '/tmp')
        self.path = '/tmp/toto'
        self.content_path = 'a'
        self.content_cid = 'CID'
        self.chunk_hash = '00000000000000000000000000000000'
        self.chunk_size = 1
        self.chunk_id = 'AAAA'
        self.chunk_url = 'http://127.0.0.1:6000/' + self.chunk_id
        self.chunk_pos = '0'
        self.metadata = {
            'content_cid': self.content_cid,
            'content_path': self.content_path,
            'content_size': 1,
            'content_chunksnb': 1,
            'chunk_id': self.chunk_id,
            'chunk_pos': self.chunk_pos,
            'chunk_size': self.chunk_size,
            'chunk_hash': self.chunk_hash}
        self.chunk = {'url': self.chunk_url}
        self.chunks = [self.chunk]
        self.spare_data = {'notin': [], 'broken': [self.chunk], 'size': 0}
        self.new_chunk_id = 'BBBB'
        self.new_chunk_url = 'http://127.0.0.1:6001/' + self.new_chunk_id
        self.new_chunks = {'chunks': [{'id': self.new_chunk_url}]}
        self.new_metadata = self.metadata.copy()
        self.new_metadata['chunk_id'] = self.new_chunk_id
        self.update_data = {
            'old': [{'type': 'chunk', 'id': self.chunk_url,
                     'size': self.chunk_size, 'hash': self.chunk_hash}],
            'new': [{'type': 'chunk', 'id': self.new_chunk_url,
                     'size': self.chunk_size, 'hash': self.chunk_hash}]}

    def test_chunk_move(self):
        mover = self.mover
        mover.load_chunk_metadata = Mock(return_value=self.metadata)
        mover.container_client.content_show = Mock(return_value=self.chunks)
        mover.container_client.content_spare = Mock(
            return_value=self.new_chunks)
        mover.blob_client.chunk_copy = Mock(
            return_value=self.new_metadata)
        mover.container_client.container_raw_update = Mock(
            return_value={})
        mover.blob_client.chunk_delete = Mock(
            return_value={})

        mover.chunk_move(self.path)

        mover.container_client.content_show.assert_called_once_with(
            cid=self.content_cid, path=self.content_path)
        mover.container_client.content_spare.assert_called_once_with(
            cid=self.content_cid, path=self.content_path, data=self.spare_data)
        mover.blob_client.chunk_copy.assert_called_once_with(
            self.chunk_url, self.new_chunk_url)
        mover.container_client.container_raw_update.assert_called_once_with(
            cid=self.content_cid, data=self.update_data)
        mover.blob_client.chunk_delete.assert_called_once_with(
            self.chunk_url)

    def test_chunk_move_no_content(self):
        mover = self.mover
        mover.load_chunk_metadata = Mock(return_value=self.metadata)
        mover.container_client.content_show = Mock(
            side_effect=exc.NotFound('Content not found'))

        with self.assertRaises(exc.OrphanChunk):
            mover.chunk_move(self.path)

    def test_chunk_move_not_in_content(self):
        mover = self.mover
        mover.load_chunk_metadata = Mock(return_value=self.metadata)
        mover.container_client.content_show = Mock(return_value={})

        with self.assertRaises(exc.OrphanChunk):
            mover.chunk_move(self.path)
