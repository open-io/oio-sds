import unittest
from oio.api.backblaze import BackblazeChunkWriteHandler, \
    BackblazeChunkDownloadHandler, BackblazeDeleteHandler
import StringIO
import random
import mock
import hashlib
import string


def _random_word(size):
    return ''.join(random.choice(string.lowercase) for i in range(size))

CONTAINER_ID = _random_word(10)
FILE_NAME = _random_word(10)
BACKBLAZE_CHUNK_SIZE = 100
CONTENT = _random_word(BACKBLAZE_CHUNK_SIZE + 1)
FILE_ID = _random_word(10)


def _generate_meta_chunks(chunk_size, content):
    chunk_number = len(content) // chunk_size
    meta_chunks = []
    for i in range(chunk_number):
        meta_chunks.append(_generate_meta_chunk(chunk_size))
    return meta_chunks


def _generate_meta_chunk(chunk_size):
    return {'size': chunk_size,
            'hash': _random_word(10),
            'url': 'chunk/'+_random_word(10)}


def _generate_sysmeta():
    return {}


def _generate_backblaze_infos():
    return {'backblaze.account_id': _random_word(10),
            'backblaze.application_key': _random_word(10),
            'authorization': None,
            'upload_token': None,
            'bucket_name': None}


class DownloadException(Exception):
    def __init__(self):
        super(DownloadException, self).__init__('download')


class DeleteException(Exception):
    def __init__(self):
        super(DeleteException, self).__init__('delete')


class UploadException(Exception):
    def __init__(self):
        super(UploadException, self).__init__('upload')


class UploadPartException(Exception):
    def __init__(self):
        super(UploadPartException, self).__init__('upload_part')


class BackblazeMock(object):
    def __init__(self, account_id, application_key,
                 authorization_required=None, upload_required=None,
                 upload_part=False):
        self.BACKBLAZE_MAX_CHUNK_SIZE = BACKBLAZE_CHUNK_SIZE

    def upload(self, bucket_name, sysmeta, temp, sha1):
        raise UploadException()

    def upload_part_begin(self, bucket_name, meta):
        return {'fileId': FILE_ID}

    def upload_part(self, file_id, data, part_number, sha1=None):
        if not sha1:
            sha1_gen = hashlib.sha1()
            sha1_gen.update(data)
            sha1 = sha1_gen.hexdigest()
        return None, sha1

    def upload_part_end(self, file_id, sha1_array):
        raise UploadPartException()

    def download(self, bucket_name, metadata, headers=None):
        raise DownloadException()

    def delete(self, bucket_name, metadata):
        raise DeleteException()


class BackblazeTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(BackblazeTest, self).__init__(*args, **kwargs)

    def test_upload_small_chunks(self):
        sysmeta = _generate_sysmeta()
        size = BACKBLAZE_CHUNK_SIZE - 1
        buffer_content = StringIO.StringIO(CONTENT)
        backblaze_infos = _generate_backblaze_infos()
        meta_chunk = _generate_meta_chunk(size)
        with mock.patch('oio.api.backblaze.Backblaze', BackblazeMock):
            upload_small_chunk = BackblazeChunkWriteHandler(
                sysmeta, meta_chunk, hashlib.md5(), None, backblaze_infos)
            upload_exception = False
            try:
                upload_small_chunk.stream(buffer_content)
            except UploadException:
                upload_exception = True
            self.assertTrue(upload_exception)

    def test_upload_big_chunks(self):
        sysmeta = _generate_sysmeta()
        size = len(CONTENT)
        sha1 = hashlib.sha1()
        sha1.update(CONTENT)
        backblaze_infos = _generate_backblaze_infos()
        buffer_content = StringIO.StringIO(CONTENT)
        meta_chunk = _generate_meta_chunk(size)
        with mock.patch('oio.api.backblaze.Backblaze', BackblazeMock):
            upload_big_chunk = BackblazeChunkWriteHandler(sysmeta,
                                                          meta_chunk,
                                                          hashlib.md5(),
                                                          None,
                                                          backblaze_infos)
            upload_part_exception = False
            try:
                upload_big_chunk.stream(buffer_content)
            except UploadPartException:
                upload_part_exception = True
            self.assertTrue(upload_part_exception)

    def test_upload_small_chunks_in_big(self):
        sysmeta = _generate_sysmeta()
        size = len(CONTENT)
        buffer_content = StringIO.StringIO(CONTENT[1:])
        backblaze_infos = _generate_backblaze_infos()
        meta_chunk = _generate_meta_chunk(size)
        with mock.patch('oio.api.backblaze.Backblaze', BackblazeMock):
            upload_small_chunk = BackblazeChunkWriteHandler(sysmeta,
                                                            meta_chunk,
                                                            hashlib.md5(),
                                                            None,
                                                            backblaze_infos)
            upload_exception = False
            try:
                upload_small_chunk.stream(buffer_content)
            except UploadException:
                upload_exception = True
            self.assertTrue(upload_exception)

    def test_delete(self):
        sysmeta = _generate_sysmeta()
        size = len(CONTENT)
        backblaze_infos = _generate_backblaze_infos()
        meta_chunk = _generate_meta_chunk(size)
        with mock.patch('oio.api.backblaze.Backblaze', BackblazeMock):
            delete_chunk = BackblazeDeleteHandler(sysmeta,
                                                  [meta_chunk],
                                                  backblaze_infos)
            delete_exception = False
            try:
                delete_chunk.delete()
            except DeleteException:
                delete_exception = True
            self.assertTrue(delete_exception)

    def test_download(self):
        sysmeta = _generate_sysmeta()
        size = len(CONTENT)
        backblaze_infos = _generate_backblaze_infos()
        meta_chunk = _generate_meta_chunk(size)
        with mock.patch('oio.api.backblaze.Backblaze', BackblazeMock):
            download_chunk = BackblazeChunkDownloadHandler(sysmeta,
                                                           [meta_chunk],
                                                           0,
                                                           0,
                                                           None,
                                                           backblaze_infos)
            download_exception = False
            try:
                download_chunk.get_stream()
            except DownloadException:
                download_exception = True
            self.assertTrue(download_exception)
