import unittest
import sys
from oio.api.backblaze_http import Backblaze
import random
import string


def _generate_fake_metadata(container_id, name):
    return {
        'mime_type': 'application/octet-stream',
        'container_id': container_id,
        'name': name
        }


def _get_name(container_id, name):
    return container_id + '/' + name


def _random_word(length):
    return ''.join(random.choice(string.lowercase) for i in range(length))


class BackblazeTest(unittest.TestCase):
    APPLICATION_KEY = None
    ACCOUNT_ID = None
    BUCKET_NAME = None

    def __init__(self, *args, **kwargs):
        super(BackblazeTest, self).__init__(*args, **kwargs)
        if not (self.APPLICATION_KEY and self.ACCOUNT_ID and self.BUCKET_NAME):
            self.backblaze_test = None
        else:
            self.backblaze_test = Backblaze(self.ACCOUNT_ID,
                                            self.APPLICATION_KEY)

    # TODO: make the test compatible with travis
    def test_backblaze(self):
        return
        self.assertTrue(self.backblaze_test is not None)
        filename = _random_word(10)
        container_id = _random_word(10)
        true_filename = _get_name(container_id, filename)
        size = self.backblaze_test.get_size(self.BUCKET_NAME)
        meta = _generate_fake_metadata(container_id, filename)
        content = _random_word(100)
        res = self.backblaze_test.upload(self.BUCKET_NAME, meta, content)
        self.assertTrue(res)
        size_after_upload = self.backblaze_test.get_size(self.BUCKET_NAME)
        self.assertTrue(size + len(content) == size_after_upload)
        res = self.backblaze_test._get_id_file_by_file_name(self.BUCKET_NAME,
                                                            true_filename)
        self.assertTrue(res)
        res = self.backblaze_test.download(self.BUCKET_NAME, meta)
        self.assertTrue(res == content)
        res = self.backblaze_test.delete(self.BUCKET_NAME, meta)
        self.assertTrue(res)
        res = self.backblaze_test._get_id_file_by_file_name(self.BUCKET_NAME,
                                                            true_filename)
        self.assertFalse(res)
        size_after_delete = self.backblaze_test.get_size(self.BUCKET_NAME)
        self.assertTrue(size_after_delete == size)


if __name__ == '__main__':
    if len(sys.argv) > 3:
        BackblazeTest.BUCKET_NAME = sys.argv.pop()
        BackblazeTest.APPLICATION_KEY = sys.argv.pop()
        BackblazeTest.ACCOUNT_ID = sys.argv.pop()
    unittest.main()
