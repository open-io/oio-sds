import unittest
from oio.api.backblaze_http import Backblaze, BackblazeException
import random
import string
import base64
import json
import hashlib
import mock
import StringIO
APPLICATION_KEY = str(random.getrandbits(10))
ACCOUNT_ID = str(random.getrandbits(10))
BUCKET_NAME = str(random.getrandbits(10))
KEY = '%s.%s' % (ACCOUNT_ID, APPLICATION_KEY)
BUCKET_ID = 'AAAA'
B2_DOWNLOAD_URL = 'b2_download'
B2_UPLOAD_URL = 'b2_upload'
list_authorization = {KEY:
                      ({'accountId': ACCOUNT_ID,
                        'apiUrl': '',
                        'authorizationToken': '',
                        'downloadUrl': B2_DOWNLOAD_URL},
                       {'bucketId': BUCKET_ID,
                        'uploadUrl': B2_UPLOAD_URL,
                        'authorizationToken': ''})}

list_files = {BUCKET_NAME: {'bucket_id': BUCKET_ID,
                            'files': []}}


def mock_authorize_account(headers):
    auth = headers['Authorization']
    basic, encoded = auth.split(' ')
    auth_decoded = base64.b64decode(encoded)
    account_id, application_key = auth_decoded.split(':')
    if account_id != ACCOUNT_ID or application_key != APPLICATION_KEY:
        raise BackblazeException(401, 'Invalid authorization', None, None)
    return list_authorization[KEY][0]


def mock_list_buckets(headers, file_descriptor):
    if headers['Authorization'] != \
       list_authorization[KEY][0]['authorizationToken']:
        raise BackblazeException(401, 'Not authorized', None, None)
    dic_body = json.load(StringIO.StringIO(file_descriptor))
    account_id = dic_body['accountId']
    if account_id != ACCOUNT_ID:
        raise BackblazeException(400,
                                 'Account %s does not exist' % (account_id),
                                 None, None)

    return {'buckets': [{'bucketId': list_files[BUCKET_NAME]['bucket_id'],
                         'bucketName': BUCKET_NAME}]}


def mock_upload_token(headers, file_descriptor):
    dic_body = json.load(StringIO.StringIO(file_descriptor))
    bucket_id = dic_body['bucketId']
    if bucket_id != BUCKET_ID:
        return BackblazeException(400, 'bucket %s does not exist' %
                                  (bucket_id,), None, None)
    return list_authorization[KEY][1]


def mock_download(headers, url):
    file_name = ''
    for i in url.split('/')[3:]:
        file_name = file_name + '/' + i
    file_name = file_name[1:]
    bucket_name = url.split('/')[2]
    if BUCKET_NAME != bucket_name:
        return BackblazeException(404, 'Bucket does not exist: %s' %
                                  (bucket_name), None, None)
    for i in list_files[BUCKET_NAME]['files']:
        if i['fileName'] == file_name:
            return i['content']
    raise BackblazeException(404, 'Bucket %s does not have file: %s' %
                             (bucket_name, file_name), None, None)


def mock_list_file_names(headers, file_descriptor):
    dic = json.load(StringIO.StringIO(file_descriptor))
    if headers['Authorization'] != \
       list_authorization[KEY][0]['authorizationToken']:
        raise BackblazeException(401, 'Invalid authorization token',
                                 None, None)
    bucket_id = dic['bucketId']
    if bucket_id != BUCKET_ID:
        raise BackblazeException(400, 'Invalid bucketId: %s' % (bucket_id))
    return {'files': list_files[BUCKET_NAME]['files'],
            'nextFileName': None}


def mock_delete(headers, file_descriptor):
    dic = json.load(StringIO.StringIO(file_descriptor))
    if headers['Authorization'] != \
       list_authorization[KEY][0]['authorizationToken']:
        raise BackblazeException(401, 'Invalid authorization token', None,
                                 None)
    file_dic = None
    for i in list_files[BUCKET_NAME]['files']:
        if i['fileName'] == dic['fileName'] and i['fileId'] == dic['fileId']:
            file_dic = i
    if not file_dic:
        raise BackblazeException(400, 'File not present: %s %s' %
                                 (dic['fileName'], dic['fileId']), None, None)
    list_files[BUCKET_NAME]['files'].remove(file_dic)
    return {'fileName': dic['fileName'],
            'fileId': dic['fileId']}


def mock_upload(headers, file_descriptor):
    content = file_descriptor
    if headers['Authorization'] != \
       list_authorization[KEY][0]['authorizationToken']:
        raise BackblazeException(401, 'Invalid authorization token',
                                 None, None)
    hash_sha1 = hashlib.sha1()
    hash_sha1.update(content)
    if headers['X-Bz-Content-Sha1'] != hash_sha1.hexdigest():
        raise BackblazeException(503, "error Sha1 send", None, None)
    file_name = headers['X-Bz-File-Name']
    # TODO : maybe put a true unique id!
    file_id = headers['X-Bz-Content-Sha1']
    dic_file = {'content': content,
                'fileId': file_id,
                'fileName': file_name,
                'contentSha1': headers['X-Bz-Content-Sha1'],
                'contentType': headers['Content-Type'],
                'contentLength': len(content),
                'size': len(content)}
    list_files[BUCKET_NAME]['files'].append(dic_file)
    return dic_file


def _request(obj, content_type, url, headers=None,
             file_descriptor=None, json=None):
    json
    obj
    if url.find('b2_authorize_account') != -1:
        return mock_authorize_account(headers)
    elif url.find('b2_list_buckets') != -1:
        return mock_list_buckets(headers, file_descriptor)
    elif url.find('b2_get_upload_url') != -1:
        return mock_upload_token(headers, file_descriptor)
    elif url.find('b2_list_file_names') != -1:
        return mock_list_file_names(headers, file_descriptor)
    elif url.find('b2_delete_file_version') != -1:
        return mock_delete(headers, file_descriptor)
    elif url.find(B2_UPLOAD_URL) != -1:
        return mock_upload(headers, file_descriptor)
    elif url.find(B2_DOWNLOAD_URL) != -1:
        return mock_download(headers, url)
    else:
        raise BackblazeException(500, 'Internal server error', None, None)


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


class BackblazeHttpTest(unittest.TestCase):
    @mock.patch('oio.api.backblaze_http.Requests.get_response_from_request',
                _request)
    def __init__(self, *args, **kwargs):
        super(BackblazeHttpTest, self).__init__(*args, **kwargs)
        if not (APPLICATION_KEY and ACCOUNT_ID and BUCKET_NAME):
            self.backblaze_test = None
        else:
            self.backblaze_test = Backblaze(ACCOUNT_ID,
                                            APPLICATION_KEY)

    @mock.patch('oio.api.backblaze_http.Requests.get_response_from_request',
                _request)
    def test_backblaze(self):
        self.assertTrue(self.backblaze_test is not None)
        filename = _random_word(10)
        container_id = _random_word(10)
        true_filename = _get_name(container_id, filename)
        size = self.backblaze_test.get_size(BUCKET_NAME)
        meta = _generate_fake_metadata(container_id, filename)
        content = _random_word(100)
        res = self.backblaze_test.upload(BUCKET_NAME, meta, content)
        self.assertTrue(res)
        size_after_upload = self.backblaze_test.get_size(BUCKET_NAME)
        self.assertTrue(size + len(content) == size_after_upload)
        res = self.backblaze_test._get_id_file_by_file_name(BUCKET_NAME,
                                                            true_filename)
        self.assertTrue(res)
        res = self.backblaze_test.download(BUCKET_NAME, meta)
        self.assertTrue(res == content)
        res = self.backblaze_test.delete(BUCKET_NAME, meta)
        self.assertTrue(res)
        res = self.backblaze_test._get_id_file_by_file_name(BUCKET_NAME,
                                                            true_filename)
        self.assertFalse(res)
        size_after_delete = self.backblaze_test.get_size(BUCKET_NAME)
        self.assertTrue(size_after_delete == size)

    @mock.patch('oio.api.backblaze_http.Requests.get_response_from_request',
                _request)
    def test_bad_authorization(self):
        bad_account_id = ACCOUNT_ID + ACCOUNT_ID
        throw_exception = False
        try:
            Backblaze(bad_account_id, APPLICATION_KEY)
        except BackblazeException:
            throw_exception = True
            self.assertTrue(throw_exception)

    @mock.patch('oio.api.backblaze_http.Requests.get_response_from_request',
                _request)
    def test_file_not_present(self):
        true_filename = ACCOUNT_ID
        meta = _generate_fake_metadata('', true_filename)
        throw_exception = False
        try:
            self.backblaze_test.download(BUCKET_NAME, meta)
        except BackblazeException as e:
            if e.message.find('does not have file') != -1:
                throw_exception = True
                self.assertTrue(throw_exception)

    def bad_bucket_name(self):
        bad_bucket_name = BUCKET_NAME + BUCKET_NAME
        true_filename = bad_bucket_name
        meta = _generate_fake_metadata('', true_filename)
        throw_exception = False
        try:
            self.backblaze_test.download(bad_bucket_name, meta)
        except BackblazeException as e:
            if e.message.find('Bucket does not exist') != -1:
                throw_exception = True
                self.assertTrue(throw_exception)
