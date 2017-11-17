# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

from six import string_types
from six.moves import configparser
from requests import exceptions, Session, Request
import base64
import hashlib
import json as js
from oio.api import io


def _format_autorization_required(account_id, application_key):
    return 'Basic ' + base64.b64encode(account_id+':'+application_key)


def _recover_true_path(metadata, chunk_path):
    return metadata['container_id'] + '/' + chunk_path


def _get_sha1(data):
    generate = hashlib.sha1()
    if not isinstance(data, string_types):
        for chunk in iter(lambda: data.read(io.WRITE_CHUNK_SIZE), b''):
            generate.update(chunk)
            data.seek(0, 0)
    else:
        generate.update(data)
    return generate.hexdigest()


class BackblazeUtils(object):

    b2_authorization_list = {}

    @staticmethod
    def get_credentials(storage_method, application_key_path=None,
                        renew=False):
        if not storage_method.bucket_name:
            message = "missing backblaze parameters: %s" % ('bucket_name',)
            raise BackblazeUtilsException(message)
        if not storage_method.account_id:
            message = "missing backblaze parameters: %s" % ('account_id',)
            raise BackblazeUtilsException(message)
        if not application_key_path:
            message = "missing backblaze parameters: %s" % \
                      ('application_key_path',)
            raise BackblazeUtilsException(message)
        key = '%s.%s' % (storage_method.account_id, storage_method.bucket_name)
        if not renew:
            authorization = BackblazeUtils.b2_authorization_list.get(key, None)
            if authorization:
                return authorization
        config = configparser.ConfigParser()
        app_key = None
        with open(application_key_path) as app_key_f:
            try:
                config.readfp(app_key_f)
            except IOError as exc:
                raise BackblazeUtilsException(
                    "Failed to load application key: %s"
                    % exc)
            app_key = config.get('backblaze',
                                 '%s.%s.application_key'
                                 % (storage_method.account_id,
                                    storage_method.bucket_name))
        if not app_key:
            raise BackblazeUtilsException('application key not found')
        meta = {}
        meta['backblaze.account_id'] = storage_method.account_id
        meta['backblaze.application_key'] = app_key
        meta['bucket_name'] = storage_method.bucket_name
        backblaze = Backblaze(storage_method.account_id,
                              app_key)
        meta['authorization'] = backblaze.authorization_token
        meta['upload_token'] = backblaze._get_upload_token_by_bucket_name(
            storage_method.bucket_name)
        BackblazeUtils.b2_authorization_list[key] = meta
        return meta


class Backblaze(object):
    BACKBLAZE_MAX_CHUNK_SIZE = 209715200
    BACKBLAZE_BASE_API_URL = 'https://api.backblazeb2.com'

    def __init__(self, account_id, application_key,
                 authorization_required=None, upload_required=None,
                 upload_part=False):

        self.upload_token = self.upload_part_token = None
        self.account_id = account_id
        self.application_key = application_key
        authorization = authorization_required
        if not authorization:
            authorization = self._recover_account_backblaze()
        self.authorization_required = authorization
        if not upload_part:
            self.upload_token = upload_required
        else:
            self.upload_part_token = upload_required
        self.liste_bucket_id = {}

    def _recover_account_backblaze(self):
        header = {'Authorization':
                  _format_autorization_required(self.account_id,
                                                self.application_key)}
        url_request = '%s/b2api/v1/b2_authorize_account' % \
                      (self.BACKBLAZE_BASE_API_URL)
        return Requests().get_response_from_request('GET', url_request, header,
                                                    json=True)

    def _recover_list_buckets_token(self):
        body = {'accountId': self.account_id}
        headers = {'Authorization':
                   self.authorization_required['authorizationToken']}
        url = '%s/b2api/v1/b2_list_buckets' % \
              self.authorization_required['apiUrl']
        return Requests().get_response_from_request('POST', url, headers,
                                                    js.dumps(body), True)

    def _recover_bucket_id_backblaze(self, bucket_name):
        if self.liste_bucket_id.get(bucket_name, None) is not None:
            return self.liste_bucket_id[bucket_name]
        list_buckets = self.get_list_buckets()
        for tmp in list_buckets['buckets']:
            if tmp['bucketName'] == bucket_name:
                self.liste_bucket_id[bucket_name] = tmp['bucketId']
                return tmp['bucketId']
        return None

    def _get_upload_token(self, bucket_id):
        body = {'bucketId': bucket_id}
        headers = {'Authorization':
                   self.authorization_required['authorizationToken']}
        url_upload = '%s/b2api/v1/b2_get_upload_url' % \
                     self.authorization_required['apiUrl']
        return Requests().get_response_from_request('POST', url_upload,
                                                    headers,
                                                    js.dumps(body), True)

    def _begin_big_file(self, bucket_id, metadata):
        body = {'bucketId': bucket_id,
                'fileName': _recover_true_path(metadata, metadata['name']),
                'contentType': metadata['mime_type']}
        headers = {'Authorization':
                   self.authorization_required['authorizationToken']}
        url_upload = '%s/b2api/v1/b2_start_large_file' % \
                     self.authorization_required['apiUrl']
        return Requests().get_response_from_request('POST', url_upload,
                                                    headers,
                                                    js.dumps(body), True)

    def _end_big_file(self, file_id, sha1_array):
        body = {'fileId': file_id, 'partSha1Array': sha1_array}
        headers = {'Authorization':
                   self.authorization_required['authorizationToken']}
        url_upload = '%s/b2api/v1/b2_finish_large_file' % \
            self.authorization_required['apiUrl']
        return Requests().get_response_from_request('POST', url_upload,
                                                    headers,
                                                    js.dumps(body), True)

    def _get_upload_part_token(self, file_id):
        body = {'fileId': file_id}
        headers = {'Authorization':
                   self.authorization_required['authorizationToken']}
        url_upload = '%s/b2api/v1/b2_get_upload_part_url' % \
                     self.authorization_required['apiUrl']
        return Requests().get_response_from_request('POST', url_upload,
                                                    headers,
                                                    js.dumps(body), True)

    def _recover_upload_part_file(self, data, sha1, part_number):
        headers = {
            'Authorization': self.upload_part_token['authorizationToken'],
            'X-Bz-Part-Number': part_number,
            'X-Bz-Content-Sha1': sha1,
        }
        upload_url = self.upload_part_token['uploadUrl']
        resp = Requests().get_response_from_request('POST', upload_url,
                                                    headers, data, True)
        return resp

    def _recover_upload_file(self, metadata, data, sha1):
        headers = {
            'Authorization': self.upload_token['authorizationToken'],
            'X-Bz-File-Name': _recover_true_path(metadata, metadata['name']),
            'Content-Type': metadata['mime_type'],
            'X-Bz-Content-Sha1': sha1,
        }
        upload_url = self.upload_token['uploadUrl']
        resp = Requests().get_response_from_request('POST', upload_url,
                                                    headers, data, True)
        return resp

    def _download_backblaze(self, bucket_name, link, header=None):
        headers = {'Authorization':
                   self.authorization_required['authorizationToken']}
        if header:
            for key in header:
                headers[key] = header[key]
        url_upload = '%s/file/%s/%s' % \
                     (self.authorization_required['downloadUrl'], bucket_name,
                      link)
        return Requests().get_response_from_request('GET', url_upload,
                                                    headers, None)

    def _list_file_names(self, bucket_id):
        start_file_name = True
        url_list = '%s/b2api/v1/b2_list_file_names' % \
                   self.authorization_required['apiUrl']
        headers = {'Authorization':
                   self.authorization_required['authorizationToken']}
        while start_file_name:
            if start_file_name and start_file_name is not True:
                body = {'bucketId': bucket_id,
                        'startFileName': start_file_name}
            else:
                body = {'bucketId': bucket_id}
            result = Requests().get_response_from_request('POST', url_list,
                                                          headers,
                                                          js.dumps(body),
                                                          True)
            start_file_name = result['nextFileName']
            yield result['files']

    def _get_id_file_by_file_name(self, bucket_name, filename):
        generator = self.get_list_file_names(bucket_name)
        for chunk_list in generator:
            for file_info in chunk_list:
                if file_info['fileName'] == filename:
                    return file_info['fileId']
        return None

    def _delete_file_version(self, file_id, filename):
        headers = {'Authorization':
                   self.authorization_required['authorizationToken']}
        body = {'fileId': file_id, 'fileName': filename}
        url_delete = '%s/b2api/v1/b2_delete_file_version' % \
                     self.authorization_required['apiUrl']
        return Requests().get_response_from_request('POST', url_delete,
                                                    headers, js.dumps(body),
                                                    True)

    @property
    def authorization_token(self):
        return self.authorization_required

    def get_list_buckets(self):
        return self._recover_list_buckets_token()

    def get_list_file_names_by_bucket_id(self, bucket_id):
        generator = self._list_file_names(bucket_id)
        for i in generator:
            yield i

    def get_list_file_names(self, bucket_name):
        bucket_id = self._recover_bucket_id_backblaze(bucket_name)
        generator = self.get_list_file_names_by_bucket_id(bucket_id)
        for i in generator:
            yield i

    def _get_upload_token_by_bucket_name(self, bucket_name):
        bucket_id = self._recover_bucket_id_backblaze(bucket_name)
        return self._get_upload_token(bucket_id)

    def upload(self, bucket_name, meta, data, sha1=None):
        if not self.upload_token:
            self.upload_token = self._get_upload_token_by_bucket_name(
                bucket_name)
        if not sha1:
            sha1 = _get_sha1(data)
        result = self._recover_upload_file(meta, data, sha1)
        return result

    def upload_part_begin(self, bucket_name, meta):
        bucket_id = self._recover_bucket_id_backblaze(bucket_name)
        return self._begin_big_file(bucket_id, meta)

    def upload_part(self, file_id, data, part_number, sha1=None):
        if not self.upload_part_token:
            self.upload_part_token = self. _get_upload_part_token(file_id)
        if not sha1:
            sha1 = _get_sha1(data)
        result = self._recover_upload_part_file(data, sha1, part_number)
        return (result, sha1)

    def upload_part_end(self, file_id, sha1_array):
        return self._end_big_file(file_id, sha1_array)

    def download_by_path_name(self, bucket_name, link, headers=None):
        return self._download_backblaze(bucket_name, link, headers)

    def download(self, bucket_name, metadata, headers=None):
        link = _recover_true_path(metadata, metadata['name'])
        return self.download_by_path_name(bucket_name, link, headers)

    def get_backblaze_infos(self, bucket_name):
        res = self.get_list_file_names(bucket_name)
        size = 0
        number = 0
        for chunk_list in res:
            for file_info in chunk_list:
                size = file_info['size'] + size
                number = number + 1
        return (size, number)

    def get_file_number(self, bucket_name):
        res = self.get_list_file_names(bucket_name)
        size = 0
        for chunk_list in res:
            for file_info in chunk_list:
                size = size + 1
        return size

    def get_size(self, bucket_name):
        res = self.get_list_file_names(bucket_name)
        size = 0
        for chunk_list in res:
            for file_info in chunk_list:
                size = file_info['size'] + size
        return size

    def delete(self, bucket_name, metadata):
        filename = _recover_true_path(metadata, metadata['name'])
        file_id = self._get_id_file_by_file_name(bucket_name, filename)
        return self.delete_by_path_name(file_id, filename)

    def delete_by_path_name(self, file_id, file_name):
        return self._delete_file_version(file_id, file_name)


class Requests(object):
    def __init__(self, error_handler=None):
        self.error_handler = error_handler

    def _get_json_response(self, content_type, url, headers, file_descriptor):
        response = self._get_response(content_type, url, headers,
                                      file_descriptor)

        if response is not None:
            return response.json()
        return None

    def _get_response(self, content_type, url, headers, file_descriptor):
        s = Session()
        response = None
        headers = dict([k, str(headers[k])] for k in headers)
        req = Request(content_type, url, headers=headers, data=file_descriptor)
        prepared = req.prepare()
        try:
            response = s.send(prepared)
        except exceptions.Timeout:
            raise
        except exceptions.TooManyRedirects:
            raise
        except exceptions.RequestException:
            raise
        if (response.status_code / 100) != 2:
            try:
                raise BackblazeException(response.status_code,
                                         response.json()['message'],
                                         response,
                                         headers)
            except ValueError:
                raise BackblazeException(response.status_code,
                                         response.text,
                                         response,
                                         headers)
        return response

    def get_response_from_request(self, content_type, url, headers=None,
                                  file_descriptor=None, json=False):
        header = headers or {}
        if json:
            return self._get_json_response(content_type, url,
                                           header, file_descriptor)
        return self._get_response(content_type, url,
                                  header, file_descriptor).content


class BackblazeUtilsException(Exception):
    def __init__(self, string):
        self._string = string

    def __str__(self):
        return self._string


class BackblazeException(Exception):
    def __init__(self, status_code, message, response, headers_send):
        super(BackblazeException, self).__init__()
        self._status_code = status_code
        self._message = message
        self._response = response
        self._headers_send = headers_send

    def __str__(self):
        return '(%d) %s' % (self.status_code, self.message)

    @property
    def status_code(self):
        return self._status_code

    @property
    def message(self):
        return self._message

    @property
    def headers_send(self):
        return self._headers_send

    @property
    def headers_received(self):
        return self._response.headers
