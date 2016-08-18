# Copyright (C) 2016 OpenIO SAS
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from oio.common.exceptions import SourceReadError, OioException


class CryptographyToolsException(Exception):
    def __init__(self, message):
        super(CryptographyToolsException, self).__init__()
        self._message = message

    def __str__(self):
        return self._message


# This cryptography tool use the Fernet method of the cryptography module
# to work. If this cryptography tool has vuln, change this tool to use the new
# cryptography module.
# the from_crypt_function_to_actual_crypt take into account this possibility
# and can change the encryption of the data
class CryptographyTools(object):
    READ_SIZE = 65536
    BLOCK_SIZE = 128
    VERSION_SIZE = 8
    TIMESTAMP_SIZE = 64
    HMAC_SIZE = 256
    crypt = None

    def __init__(self, key=None):
        if key:
            self.crypt = Fernet(key)

    @staticmethod
    def generate_key():
        return Fernet.generate_key()

    def encrypt(self, message):
        if not self.crypt:
            return message
        try:
            return self.crypt.encrypt(message)
        except TypeError:
            raise CryptographyToolsException("Error cryptography")

    def decrypt(self, cipher):
        if not self.crypt:
            return cipher
        try:
            return self.crypt.decrypt(cipher)
        except TypeError:
            raise CryptographyToolsException('Error cryptography')
        except InvalidToken:
            raise CryptographyToolsException('Invalid Token')

    # if the precedent cryptography system has been compromised
    # this function can be used to passing to the new cryptography system
    def from_crypt_function_to_actual_crypt(self, decrypt, cipher):
        decrypt_content = decrypt(cipher)
        return self.encrypt(decrypt_content)

    def _generate_dict(self, over, bytes_read, ciphered_bytes, content=None):
        """
        generate a dictionnary with some informations,
        see the function read_and encrypt for more details
        """
        return {'over': over,
                'bytes_read': bytes_read,
                'ciphered_bytes': ciphered_bytes,
                'content': content}

    def read_and_encrypt(self, fd, chunk_size, max_bytes_read,
                         fd_out=None, hooks={}):
        """
        Read chunk_size bytes from the fd file_descriptor variable
        Every max_bytes_read of ciphered data, this file yield a dictionnary
        with these parameters:
        - over : the value is true if the read is over
        - bytes_read : the number of bytes read by the function
        - ciphered_bytes : the number of ciphered-bytes read by the function
        - content : if fd_out is None,
                    this dictionnary entry returns the ciphered_content

        WARNING : every fd_out writing is in the responsability
                  of the programmer.
        if you must seek, truncate or others operations, the responsability is
        your own!

        Hooks available:
        - def on_ciphered_data(data) -> new_ciphered_data
        treatment to make with the data encrypted

        - def on_write(data) -> None
        treatment to make with the data written or sended
        """
        bytes_transferred = 0
        file_transferred = 0
        nb_file = 0
        remaining_bytes = None
        content = None if fd_out else b''
        while True:
            if chunk_size:
                remaining_bytes = chunk_size - bytes_transferred
            if remaining_bytes is None or self.READ_SIZE < remaining_bytes:
                read_size = self.READ_SIZE
            else:
                read_size = remaining_bytes
            try:
                data = fd.read(read_size)
            except (ValueError, IOError) as err:
                raise SourceReadError((str(err)))
            if len(data) == 0:
                break

            def _on_ciphered_data(cipher):
                return cipher

            f = hooks.get('on_ciphered_data', _on_ciphered_data)
            cipher = f(self.encrypt(data))

            def _on_write(data):
                pass

            f = hooks.get('on_write', _on_write)
            # if the size is greater than b2_max_file_size,
            # complete the last_file
            # and yield to upload the nb_file part.
            # after the yield, we put the following content inside
            if file_transferred + len(cipher) > max_bytes_read:
                to_write = cipher[:max_bytes_read - file_transferred]
                remains = cipher[max_bytes_read - file_transferred:]
                f(to_write)
                if fd_out:
                    fd_out.write(to_write)
                    fd_out.flush()
                else:
                    content += to_write
                yield self._generate_dict(False, bytes_transferred,
                                          max_bytes_read, content)
                f(remains)
                if fd_out:
                    fd_out.write(remains)
                else:
                    content = remains
                file_transferred = len(remains)
                nb_file += 1
                # else, we just update the data
            else:
                f(cipher)
                if fd_out:
                    fd_out.write(cipher)
                else:
                    content += cipher
                file_transferred += len(cipher)
                bytes_transferred += len(data)
            if fd_out:
                fd_out.flush()
            # False is just the end of the file
            yield self._generate_dict(True, len(data),
                                      file_transferred, content)

    def decrypt_from_stream(self, stream, begin, end, hooks={}):
        """
        decrypt the content of ciphered content in the stream variable

        The function yield every tokens available
        one hook is available :
        def stream_to_tokens(stream) : generator
        -> isolate the fd into multiple tokens to be decrypted
        """
        actual = 0
        token_nb = 0

        def _stream_to_tokens(stream):
            while True:
                content = stream.read(CryptographyTools.READ_SIZE)
                if len(content) == 0:
                    break
                yield content

        f = hooks.get('stream_to_tokens', _stream_to_tokens)
        # recover each sentence (encrypted Token)
        for i in f(stream):
            try:
                # data decryption
                content = self.decrypt(i)
                if begin >= actual or begin <= actual + len(content):
                    if actual <= begin:
                        begin_content = begin - actual
                    else:
                        begin_content = 0
                    if end is not None and end < len(content) + actual:
                        to_yield = content[begin_content: end - actual]
                    else:
                        to_yield = content[begin_content:]
                    yield to_yield
                actual += len(content)
                token_nb += 1
            except CryptographyToolsException as e:
                raise OioException('Cryptography exception: %s' % (str(e)))

    def get_token_size(self, data_size):
        remains_size = (data_size * 8) % self.BLOCK_SIZE
        # size of padding
        encrypt_entire_size = self.BLOCK_SIZE - remains_size + (data_size * 8)
        # BLOCK_SIZE is the size of the IV (initialization vector)
        overhead_size = self.BLOCK_SIZE + self.VERSION_SIZE
        overhead_size += self.TIMESTAMP_SIZE + self.HMAC_SIZE
        return (overhead_size + encrypt_entire_size) / 8

    def is_noop(self):
        return False if self.crypt else True
