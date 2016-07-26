import io
import logging
import os

from cliff import command

from oio.cli.utils import KeyValueAction
from oio.common.cryptography_tools import CryptographyTools

class GenerateEncryptionKey(command.Command):
    """Generate an Encryption Key"""

    log = logging.getLogger(__name__ + '.GenerateEncryptionKey')

    def get_parser(self, prog_name):
        parser = super(GenerateEncryptionKey, self).get_parser(prog_name)
        return parser

    def take_action(self, parsed_args):
        print CryptographyTools.generate_key()

