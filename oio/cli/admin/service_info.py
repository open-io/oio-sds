# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


from cliff import show

from oio.cli.admin.common import SingleServiceCommandMixin


def _flat_dict_from_dict(parsed_args, dict_):
    """
    Create a dictionary without depth.

    {
        'depth0': {
            'depth1': {
                'depth2': 'test'
            }
        }
    }
    =>
    {
        'depth0.depth1.depth2': 'test'
    }
    """
    flat_dict = dict()
    for key, value in dict_.items():
        if not isinstance(value, dict):
            if isinstance(value, list) and parsed_args.formatter == 'table':
                value = '\n'.join(value)
            flat_dict[key] = value
            continue

        _flat_dict = _flat_dict_from_dict(parsed_args, value)
        for _key, _value in _flat_dict.items():
            flat_dict[key + '.' + _key] = _value
    return flat_dict


class ServiceInfo(SingleServiceCommandMixin, show.ShowOne):
    """
    Get all information from the specified service.

    Works on all services using ASN.1 protocol except conscience
    (meta0, meta1, meta2, sqlx).
    """

    @property
    def logger(self):
        return self.app.client_manager.logger

    def get_parser(self, prog_name):
        parser = super(ServiceInfo, self).get_parser(prog_name)
        SingleServiceCommandMixin.patch_parser(self, parser)
        return parser

    def take_action(self, parsed_args):
        SingleServiceCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        self.logger.debug('take_action(%s)', parsed_args)

        conf = self.app.client_manager.admin.service_get_info(
            parsed_args.service)
        return zip(*sorted(_flat_dict_from_dict(parsed_args, conf).items()))
