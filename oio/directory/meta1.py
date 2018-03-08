# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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

"""Meta1 client and meta2 balancing operations"""
from oio.directory.meta import MetaMapping
from oio.common.exceptions import OioException
from oio.directory.client import DirectoryClient


class Meta1RefMapping(MetaMapping):
    """Represents the content of the meta1 database"""

    def __init__(self, namespace, directory_client=None, **kwargs):
        super(Meta1RefMapping, self).__init__(
            {'namespace': namespace}, ['meta2', 'sqlx'], **kwargs)
        self._reference = directory_client
        self.service_type_by_base = dict()
        self.args_by_base = dict()

    def _get_old_peers_by_base(self, base):
        return self.raw_services_by_base.get(base, list())

    def _get_peers_by_base(self, base):
        return self.services_by_base.get(base, dict()).keys()

    def _get_service_type_by_base(self, base):
        return self.service_type_by_base.get(base, None)

    def _get_args_by_base(self, base):
        return self.args_by_base.get(base, None)

    def _apply_link_services(self, moved_ok, **kwargs):
        for base in moved_ok:
            peers = self._get_peers_by_base(base)
            service_type = self._get_service_type_by_base(base)
            args = self._get_args_by_base(base)
            cid, seq = self.get_cid_and_seq(base)

            try:
                self.reference.force(
                    service_type=service_type, cid=cid,  replace=True,
                    services=dict(host=','.join(peers), type=service_type,
                                  args=args, seq=seq))
            except OioException as exc:
                self.logger.warn(
                    "Failed to link services for base %s (seq=%d): %s",
                    cid, seq, exc)

    @property
    def reference(self):
        if not self._reference:
            self._reference = DirectoryClient(self.conf)
        return self._reference

    def _service_id(self, service, service_type):
        return self.conf['namespace'] + "|" + service_type + "|" + service

    def _conscience_poll(self, service_type, known, avoid, **kwargs):
        try:
            services_found = self.conscience.poll(
                service_type,
                known=[self._service_id(svc, service_type) for svc in known],
                avoid=[self._service_id(svc, service_type) for svc in avoid])
            return [svc['addr'] for svc in services_found]
        except OioException as exc:
            self.logger.warn(
                "Failed to poll services (type=%s, known=%s, avoid=%s): %s",
                service_type, known, avoid, exc)
            return list()

    def move(self, src_service, dest_service, base_name, service_type,
             **kwargs):
        """
        Move a `base` of `src_service` to `dest_service`
        """
        if service_type not in self.services_by_service_type.keys():
            raise ValueError(
                "service type must be %s"
                % " or ".join(self.services_by_service_type.keys()))
        cid, seq = self.get_cid_and_seq(base_name)

        data = self.reference.list(cid=cid)
        if dest_service is not None and dest_service not in \
                self.services_by_service_type[service_type].keys():
            raise ValueError(
                "destination service must be a %s service" % service_type)

        bases = dict()
        for service in data['srv']:
            if service['type'] != service_type:
                continue
            if seq is not None and seq != service['seq']:
                continue
            base = cid + "." + str(service['seq'])
            raw_services = bases.get(base, None)
            if raw_services is None:
                raw_services = dict()
                bases[base] = raw_services
            host = service['host']
            service.pop('host', None)
            raw_services[host] = service

        moved = set()
        for base, raw_services in bases.iteritems():
            old_peers = raw_services.keys()
            if src_service not in old_peers:
                continue
            src_info = raw_services.pop(src_service)
            if dest_service is None:
                known = raw_services.keys()
                services_found = self._conscience_poll(
                    service_type, known, [src_service], **kwargs)
                if not services_found:
                    self.logger.warn(
                        "No destination service found %s (seq=%d)", cid, seq)
                dest_service = services_found[0]
            elif dest_service in old_peers:
                continue
            raw_services[dest_service] = src_info
            moved.add(base)
            self.raw_services_by_base[base] = old_peers
            self.services_by_base[base] = raw_services
            self.service_type_by_base[base] = service_type
            self.args_by_base[base] = src_info['args']

        if not moved:
            raise ValueError(
                "source service isn't used "
                "or destination service is already used for this base")
        return moved
