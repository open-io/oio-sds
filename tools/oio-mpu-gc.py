#!/usr/bin/env python

# oio-mpu-gc.py
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

from __future__ import print_function
import argparse
import json
import logging
from time import time
import sys

from oio.api.object_storage import ObjectStorageApi
from oio.common.exceptions import NoSuchContainer, NoSuchObject

DELETE = "DEL"
KEEP = "KEEP"

NS = "OPENIO"


def container_list(cnx, account, **kwargs):
    """ full list of container """
    listing = cnx.container_list(
        account, **kwargs)
    for element in listing:
        yield element

    while listing:
        kwargs['marker'] = listing[-1][0]
        listing = cnx.container_list(
            account, **kwargs)
        if listing:
            for element in listing:
                yield element


def object_list(cnx, account, container, **kwargs):
    """ full list of objects """
    try:
        listing = cnx.object_list(
            account, container, **kwargs)
    except NoSuchContainer:
        logging.error("container %s not found", container)
        return
    for element in listing['objects']:
        yield element

    while listing['truncated']:
        kwargs['marker'] = listing['next_marker']
        listing = cnx.object_list(
            account, container, **kwargs)
        for element in listing['objects']:
            yield element


def is_slo_or_missing(props):
    return props and \
            props.get('properties', {}).get('x-static-large-object') == 'True'


def parse_ns(ns, accounts, dryrun=False):
    cnx = ObjectStorageApi(ns)

    if accounts is None:
        accounts = cnx.account_list()
    elif isinstance(accounts, str):
        accounts = [accounts]

    for account in accounts:
        containers = [container[0] for container
                      in container_list(cnx, account)
                      if container[0].endswith('+segments')]

        for container in containers:
            logging.info("Inspect %s container (account %s)",
                         container, account)
            parts = list(object_list(cnx, account, container))
            bucket = container.split('+')[0]

            try:
                props = cnx.container_get_properties(account, bucket)
                if int(props.get('sys.m2.policy.version', 0)) > 1:
                    logging.warn(
                        "skip container %s because versioning is enabled",
                        bucket)
            except NoSuchContainer:
                # TODO(mbo) we should keep info to avoid useless head below
                pass

            mpus = {}
            objects = {}

            for part in parts:
                try:
                    obj, uuid, num = part['name'].rsplit('/', 2)
                    num = int(num)
                except ValueError:
                    logging.info("MPU %s not completed", part['name'])
                    obj, uuid = part['name'].rsplit('/', 1)
                    # check CTIME
                    info = cnx.object_get_properties(account, container,
                                                     part['name'])
                    if int(info['ctime']) < time() - 24 * 3600:
                        logging.warn(
                            "MPU incomplete %s older than 24H, delete",
                            part['name'])
                        mpus[uuid] = DELETE
                    else:
                        logging.warn(
                            "MPU incomplete %s is recent, keep it",
                            part['name'])
                        mpus[uuid] = KEEP

                # MPU UUID is not in cache
                if uuid not in mpus:
                    if obj in objects:
                        info = objects[obj]['metas']
                        logging.debug("use properties cache on %s", obj)
                    else:
                        try:
                            infos = []
                            for props in object_list(cnx, account, bucket,
                                                     prefix=obj, versions=True,
                                                     properties=True):
                                # only perfect matching
                                if props['name'] != obj:
                                    continue

                                # get only manifests
                                if props.get('properties', {}).get(
                                        'x-static-large-object') == 'True':
                                    _, data = cnx.object_fetch(
                                        account, bucket, obj,
                                        version=props['version'])
                                    manifest = json.loads("".join(data))
                                    infos.append(manifest)
                        except NoSuchObject:
                            infos = []
                        objects[obj] = {'metas': infos}

                    if not infos:
                        logging.info("object %s is missing or no more a SLO",
                                     obj)
                        mpus[uuid] = DELETE
                    else:
                        manifest = []
                        for entry in objects[obj]['metas']:
                            if uuid in entry[0]['name']:
                                manifest = entry

                        if not manifest:
                            _, data = cnx.object_fetch(account, bucket, obj)
                            manifest = json.loads("".join(data))
                            objects[obj]['data'] = manifest
                        else:
                            logging.debug("use manifest cache on %s", obj)

                        if int(num) > len(manifest):
                            logging.info(
                                "Part Number for %s is not in manifest range",
                                obj)
                            mpus[uuid] = DELETE
                        elif manifest[num-1]['name'] != '/%s/%s' % \
                                (container, part['name']):
                            logging.info(
                                "Part for %s is no more used in manifest", obj)
                            mpus[uuid] = DELETE
                        else:
                            logging.debug("Part for %s is referenced", obj)
                            mpus[uuid] = KEEP

                logging.info("Part %s: %s", part['name'], mpus[uuid])
                if not dryrun and mpus[uuid] == DELETE:
                    cnx.object_delete(account, container, part['name'])


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
            "-v", "--verbose",
            action="store_true", dest="flag_verbose",
            help="increase output verbosity")

    parser.add_argument(
            "-d", "--dry-run",
            action="store_true", dest="flag_dryrun",
            help="report action that should be taken")

    parser.add_argument(
            "namespace",
            help="namespace to use")

    parser.add_argument(
            "account",
            help="Account to inspect (default: all)",
            nargs="?")

    options = parser.parse_args()

    # Logging configuration
    if options.flag_verbose:
        logging.basicConfig(
            format='%(asctime)s %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S',
            level=logging.DEBUG)
    else:
        logging.basicConfig(
            format='%(asctime)s %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S',
            level=logging.INFO)

    return parse_ns(options.namespace, options.account,
                    options.flag_dryrun)


if __name__ == '__main__':
    sys.exit(main())
