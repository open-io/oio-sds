# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
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

from logging import getLogger
from six import iteritems
from cliff import lister
from oio.cli import Command


class ElectionCmdMixin(object):
    """Base class for election subcommands"""

    log = getLogger(__name__ + '.Election')

    def patch_parser(self, parser):
        # TODO(jfs): Add a --cid option that allow iterating on all the
        #            ensembles for just one election
        parser.add_argument('srvtype', metavar='<service_type>',
                            help="Service type")

    def get_params(self, parsed_args):
        ns = self.app.client_manager.zk['ns']
        cnxstr = self.app.client_manager.sds_conf['zookeeper']
        return ns, cnxstr

    def iterate_groups(self, parsed_args, non_leaf=False):
        from oio.zk.client import get_connected_handles, \
            generate_namespace_tree as _run
        ns, cnxstr = self.get_params(parsed_args)
        for zh in get_connected_handles(cnxstr):
            for group in _run(ns, parsed_args.srvtype, non_leaf=non_leaf):
                yield zh.get(), group
            zh.close()

    def _list_nodes(self, zh, path):
        import zookeeper
        path = path.replace('//', '/')
        try:
            children = list(zookeeper.get_children(zh, path))
            if len(children) <= 0:
                return
            for child in children:
                yield child
        except Exception as e:
            self.log.warn("ERROR list %s: %s", path, e)

    def _list_elections(self, zh, path):
        children = list(self._list_nodes(zh, path))
        if len(children) <= 0:
            return
        seen = dict()
        for child in children:
            key, num = child.split('-', 1)
            if key not in seen:
                seen[key] = []
            seen[key].append(num)
        for k, nums in iteritems(seen):
            nums = sorted(nums)
            yield k, nums[0], nums[-1]


class ElectionReset(ElectionCmdMixin, lister.Lister):
    """Mass-reset elections."""

    log = getLogger(__name__ + '.ElectionReset')

    def get_parser(self, prog_name):
        parser = super(ElectionReset, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
                '-s', '--smart',
                action="store_true", dest="SMART", default=False,
                help="Delete duplicate nodes")
        parser.add_argument(
                '--dry-run',
                action="store_true", dest="DRY", default=False,
                help="Do not delete, just print")
        parser.add_argument(
                '--min-services',
                type=int, action="store", dest="MIN", default=4,
                help="Do not delete election if less the NUM")
        parser.add_argument(
                '--alone',
                action="store_true", dest="ALONE", default=False,
                help="Also consider members alone in their group")
        return parser

    def take_action(self, parsed_args):
        columns = ('group', 'node', 'status')
        return columns, self._action_generator(parsed_args)

    def _action_generator(self, parsed_args):
        import zookeeper

        def action(group, node):
            if parsed_args.DRY:
                return group, node, 'Skipped'
            else:
                try:
                    zookeeper.delete(zh, group + '/' + node)
                    return group, node, 'Deleted'
                except Exception as ex:
                    return group, node, str(ex)

        for zh, group in self.iterate_groups(parsed_args):
            children = list(self._list_nodes(zh, group))
            if len(children) <= 0:
                continue
            if parsed_args.ALONE and 1 == len(children):
                yield action(group, children[0])
            elif parsed_args.MIN > len(children):
                for node in children:
                    yield group, node, 'Too few nodes'
            elif parsed_args.SMART:
                children.sort()
                # check for services registered several times
                group = {}
                for child in children:
                    n = group + '/' + child
                    data, meta = tuple(zookeeper.get(zh, n))
                    print(repr(data), repr(meta))
                    if data in group:
                        # Mark the oldest nodes for removal
                        yield action(group, group[data])
                    group[data] = child
            else:
                # systematical removal
                for child in children:
                    yield action(group, child)


class ElectionStat(ElectionCmdMixin, lister.Lister):
    """Dump election nodes."""

    log = getLogger(__name__ + '.ElectionStat')

    def get_parser(self, prog_name):
        parser = super(ElectionStat, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        columns = ('group', 'member', 'size', 'value')
        return columns, self._action_generator(parsed_args)

    def _action_generator(self, parsed_args):
        import zookeeper
        for zh, group in self.iterate_groups(parsed_args):
            children = list(self._list_nodes(zh, group))
            for child in children:
                n = group + '/' + child
                value, meta = tuple(zookeeper.get(zh, n))
                yield group, child, meta['dataLength'], repr(value)


class ElectionSmudge(ElectionCmdMixin, lister.Lister):
    """Putrefies elections with the addition of fake nodes."""

    log = getLogger(__name__ + '.ElectionSmudge')

    def get_parser(self, prog_name):
        parser = super(ElectionSmudge, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument('--value', metavar='<VALUE>', type=str, default='',
                            help="content of the Zookeeper node")
        return parser

    def take_action(self, parsed_args):
        columns = ('group', 'member', 'status')
        return columns, self._action_generator(parsed_args)

    def _action_generator(self, parsed_args):
        import zookeeper
        from oio.zk.client import _acl_openbar
        for zh, group in self.iterate_groups(parsed_args):
            for key, first, last in self._list_elections(zh, group):
                tail = str(1+int(last)).rjust(10, '0')
                suffix = key + '-' + tail
                path = group + '/' + suffix
                try:
                    zookeeper.create(zh, path, parsed_args.value,
                                     _acl_openbar, 0)
                    yield group, suffix, "OK"
                except Exception as ex:
                    yield group, suffix, str(ex)


class HierarchyArmageddon(ElectionCmdMixin, Command):
    """Remove the hierarchy tree in the Zookeeper ensembles"""

    log = getLogger(__name__ + '.HierarchyArmageddon')

    def get_parser(self, prog_name):
        parser = super(HierarchyArmageddon, self).get_parser(prog_name)
        # JFS: No patching
        parser.add_argument(
                "--fuck-the-world",
                dest='yeah', action='store_true', default=False,
                help="I am very sure I want to fuck my Zookeeper up")
        return parser

    def take_action(self, parsed_args):
        ns, cnxstr = self.get_params(parsed_args)
        if not parsed_args.yeah:
            self.log.warn("This action on [%s] requires iron bollocks.", ns)
            return
        from oio.zk.client import get_connected_handles, delete_children
        for zh in get_connected_handles(cnxstr):
            try:
                delete_children(zh.get(), ns, self.log)
            except Exception as ex:
                self.log.exception("Failed to flush '%s': %s",
                                   zh.cnxstr, str(ex))
                self.__class__.success = False
            finally:
                zh.close()


class HierarchyBootstrap(ElectionCmdMixin, Command):
    """Create the election tree in the Zookeeper ensembles."""

    log = getLogger(__name__ + '.HierarchyArmageddon')

    def get_parser(self, prog_name):
        parser = super(HierarchyBootstrap, self).get_parser(prog_name)
        # JFS: No patching
        parser.add_argument(
                "--slow",
                dest='slow', action='store_true', default=False,
                help="Create with small batches")
        parser.add_argument(
                "--lazy",
                dest='lazy', action='store_true', default=False,
                help="Only create if there is no clue of existing NS")
        return parser

    def take_action(self, parsed_args):
        # Adapt the batch size for slow ZK
        batch_size = 2048
        if parsed_args.slow:
            batch_size = 8
        # Send a bootstrap on each ensemble
        ns, cnxstr = self.get_params(parsed_args)
        from oio.zk.client import get_connected_handles, create_namespace_tree
        for zh in get_connected_handles(cnxstr):
            try:
                create_namespace_tree(zh.get(), ns, self.log,
                                      batch_size=batch_size,
                                      precheck=parsed_args.lazy)
            except Exception as ex:
                self.log.exception("Failed to bootstrap '%s': %s",
                                   zh.cnxstr, ex)
                self.__class__.success = False
            finally:
                zh.close()
