# Copyright (C) 2018-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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

from logging import getLogger
from cliff import lister
from oio.cli import Command


class ElectionCmdMixin(object):
    """Base class for election subcommands"""

    log = getLogger(__name__ + ".Election")

    def patch_parser(self, parser):
        # TODO(jfs): Add a --cid option that allow iterating on all the
        #            ensembles for just one election
        parser.add_argument("srvtype", metavar="<service_type>", help="Service type")

    def get_params(self, parsed_args):
        ns = self.app.client_manager.zk["ns"]
        cnxstr = self.app.client_manager.sds_conf["zookeeper"]
        return ns, cnxstr

    def iterate_groups(self, parsed_args, non_leaf=False):
        from oio.zk.client import get_connected_handles, generate_namespace_tree as _run

        ns, cnxstr = self.get_params(parsed_args)
        for zh in get_connected_handles(cnxstr, logger=self.log):
            for group in _run(ns, parsed_args.srvtype, non_leaf=non_leaf):
                yield zh.get(), group
            zh.close()

    def _list_nodes(self, zh, path):
        path = path.replace("//", "/")
        try:
            children = list(zh.get_children(path))
            if len(children) <= 0:
                return
            for child in children:
                yield child
        except Exception as e:
            self.log.warning("ERROR list %s: %s", path, e)

    def _list_elections(self, zh, path):
        children = list(self._list_nodes(zh, path))
        if len(children) <= 0:
            return
        seen = {}
        for child in children:
            key, num = child.split("-", 1)
            if key not in seen:
                seen[key] = []
            seen[key].append(num)
        for k, nums in seen.items():
            nums = sorted(nums)
            yield k, nums[0], nums[-1]


class ElectionReset(ElectionCmdMixin, lister.Lister):
    """Crawl elections and reset them when they seem broken."""

    log = getLogger(__name__ + ".ElectionReset")

    def get_parser(self, prog_name):
        parser = super(ElectionReset, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            "-s",
            "--smart",
            action="store_true",
            dest="SMART",
            default=False,
            help="Delete duplicate nodes",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            dest="DRY",
            default=False,
            help="Do not delete, just print",
        )
        parser.add_argument(
            "--min-services",
            type=int,
            action="store",
            dest="MIN",
            default=4,
            help="Do not reset election if less than MIN (default: 4)",
        )
        parser.add_argument(
            "--alone",
            action="store_true",
            dest="ALONE",
            default=False,
            help="Also consider members alone in their group",
        )
        return parser

    def take_action(self, parsed_args):
        columns = ("group", "node", "status")
        return columns, self._action_generator(parsed_args)

    def _action_generator(self, parsed_args):
        def action(group, node):
            if parsed_args.DRY:
                return group, node, "Skipped"
            else:
                try:
                    zh.delete(group + "/" + node)
                    return group, node, "Deleted"
                except Exception as ex:
                    return group, node, str(ex)

        for zh, group in self.iterate_groups(parsed_args):
            children = list(self._list_nodes(zh, group))
            if len(children) <= 0:
                continue
            if parsed_args.ALONE and len(children) == 1:
                yield action(group, children[0])
            elif len(children) < parsed_args.MIN:
                for node in children:
                    yield group, node, "Nothing to do"
            elif parsed_args.SMART:
                children.sort()
                # check for services registered several times
                node_for_svc = {}
                for child in children:
                    n = group + "/" + child
                    svc, node_stat = zh.get(n)
                    if svc is not None:
                        svc = svc.decode("utf-8")
                    print(repr(svc), repr(node_stat))
                    if svc in node_for_svc:
                        # Mark the oldest nodes for removal
                        yield action(group, node_for_svc[svc])
                    node_for_svc[svc] = child
                if len(node_for_svc) >= parsed_args.MIN:
                    self.log.warning(
                        "More than %d nodes in group %s", parsed_args.MIN - 1, group
                    )
                for node in node_for_svc.values():
                    parts = node.split("-", 1)
                    if len(parts) < 2:
                        self.log.warning("Node %s has no sequence number", node)
                        yield action(group, node)
                    elif len(parts[1]) > 10:
                        self.log.warning(
                            "Node %s has unexpectedly long sequence number", node
                        )
                        yield action(group, node)
                    else:
                        yield group, node, "Nothing to do"
            else:
                # systematical removal
                for child in children:
                    yield action(group, child)


class ElectionStat(ElectionCmdMixin, lister.Lister):
    """Dump election nodes."""

    log = getLogger(__name__ + ".ElectionStat")

    def get_parser(self, prog_name):
        parser = super(ElectionStat, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        columns = ("group", "member", "size", "value")
        return columns, self._action_generator(parsed_args)

    def _action_generator(self, parsed_args):
        for zh, group in self.iterate_groups(parsed_args):
            children = list(self._list_nodes(zh, group))
            for child in children:
                n = group + "/" + child
                addr, node_stat = zh.get(n)
                if addr is not None:
                    addr = addr.decode("utf-8")
                yield group, child, node_stat.data_length, repr(addr)


class ElectionSmudge(ElectionCmdMixin, lister.Lister):
    """Putrefies elections with the addition of fake nodes."""

    log = getLogger(__name__ + ".ElectionSmudge")

    def get_parser(self, prog_name):
        parser = super(ElectionSmudge, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            "--value",
            metavar="<VALUE>",
            type=str,
            default="",
            help="content of the Zookeeper node",
        )
        return parser

    def take_action(self, parsed_args):
        columns = ("group", "member", "status")
        return columns, self._action_generator(parsed_args)

    def _action_generator(self, parsed_args):
        from oio.zk.client import _acl_openbar

        for zh, group in self.iterate_groups(parsed_args):
            for key, _, last in self._list_elections(zh, group):
                tail = str(1 + int(last)).rjust(10, "0")
                suffix = key + "-" + tail
                path = group + "/" + suffix
                value = parsed_args.value.encode("utf-8")
                try:
                    zh.create(path, value=value, acl=_acl_openbar)
                    yield group, suffix, "OK"
                except Exception as ex:
                    yield group, suffix, str(ex)


class HierarchyArmageddon(ElectionCmdMixin, Command):
    """Remove the hierarchy tree in the Zookeeper ensembles"""

    log = getLogger(__name__ + ".HierarchyArmageddon")

    def get_parser(self, prog_name):
        parser = super(HierarchyArmageddon, self).get_parser(prog_name)
        # JFS: No patching
        parser.add_argument(
            "--fuck-the-world",
            dest="yeah",
            action="store_true",
            default=False,
            help="I am very sure I want to fuck my Zookeeper up",
        )
        return parser

    def take_action(self, parsed_args):
        ns, cnxstr = self.get_params(parsed_args)
        if not parsed_args.yeah:
            self.log.warn("This action on [%s] requires iron bollocks.", ns)
            return
        from oio.zk.client import get_connected_handles, delete_children

        for zh in get_connected_handles(cnxstr, logger=self.log):
            try:
                delete_children(zh.get(), ns, self.log)
            except Exception as ex:
                self.log.exception("Failed to flush '%s': %s", zh.cnxstr, str(ex))
                self.__class__.success = False
            finally:
                zh.close()


class HierarchyBootstrap(ElectionCmdMixin, Command):
    """Create the election tree in the Zookeeper ensembles."""

    log = getLogger(__name__ + ".HierarchyArmageddon")

    def get_parser(self, prog_name):
        parser = super(HierarchyBootstrap, self).get_parser(prog_name)
        # JFS: No patching
        parser.add_argument(
            "--slow",
            dest="slow",
            action="store_true",
            default=False,
            help="Create with small batches",
        )
        parser.add_argument(
            "--lazy",
            dest="lazy",
            action="store_true",
            default=False,
            help="Only create if there is no clue of existing NS",
        )
        return parser

    def take_action(self, parsed_args):
        # Adapt the batch size for slow ZK
        batch_size = 2048
        if parsed_args.slow:
            batch_size = 8
        # Send a bootstrap on each ensemble
        ns, cnxstr = self.get_params(parsed_args)
        from oio.zk.client import get_connected_handles, create_namespace_tree

        for zh in get_connected_handles(cnxstr, logger=self.log):
            try:
                create_namespace_tree(
                    zh.get(),
                    ns,
                    self.log,
                    batch_size=batch_size,
                    precheck=parsed_args.lazy,
                )
            except Exception as ex:
                self.log.exception("Failed to bootstrap '%s': %s", zh.cnxstr, ex)
                self.__class__.success = False
            finally:
                zh.close()
