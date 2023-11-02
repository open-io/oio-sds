# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2023 OVH SAS
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

from oio.cli import Command, Lister, ShowOne


class ListReference(Lister):
    """List services linked to a reference."""

    log = getLogger(__name__ + ".ListReference")

    def get_parser(self, prog_name):
        parser = super(ListReference, self).get_parser(prog_name)
        parser.add_argument(
            "reference", metavar="<reference>", help="Reference to list"
        )
        parser.add_argument(
            "--cid",
            dest="is_cid",
            help="Interpret <reference> as a CID",
            action="store_true",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        if parsed_args.is_cid:
            data = self.app.client_manager.reference.list(cid=parsed_args.reference)
        else:
            data = self.app.client_manager.reference.list(
                self.app.client_manager.account, reference=parsed_args.reference
            )
        columns = ("Type", "Host", "Args", "Seq")
        results = ((d["type"], d["host"], d["args"], d["seq"]) for d in data["srv"])
        return columns, results


class ShowReference(ShowOne):
    """Show reference properties."""

    log = getLogger(__name__ + ".ShowReference")

    def get_parser(self, prog_name):
        parser = super(ShowReference, self).get_parser(prog_name)
        parser.add_argument(
            "reference", metavar="<reference>", help="Reference to show"
        )
        parser.add_argument(
            "--cid",
            dest="is_cid",
            help="Interpret <reference> as a CID",
            action="store_true",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        if parsed_args.is_cid:
            data = self.app.client_manager.reference.list(cid=parsed_args.reference)
            account = data.get("account")
            reference = data.get("name")
        else:
            account = self.app.client_manager.account
            reference = parsed_args.reference

        data = self.app.client_manager.reference.get_properties(account, reference)
        info = {"account": account, "name": reference, "cid": data.get("cid", None)}
        for k, v in data["properties"].items():
            info["meta." + k] = v
        return list(zip(*sorted(info.items())))


class CreateReference(Lister):
    """
    Create one or several references.
    """

    log = getLogger(__name__ + ".CreateReference")

    def get_parser(self, prog_name):
        parser = super(CreateReference, self).get_parser(prog_name)
        parser.add_argument(
            "references",
            metavar="<reference>",
            nargs="+",
            help="Reference(s) to create",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        results = []
        account = self.app.client_manager.account
        for reference in parsed_args.references:
            created = self.app.client_manager.reference.create(
                account, reference=reference
            )
            results.append((reference, created))

        return ("Name", "Created"), (r for r in results)


class DeleteReference(Command):
    """
    Delete one or several references.

    A reference must be empty before being deleted.
    """

    log = getLogger(__name__ + ".DeleteReference")

    def get_parser(self, prog_name):
        parser = super(DeleteReference, self).get_parser(prog_name)
        parser.add_argument(
            "references",
            metavar="<reference>",
            nargs="+",
            help="Reference(s) to delete",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        for reference in parsed_args.references:
            self.app.client_manager.reference.delete(
                self.app.client_manager.account, reference=reference
            )


class LinkReference(Command):
    """Link services to a reference."""

    log = getLogger(__name__ + ".LinkReference")

    def get_parser(self, prog_name):
        parser = super(LinkReference, self).get_parser(prog_name)
        parser.add_argument(
            "reference", metavar="<reference>", help="Reference to update"
        )
        parser.add_argument(
            "srv_type",
            metavar="<srv_type>",
            help="Link services of type <srv_type> to the reference",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        reference = parsed_args.reference
        srv_type = parsed_args.srv_type

        self.app.client_manager.reference.link(
            self.app.client_manager.account, reference, srv_type
        )


class UnlinkReference(Command):
    """Unlink services from a reference."""

    log = getLogger(__name__ + ".UnlinkReference")

    def get_parser(self, prog_name):
        parser = super(UnlinkReference, self).get_parser(prog_name)
        parser.add_argument(
            "reference", metavar="<reference>", help="Reference to unlink"
        )
        parser.add_argument(
            "srv_type",
            metavar="<srv_type>",
            help="Unlink services of <srv_type> from the reference",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        reference = parsed_args.reference
        srv_type = parsed_args.srv_type

        self.app.client_manager.reference.unlink(
            self.app.client_manager.account, reference, srv_type
        )


class PollReference(Command):
    """
    Poll (renew) services for a reference.

    Assign a new set of services to the reference,
    increment the sequence number.
    """

    log = getLogger(__name__ + ".PollReference")

    def get_parser(self, prog_name):
        parser = super(PollReference, self).get_parser(prog_name)
        parser.add_argument(
            "reference", metavar="<reference>", help="Reference to poll"
        )
        parser.add_argument(
            "srv_type", metavar="<srv_type>", help="Poll services of type <srv_type>"
        )
        return parser

    def take_action(self, parsed_args):
        reference = parsed_args.reference
        srv_type = parsed_args.srv_type

        self.app.client_manager.reference.renew(
            self.app.client_manager.account, reference, srv_type
        )


class ForceReference(Command):
    """
    Force link a service to reference.

    In order to keep the same sequence number,
    you must first unlink the service.
    """

    log = getLogger(__name__ + ".ForceReference")

    def get_parser(self, prog_name):
        parser = super(ForceReference, self).get_parser(prog_name)
        parser.add_argument(
            "reference", metavar="<reference>", help="Reference to update"
        )
        parser.add_argument(
            "host", metavar="<host>", help="Service hosts (separated by ',')"
        )
        parser.add_argument("type", metavar="<type>", help="Service type")
        parser.add_argument(
            "--seq",
            metavar="<seq>",
            default=1,
            type=int,
            help="Service sequence number",
        )
        parser.add_argument("--args", metavar="<args>", default="", help="Service args")
        parser.add_argument(
            "--replace",
            dest="replace",
            default=False,
            help=(
                "Do not require the list of services of the specified "
                "type to be empty, replace it. By default, refuse to "
                "overwrite."
            ),
            action="store_true",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        reference = parsed_args.reference
        service = dict(
            host=parsed_args.host,
            type=parsed_args.type,
            args=parsed_args.args,
            seq=parsed_args.seq,
        )

        self.app.client_manager.reference.force(
            self.app.client_manager.account,
            reference,
            parsed_args.type,
            service,
            replace=parsed_args.replace,
        )


class SetReference(Command):
    """Set reference properties."""

    log = getLogger(__name__ + ".SetReference")

    def get_parser(self, prog_name):
        from oio.cli.common.utils import KeyValueAction

        parser = super(SetReference, self).get_parser(prog_name)
        parser.add_argument(
            "reference", metavar="<reference>", help="Reference to modify"
        )
        parser.add_argument(
            "--property",
            metavar="<key=value>",
            action=KeyValueAction,
            help="Property to add/update for this reference",
        )
        parser.add_argument(
            "--clear",
            dest="clear",
            default=False,
            help="Clear previous properties",
            action="store_true",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        self.app.client_manager.reference.set_properties(
            self.app.client_manager.account,
            parsed_args.reference,
            parsed_args.property,
            parsed_args.clear,
        )


class UnsetReference(Command):
    """Unset reference properties."""

    log = getLogger(__name__ + ".UnsetReference")

    def get_parser(self, prog_name):
        parser = super(UnsetReference, self).get_parser(prog_name)
        parser.add_argument(
            "reference", metavar="<reference>", help="Reference to modify"
        )
        parser.add_argument(
            "--property",
            metavar="<key>",
            action="append",
            default=[],
            help="Property to remove from reference",
            required=True,
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        self.app.client_manager.reference.del_properties(
            self.app.client_manager.account, parsed_args.reference, parsed_args.property
        )


class LocateReference(ShowOne):
    """Locate the services in charge of a reference."""

    log = getLogger(__name__ + ".LocateReference")

    def get_parser(self, prog_name):
        parser = super(LocateReference, self).get_parser(prog_name)
        parser.add_argument(
            "reference", metavar="<reference>", help="Reference to locate"
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        account = self.app.client_manager.account
        reference = parsed_args.reference

        data = self.app.client_manager.reference.list(account, reference)

        info = {
            "account": account,
            "name": reference,
            "cid": data.get("cid"),
            "meta0": [],
            "meta1": [],
        }
        for svc in data["dir"]:
            if svc["type"] == "meta0":
                info["meta0"].append(svc["host"])
            elif svc["type"] == "meta1":
                info["meta1"].append(svc["host"])

        for srv_type in ["meta0", "meta1"]:
            info[srv_type] = ", ".join(h for h in info[srv_type])

        return list(zip(*sorted(info.items())))
