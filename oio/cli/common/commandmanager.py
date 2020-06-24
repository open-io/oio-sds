# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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

from pkg_resources import iter_entry_points
from cliff import commandmanager


class CommandManager(commandmanager.CommandManager):
    def __init__(self, namespace, convert_underscores=True):
        self.group_list = []
        super(CommandManager, self).__init__(namespace, convert_underscores)

    def load_commands(self, namespace):
        self.group_list.append(namespace)
        return super(CommandManager, self).load_commands(namespace)

    def add_command_group(self, group=None):
        if group:
            self.load_commands(group)

    def get_command_groups(self):
        return self.group_list

    def get_command_names(self, group=None):
        group_list = []
        if group is not None:
            for entry_point in iter_entry_points(group):
                cmd_name = (
                    entry_point.name.replace('_', ' ')
                    if self.convert_underscores
                    else entry_point.name
                )
                group_list.append(cmd_name)
            return group_list
        return list(self.commands.keys())
