import pkg_resources
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
            for entry_point in pkg_resources.iter_entry_points(group):
                cmd_name = (
                    entry_point.name.replace('_', ' ')
                    if self.convert_underscores
                    else entry_point.name
                )
                group_list.append(cmd_name)
            return group_list
        return self.commands.keys()
