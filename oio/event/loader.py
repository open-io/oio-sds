# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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


import os
import re
import pkg_resources
from six.moves import configparser


DEFAULT_HANDLER = 'egg:oio#default'

_loaders = {}


class _Type(object):
    name = None
    egg_protocols = None

    def invoke(self, ctx, **kwargs):
        pass


class _Handler(_Type):
    name = 'handler'
    egg_protocols = ['oio.event.handler_factory']
    config_prefixes = ['handler']

    def invoke(self, context, **kwargs):
        if context.protocol == 'oio.event.handler_factory':
            app = kwargs.pop('app')
            return context.object(
                app, context.global_conf, **context.local_conf)
        else:
            assert 0, 'Protocol %r unknown' % context.protocol


HANDLER = _Handler()


class _Filter(_Type):
    name = 'filter'
    egg_protocols = ['oio.event.filter_factory']
    config_prefixes = ['filter']

    def invoke(self, context, **kwargs):
        if context.protocol == 'oio.event.filter_factory':
            return context.object(context.global_conf, **context.local_conf)
        else:
            assert 0, 'Protocol %r unknown' % context.protocol


FILTER = _Filter()


class _Pipeline(_Type):
    name = 'pipeline'

    def invoke(self, context, **kwargs):
        app = context.handler_context.create(**kwargs)
        filters = [c.create(**kwargs) for c in context.filter_contexts]
        filters.reverse()
        for filter_ in filters:
            app = filter_(app)
        return app


PIPELINE = _Pipeline()


def loadhandlers(path, global_conf=None, **kwargs):
    loader = ConfigLoader(path)
    handlers = {}
    handlers.update(
        (name[8:], loadhandler(loader, name[8:], global_conf, **kwargs))
        for name in loader.get_sections(prefix="handler")
    )
    return handlers


def loadhandler(loader, name, global_conf=None, **kwargs):
    context = loader.get_context(HANDLER, name, global_conf)
    return context.create(**kwargs)


def loadcontext(obj_type, uri, name=None, global_conf=None):
    if '#' in uri:
        if name is None:
            uri, name = uri.split('#', 1)
        else:
            uri = uri.split('#', 1)[0]
    if ':' not in uri:
        raise LookupError("URI scheme invalid %r" % uri)
    scheme, path = uri.split(':', 1)
    scheme = scheme.lower()
    if scheme not in _loaders:
        raise LookupError('URI scheme unknown: %r' % scheme)
    return _loaders[scheme](
        obj_type, uri, path, name=name, global_conf=global_conf)


def _loadegg(obj_type, uri, spec, name, global_conf):
    loader = EggLoader(spec)
    return loader.get_context(obj_type, name, global_conf)


_loaders['egg'] = _loadegg


class _Loader(object):
    pass


class CustomConfigParser(configparser.ConfigParser):
    def __init__(self, filename, *args, **kwargs):
        configparser.ConfigParser.__init__(self, *args, **kwargs)
        self.filename = filename


class ConfigLoader(object):
    def __init__(self, filename):
        self.filename = filename = filename.strip()
        defaults = {
                '__file__': os.path.abspath(filename)}
        self.parser = CustomConfigParser(filename, defaults=defaults)
        self.parser.optionxform = str
        with open(filename) as f:
            self.parser.readfp(f)

    _absolute_re = re.compile(r'^[a-zA-Z]+:')

    def absolute_name(self, name):
        if name is None:
            return False
        return self._absolute_re.search(name)

    def get_context(self, obj_type, name=None, global_conf=None):
        if self.absolute_name(name):
            return loadcontext(obj_type, name, global_conf=global_conf)
        section = self.find_config_section(
                obj_type, name=name)
        defaults = self.parser.defaults()
        _global_conf = defaults.copy()
        if global_conf is not None:
            _global_conf.update(global_conf)
        global_conf = _global_conf
        local_conf = {}
        for option in self.parser.options(section):
            if option in defaults:
                continue
            local_conf[option] = self.parser.get(section, option)
        if obj_type == HANDLER:
            context = self._pipeline_context(
                obj_type, section, name=name, global_conf=global_conf,
                local_conf=local_conf)
        elif 'use' in local_conf:
            context = self._context_from_use(
                obj_type, local_conf, global_conf, section)
        else:
            raise LookupError(
                "Invalid section config %r" % section)
        return context

    def _pipeline_context(self, obj_type, section, name, global_conf,
                          local_conf):
        if 'pipeline' not in local_conf:
            pipeline = []
        else:
            pipeline = local_conf.pop('pipeline').split()
        context = LoaderContext(
            None, PIPELINE, None, global_conf, local_conf, self)
        # context.handler_context = self._context_from_use(
        #     obj_type, local_conf, global_conf, section)
        context.handler_context = loadcontext(
                HANDLER, DEFAULT_HANDLER, global_conf=global_conf)
        context.filter_contexts = [
            self.get_context(FILTER, n, global_conf)
            for n in pipeline]
        return context

    def _context_from_use(self, obj_type, local_conf, global_conf, section):
        use = local_conf.pop('use', None)
        if not use:
            raise LookupError("Missing 'use' in section config %r" % section)

        context = self.get_context(
            obj_type, name=use, global_conf=global_conf)
        context.local_conf.update(local_conf)
        context.loader = self

        if context.protocol is None:
            section_protocol = section.split(':', 1)[0]
            if section_protocol in ('handler'):
                context.protocol = 'handler_factory'
            else:
                context.protocol = '%s_factory' % section_protocol

        return context

    def find_config_section(self, obj_type, name=None):
        sections = []
        for prefix in obj_type.config_prefixes:
            found = self._find_sections(
                self.parser.sections(), prefix, name)
            if found:
                sections.extend(found)
                break
        if not sections:
            raise LookupError(
                'No section %r found in config %r' % (name, self.filename))
        if len(sections) > 1:
            raise LookupError(
                'Ambiguous section %r found in config %r'
                % (name, self.filename))

        return sections[0]

    def _find_sections(self, sections, prefix, name):
        found = []
        if name is None:
            if prefix in sections:
                found.append(prefix)
            name = 'main'
        for section in sections:
            if section.startswith(prefix + ':'):
                if section[len(prefix) + 1:].strip() == name:
                    found.append(section)
        return found

    def get_sections(self, prefix=None):
        return [section for section in self.parser.sections()
                if not prefix or section.startswith(prefix + ':')]


class EggLoader(_Loader):
    def __init__(self, spec):
        self.spec = spec

    def get_context(self, obj_type, name=None, global_conf=None):
        entry_point, protocol, ep_name = self.find_egg_ep(obj_type, name=name)
        distribution = pkg_resources.get_distribution(self.spec)
        return LoaderContext(
                entry_point, obj_type, protocol, global_conf or {}, {}, self,
                distribution=distribution, ep_name=ep_name)

    def find_egg_ep(self, obj_type, name=None):
        if name is None:
            name = 'main'
        entries = []
        for protocol in obj_type.egg_protocols:
            pkg_resources.require(self.spec)
            entry = pkg_resources.get_entry_info(
                        self.spec, protocol, name)
            if entry is not None:
                entries.append((entry.load(), protocol, entry.name))
                break
        if not entries:
            raise LookupError(
                "Entry point %r not found in egg %r"
                % (name, self.spec))
        if len(entries) > 1:
            raise LookupError(
                "Ambiguous entry for %r in egg"
                % (name, self.spec))
        return entries[0]


class LoaderContext(object):
    def __init__(self, obj, obj_type, protocol, global_conf, local_conf,
                 loader, distribution=None, ep_name=None):
        self.object = obj
        self.obj_type = obj_type
        self.protocol = protocol
        self.global_conf = global_conf
        self.local_conf = local_conf
        self.loader = loader
        self.distribution = distribution
        self.ep_name = ep_name

    def create(self, **kwargs):
        return self.obj_type.invoke(self, **kwargs)

    def config(self):
        conf = AttrDict(self.global_conf)
        conf.update(self.local_conf)
        conf.local_conf = self.local_conf
        conf.global_conf = self.global_conf
        conf.context = self
        return conf


class AttrDict(dict):
    pass
