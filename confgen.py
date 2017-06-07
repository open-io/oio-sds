#!/usr/bin/env python

# confgen.py, a code generator foor OpenIO SDS
# Copyright (C) 2017 OpenIO, original work as part of OpenIO SDS
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

import sys, json
from itertools import chain


def str2epoch(s):
    s = str(s).strip()
    if s.endswith('ms'):
        return "1"
    if s.endswith('s'):
        return str(int(s[:-1]))
    if s.endswith('m'):
        return str(60 * int(s[:-1]))
    if s.endswith('h'):
        return str(3600 * int(s[:-1]))
    if s.endswith('d'):
        return str(86400 * int(s[:-1]))
    return s


def str2size(s):
    s = str(s).strip()
    if s == "max":
        return 'G_MAXINT64'
    if s.endswith('ki'):
        return int(s[:-2]) * 1024
    if s.endswith('Mi'):
        return int(s[:-2]) * 1024 * 1024
    if s.endswith('Gi'):
        return int(s[:-2]) * 1024 * 1024 * 1024
    if s.endswith('Ti'):
        return int(s[:-2]) * 1024 * 1024 * 1024 * 1024
    if s.endswith('k'):
        return int(s[:-1]) * 1000
    if s.endswith('M'):
        return int(s[:-1]) * 1000 * 1000
    if s.endswith('G'):
        return int(s[:-1]) * 1000 * 1000 * 1000
    if s.endswith('T'):
        return int(s[:-1]) * 1000 * 1000 * 1000 * 1000
    return eval(str(s))


def str2monotonic(s):
    s = str(s).strip()
    if s == "max":
        return 'G_MAXINT64'
    if s.endswith('ms'):
        return s[:-2] + ' * G_TIME_SPAN_MILLISECOND'
    if s.endswith('s'):
        return s[:-1] + ' * G_TIME_SPAN_SECOND'
    if s.endswith('m'):
        return s[:-1] + ' * G_TIME_SPAN_MINUTE'
    if s.endswith('h'):
        return s[:-1] + ' * G_TIME_SPAN_HOUR'
    if s.endswith('d'):
        return s[:-1] + ' * G_TIME_SPAN_DAY'
    return eval(str(s))


def name2key(name):
    return name.replace("_", ".")


def key2macro(name):
    return "OIO__" + name.replace(".", "_").upper()


class Variable(object):
    def __init__(self, cfg):
        self.name = cfg["name"]
        self.key = cfg.get("key", name2key(self.name))
        self.macro = cfg.get("macro", key2macro(self.key))
        self.kind = None
        self.ctype = None
        self.descr = cfg.get("descr", "")
        if not self.descr:
            self.descr = "TODO: to be documented"
        self.default = cfg.get("def")
        self.declare = bool(cfg.get("declare", True))

    def raw(self):
        out = dict()
        out["key"] = self.key
        out["descr"] = self.descr
        out["macro"] = self.macro
        out["ctype"] = self.ctype
        out["default"] = self.default
        return out;

    def _gen_declaration(self, out):
        assert(False)

    def _gen_registration(self, out):
        assert(False)

    def _gen_header(self, out):
        out.write("\n#ifndef {0}\n# define {0} ({1})\n#endif\n\n".format(
                self.macro, self.default))
        if self.declare:
            out.write('extern {0} {1};\n'.format(self.ctype, self.name))


class String(Variable):
    def __init__(self, cfg):
        self.name = cfg["name"]
        self.limit = int(cfg["limit"])
        self.key = cfg.get("key", name2key(self.name))
        self.macro = cfg.get("macro", key2macro(self.key))
        self.ctype = 'string'
        self.descr = cfg.get("descr", "")
        if not self.descr:
            self.descr = "TODO: to be documented"
        self.default = cfg.get("def")
        self.declare = bool(cfg.get("declare", True))

    def raw(self):
        out = dict()
        out["key"] = self.key
        out["descr"] = self.descr
        out["macro"] = self.macro
        out["ctype"] = self.ctype
        out["limit"] = self.limit
        out["default"] = self.default
        return out;

    def _gen_declaration(self, out):
        out.write("gchar {0} [{1}] = {2};\n".format(
            self.name, self.limit, self.macro))

    def _gen_registration(self, out):
        out.write('\n\toio_var_register_string('
                '\n\t\t{name}, "{key}",'
                '\n\t\t"{descr}",'
                '\n\t\t{def}, {limit});\n'.format(**{
            "name": self.name,
            "key": self.key,
            "descr": self.descr,
            "def": self.macro,
            "limit": self.limit}))

    def _gen_header(self, out):
        out.write("\n#ifndef {0}\n# define {0} \"{1}\"\n#endif\n\n".format(
                self.macro, self.default))
        if self.declare:
            out.write('extern gchar {0}[{1}];\n'.format(self.name, self.limit))


class Bool(Variable):
    def __init__(self, conf):
        super(Bool, self).__init__(conf)
        self.kind = "OIO_VARKIND_size"  # dumb, but just working
        self.ctype = "gboolean"
        self.default = str(bool(conf.get("def", False))).upper()

    def _gen_declaration(self, out):
        out.write('gboolean {0} = {1};\n'.format(self.name, self.macro))

    def _gen_registration(self, out):
        out.write('\n\toio_var_register_gboolean('
                '\n\t\t&{0}, "{2}",'
                '\n\t\t"{3}",'
                '\n\t\t{1});\n'.format(
            self.name, self.macro, self.key, self.descr))


class Number(Variable):
    def __init__(self, conf):
        super(Number, self).__init__(conf)
        self.ctype = None
        self.vmin = conf.get('min', 0)
        self.vmax = conf.get('max', 0)
        self.default = conf.get('def', 0)

    def _gen_declaration(self, out):
        out.write('{2} {0} = {1};\n'.format(
            self.name, self.macro, self.ctype))

    def _gen_registration(self, out):
        out.write('\n\toio_var_register_{ctype}('
                '\n\t\t&{name}, {kind}, "{key}",'
                '\n\t\t"{descr}",'
                '\n\t\t{def}, {min}, {max});\n'.format(**{
            "name": self.name,
            "kind": self.kind,
            "ctype": self.ctype,
            "key": self.key,
            "descr": self.descr,
            "def": self.macro,
            "min": self.vmin,
            "max": self.vmax}))

    def raw(self):
        out = super(Number, self).raw()
        out["vmin"] = self.vmin
        out["vmax"] = self.vmax
        return out


class Monotonic(Number):
    def __init__(self, conf):
        super(Monotonic, self).__init__(conf)
        self.kind = 'OIO_VARKIND_time'
        self.ctype = "gint64"
        self.default = str2monotonic(self.default)
        self.vmin = str2monotonic(self.vmin)
        self.vmax = str2monotonic(self.vmax)


class Epoch(Number):
    def __init__(self, conf):
        super(Epoch, self).__init__(conf)
        self.kind = 'OIO_VARKIND_time'
        self.ctype = "gint64"
        self.default = str2epoch(self.default)
        self.vmin = str2epoch(self.vmin)
        self.vmax = str2epoch(self.vmax)


class Float(Number):
    def __init__(self, conf):
        super(Float, self).__init__(conf)
        self.ctype = 'gdouble'
        self.kind = 'OIO_VARKIND_time'
        self.default = float(self.default)
        self.vmin = float(self.vmin)
        self.vmax = float(self.vmax)


class Size(Number):
    def __init__(self, conf, ctype):
        super(Size, self).__init__(conf)
        self.kind = 'OIO_VARKIND_size'
        self.ctype = ctype
        self.default = str2size(self.default)
        self.vmin = str2size(self.vmin)
        self.vmax = str2size(self.vmax)


class Int(Size):
    def __init__(self, conf):
        super(Int, self).__init__(conf, 'gint')


class Int32(Size):
    def __init__(self, conf):
        super(Int32, self).__init__(conf, 'gint32')


class Int64(Size):
    def __init__(self, conf):
        super(Int64, self).__init__(conf, 'gint64')


class Uint(Size):
    def __init__(self, conf):
        super(Uint, self).__init__(conf, 'guint')


class Uint32(Size):
    def __init__(self, conf):
        super(Uint32, self).__init__(conf, 'guint32')


class Uint64(Size):
    def __init__(self, conf):
        super(Uint64, self).__init__(conf, 'guint64')


_classes = {
    "bool": Bool,
    "boolean": Bool,
    "monotonic": Monotonic,
    "epoch": Epoch,
    "i": Int,
    "i32": Int32,
    "i64": Int64,
    "int": Int,
    "int32": Int32,
    "int64": Int64,
    "u": Uint,
    "u32": Uint32,
    "u64": Uint64,
    "uint": Uint,
    "uint32": Uint32,
    "uint64": Uint64,
    "float": Float,
    "real": Float,
    "double": Float,
    "string": String,
}


def make_variable(cfg):
    cls = _classes[cfg["type"]]
    return cls(cfg)


def path2macro(p):
    from os import getcwd
    p = getcwd() + '_' + p
    p = p.replace("-", "_")
    p = p.replace(".", "_")
    p = p.replace("/", "_")
    return ("OIO_" + p + '_').upper()


def start_headers(out, name):
    out.write('#ifndef {0}\n#define {0}\n\n#include "core/oiovar.h"\n'.format(path2macro(name)))
    out.write('\n/* AUTO-GENERATED by confgen.py */\n')


def end_headers(out, name):
    out.write("\n\n#endif /* {0} */\n".format(path2macro(name)))


def start_declarations(out, header):
    out.write('#include "{0}" /* AUTO-GENERATED by confgen.py */\n'.format(header))


def end_declarations(_out):
    pass


def start_registration(out, header):
    out.write("static void __attribute__ ((constructor))\n")
    out.write("_declare_gboolean_{0} (void) {{\n".format(path2macro(header)))


def end_registration(out):
    out.write('}\n')


def gen_markdown_single_var(out, var):
    out.write("""
### {key}

> {descr}

 * default: **{default}**
 * type: {ctype}
 * cmake directive: *{macro}*
""".format(**var.raw()))
    if not isinstance(var, Bool):
        out.write(" * range: {vmin} -> {vmax}\n".format(**var.raw()))

def gen_markdown(out, allvars):
    out.write("\n## Fully configurable variables (compilation & runtime)\n")
    out.write("\n### Variables for production purposes\n")
    for var in allvars:
        if var.key.startswith('enbug'):
            continue
        gen_markdown_single_var(out, var)

    out.write("""
## Variables only for testing purposes

These variables are only active when the **ENBUG** option has been specified on
the cmake command line.

""")
    for var in allvars:
        if not var.key.startswith('enbug'):
            continue
        gen_markdown_single_var(out, var)

def gen_cmake(out, allvars):
    for var in allvars:
        out.write("dir2macro({0})\n".format(var.macro))


def get_all_vars(descr):
    allvars = [v["variables"] for _,v in descr.iteritems()]
    allvars = chain(*allvars)
    return sorted(
            [make_variable(x) for x in allvars],
            key=lambda x: x.key)

def get_module_vars(descr):
    return sorted(
            [make_variable(x) for x in descr["variables"]],
            key=lambda x: x.key)


module = sys.argv[1]
path = sys.argv[2]
with open(path, "r") as fin:

    descr = json.load(fin)

    if module == 'github':
        with open("Variables.md", "w") as out:
            with open("Variables.md.inc", "r") as header_in:
                out.write(header_in.read())
            gen_markdown(out, get_all_vars(descr))

    elif module == 'cmake':
        with open("Variables.CMakeFile", "w") as out:
            out.write('### file generated by confgen.py\n\n')
            gen_cmake(out, get_all_vars(descr))
            out.write("")

    else:
        descr = descr[module]
        out = {
                "src": open(descr["code"], "w"),
                "hdr": open(descr["header"], "w"),
                "doc": sys.stdout
        }

        variables = get_module_vars(descr)

        start_headers(out["hdr"], descr["header"])
        for var in variables:
            var._gen_header(out["hdr"])
        end_headers(out["hdr"], descr["header"])

        start_declarations(out["src"], descr["header"])
        for var in variables:
            var._gen_declaration(out["src"])
        end_declarations(out["src"])

        start_registration(out["src"], descr["header"])
        for var in variables:
            var._gen_registration(out["src"])
        end_registration(out["src"])

        out["src"].close()
        out["hdr"].close()

