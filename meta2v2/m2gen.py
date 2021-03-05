#!/usr/bin/env python

# OpenIO SDS meta2v2
# Copyright (C) 2014 Worldline, as part of Redcurrant
# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021 OVH SAS
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

index = 0

agpl = """/*
Copyright (C) 2017-2017 OpenIO SAS, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
"""


def bool2int(b):
    if b:
        return "1"
    return "0"


def next_seq():
    global index
    i, index = index, index + 1
    return i


def dquoted(s):
    return '"'+str(s)+'"'


def field_index(bean, name):
    i = 0
    for f in bean.fields:
        if f.name == name:
            return i
        i = i + 1
    raise Exception("Field "+str(name)+" not found in bean "+str(bean.name))


class ForeignKey(object):

    def __init__(self, src, dst):
        base, base_fields, base_name = src
        target, target_fields, target_name = dst
        # configure the source part
        self.base = base
        self.base_name = str(base_name)
        self.base_fields = list()
        for f in base_fields:
            self.base_fields.append((field_index(base, f), str(f)))
        # configure the target part
        self.target = target
        self.target_name = str(target_name)
        self.target_fields = list()
        for f in target_fields:
            self.target_fields.append((field_index(target, f), str(f)))
        # now the FK in itself
        self.name = 'fk_' + self.base.name.upper() + '_' + \
                    self.target.name.upper()+ '_' + str(next_seq())
        self.base.fk_outgoing.append(self)
        self.target.fk_incoming.append(self)


class Field(object):

    def __init__(self, name):
        self.name = name
        self.type_sql = None
        self.type_c = None
        self.position = 0
        self.struct = None
        self.mandatory = True
        self.unique = False

    def __repr__(self):
        return '<Field name="{0}" type="{1}/{2}" pos="{3}">' \
            .format(self.name, self.type_sql, self.type_c, self.position)

    def set_index(self, i):
        self.position = i


class Blob(Field):

    def __init__(self, name):
        Field.__init__(self, name)
        self.type_c = 'GByteArray *'
        self.type_sql = 'BLOB'


class Text(Field):

    def __init__(self, name):
        Field.__init__(self, name)
        self.type_c = 'GString *'
        self.type_sql = 'TEXT'


class Int(Field):

    def __init__(self, name):
        Field.__init__(self, name)
        self.type_c = 'gint64'
        self.type_sql = "INT"


class Bool(Field):

    def __init__(self, name):
        Field.__init__(self, name)
        self.type_c = 'gboolean'
        self.type_sql = "BOOL"


class Struct(object):

    def __init__(self, name):
        self.name = str(name)
        self.c_name = str(name).upper()
        self.sql_name = str(name).upper()
        self.fields = list()
        self.pk = None
        self.fk_outgoing = list()
        self.fk_incoming = list()
        self.indexes = list()
        self.order = 999

    def __repr__(self):
        l = list()
        l.append('<Struct name="'+str(self.name)+'">')
        for f in self.fields:
            l.append('\t'+repr(f))
        l.append("</Struct>")
        return "\n".join(l)

    def field(self, f, mandatory=True, unique=False):
        f.set_index(len(self.fields))
        f.struct = self
        f.mandatory = bool(mandatory)
        f.unique = bool(unique)
        self.fields.append(f)
        return self

    def PK(self, t):
        self.pk = t
        return self

    def index(self, n, fl):
        i = (str(n), [str(x) for x in fl])
        self.indexes.append(i)
        return self

    def set_sql_name(self, n):
        self.sql_name = str(n)
        return self

    def get_fields_names(self):
        return [str(f.name) for f in self.fields]

    def get_fk_names(self):
        l = list()
        for fk in self.fk_incoming:
            l.append(str(fk.target_name))
        for fk in self.fk_outgoing:
            l.append(str(fk.base_name))
        return l

    def set_order(self, o):
        self.order = o
        return self


class Generator(object):

    def __init__(self):
        self.allbeans = dict()
        self.allfk = list()

    def add_bean(self, bean):
        self.allbeans[bean.name] = bean
        return bean

    def add_fk(self, fk):
        self.allfk.append(fk)
        return fk

    def reverse_dependencies(self):
        """Returns the list of bean's names, listing first the beans without
dependencies, then the bean with already listed dependencies until the end of
the list."""
        done = set()
        result = list()
        queue = list()

        def push(n):
            queue.append(n)

        def pop():
            return queue.pop(0)

        def has():
            return len(queue) > 0

        # init the queue
        for bean in self.allbeans.values():
            push(bean.name)
        # run the queue
        while has():
            count = 0
            name = pop()
            bean = self.allbeans[name]
            # count the unmatched dependencies
            for fk in bean.fk_outgoing:
                if fk.target.name not in done:
                    count = count + 1
                    break
            # if there has no unmatched deps, OK, else re-queue it
            if count <= 0:
                result.append(name)
                done.add(name)
            else:
                push(name)
        return [self.allbeans[n] for n in result]

    def dump_c_header(self, out):
        out.write(agpl)
        out.write("/* AUTOGENERATED */\n")
        out.write("#ifndef GENERATED_H\n")
        out.write("# define GENERATED_H 1\n")
        out.write("# include <glib.h>\n")
        out.write("# include <sqlite3.h>\n")
        out.write("# include <meta2v2/generic.h>\n")
        out.write("\n")
        for t in self.allbeans.values():
            out.write("extern const struct bean_descriptor_s descr_struct_"+t.name.upper()+";\n")
        out.write("extern const gchar *schema;\n")
        out.write("\n")

        for t in self.allbeans.values():
            u = t.name.upper()
            out.write("\n")
            out.write("struct fields_"+u+"_s;\n")
            out.write("struct bean_"+u+"_s;\n")

        for t in self.allbeans.values():
            u = t.name.upper()
            out.write("\n/* Loader and Saver for "+u+" */\n")
            out.write("\nGError* "+u+"_load(sqlite3 *db, const gchar *clause,\n")
            out.write("\t\tGVariant **params, on_bean_f cb, gpointer u);\n")

        for t in self.allbeans.values():
            u = t.name.upper()
            out.write("\n/* Getters and Setters for "+u+" */\n\n")
            for f in t.fields:
                out.write(f.type_c+" "+u+"_get_"+f.name+"(struct bean_"+u+"_s *bean);\n")
                out.write("void "+u+"_set_"+f.name+"(struct bean_"+u+"_s *bean, "+f.type_c+" v);\n")
                if isinstance(f, Text):
                    out.write("void "+u+"_set2_"+f.name+"(struct bean_"+u+"_s *bean, const gchar *v);\n")
                if isinstance(f, Blob):
                    out.write("void "+u+"_set2_"+f.name+"(struct bean_"+u+"_s *bean, const guint8 *v, gsize vlen);\n")
                if not f.mandatory:
                    out.write("void "+u+"_nullify_"+f.name+"(struct bean_"+u+"_s *bean);\n")
                out.write("\n")

        out.write("\n#endif /* GENERATED_H */\n")

    def dump_c_codec(self, out):
        out.write(agpl)
        out.write("/* !!!AUTOGENERATED!!! */\n")
        out.write("#include <metautils/lib/metautils.h>\n")
        out.write("#include <meta2v2/generic.h>\n")
        out.write("#include <meta2v2/autogen.h>\n")
        out.write("#include <glib.h>\n")
        out.write("\n")

        out.write("const gchar *schema =\n")

        def print_quoted(s):
            out.write('\t'+dquoted(s)+"\n")
        for t in self.reverse_dependencies():
            print_quoted("CREATE TABLE IF NOT EXISTS "+t.sql_name+" (")
            for f in t.fields:
                tmp = list()
                tmp.append(" "+f.name+' '+f.type_sql)
                if f.mandatory:
                    tmp.append(" NOT NULL")
                if f.unique:
                    tmp.append(" UNIQUE")
                tmp.append(",")
                print_quoted(''.join(tmp))
            for fk in t.fk_outgoing:
                tmp = list()
                tmp.append(" CONSTRAINT " + fk.name)
                tmp.append(" FOREIGN KEY (" + ','.join([n for i, n in fk.base_fields])+")")
                tmp.append(" REFERENCES "+fk.target.sql_name+"("+','.join([n for i, n in fk.target_fields])+")")
                tmp.append(" ON UPDATE CASCADE ON DELETE CASCADE,")
                print_quoted(''.join(tmp))
            print_quoted(" PRIMARY KEY ("+','.join(t.pk)+")")
            print_quoted(");")
            for n, fl in t.indexes:
                print_quoted("CREATE INDEX IF NOT EXISTS "+n+" on "+t.sql_name+"("+','.join(fl)+");")
        print_quoted("INSERT OR IGNORE INTO admin(k,v) VALUES (\\\"schema_version\\\",\\\"1.8\\\");")
        print_quoted("INSERT OR IGNORE INTO admin(k,v) VALUES (\\\"version:main.admin\\\",\\\"1:0\\\");")
        for t in self.reverse_dependencies():
            print_quoted("INSERT OR IGNORE INTO admin(k,v) VALUES (\\\"version:main."+t.sql_name+"\\\",\\\"1:0\\\");")
        out.write(';\n')

        for fk in self.allfk:
            out.write("static struct fk_field_s descr_fk_fields_in_"+fk.name.upper()+"[] =\n{\n\t")
            out.write(', '.join(['{'+str(i)+','+dquoted(s)+'}' for i,s in fk.base_fields])+", {-1,NULL}\n")
            out.write("};\n\n")
            out.write("static struct fk_field_s descr_fk_fields_out_"+fk.name.upper()+"[] =\n{\n\t")
            out.write(','.join(['{'+str(i)+','+dquoted(s)+'}' for i,s in fk.target_fields])+", {-1,NULL}\n")
            out.write("};\n\n")

        # Define the bean fields containers
        for t in self.allbeans.values():
            out.write("struct fields_"+t.c_name+"_s {\n")
            for f in t.fields:
                out.write("\t"+f.type_c+' '+f.name+';\n')
            out.write("};\n\n")

        # Define the bean descriptors
        for t in self.allbeans.values():
            out.write("struct bean_"+t.c_name+"_s {\n")
            out.write("\tstruct bean_header_s header;\n")
            out.write("\tstruct fields_"+t.c_name+"_s fields;\n")
            out.write("};\n\n")

        # define the field descriptors
        for t in self.allbeans.values():
            out.write("static struct field_descriptor_s descr_fields_"+t.c_name+"[] =\n{\n")
            for f in t.fields:
                pk = False
                if f.name in list(t.pk):
                    pk = True
                out.write('\t{ ')
                out.write("offsetof(struct fields_"+t.c_name+"_s,"+f.name+"), ")
                out.write(str(f.position)+', ')
                out.write('FT_'+str(f.type_sql)+', ')
                out.write(bool2int(pk)+', ')
                out.write(bool2int(f.mandatory)+', ')
                out.write(dquoted(f.name))
                out.write(' },\n')
            out.write("\t{0, 0, FALSE, 0, FALSE, \"\"}\n};\n")
            out.write("\n")

        # define the foreign key fields descriptors
        for t in self.allbeans.values():
            if len(t.get_fk_names()) > 0:
                out.write("static gchar * descr_fk_names_"+t.c_name+"[] = { "+','.join([dquoted(n) for n in t.get_fk_names()])+", NULL };\n")
            else:
                out.write("static gchar *descr_fk_names_"+t.c_name+"[] = { NULL };\n")
            out.write('\n')

        # define the foreign key descriptors
        for t in self.allbeans.values():
            out.write("static struct fk_descriptor_s descr_fk_"+t.c_name+"[] =\n{\n")
            for fk in t.fk_incoming:
                out.write('\t{\n')
                out.write('\t\t&descr_struct_'+fk.base.name.upper() +',\n')
                out.write('\t\tdescr_fk_fields_in_'+fk.name.upper()+',\n')
                out.write('\t\t&descr_struct_'+fk.target.name.upper()+',\n')
                out.write('\t\tdescr_fk_fields_out_'+fk.name.upper()+',\n')
                out.write('\t\t'+dquoted(fk.target_name)+',\n')
                out.write('\t},\n')
            for fk in t.fk_outgoing:
                out.write('\t{\n')
                out.write('\t\t&descr_struct_'+fk.base.name.upper() +',\n')
                out.write('\t\tdescr_fk_fields_in_'+fk.name.upper()+',\n')
                out.write('\t\t&descr_struct_'+fk.target.name.upper()+',\n')
                out.write('\t\tdescr_fk_fields_out_'+fk.name.upper()+',\n')
                out.write('\t\t'+dquoted(fk.base_name)+',\n')
                out.write('\t},\n')
            out.write("\t{NULL, NULL, NULL, NULL, \"\"}\n};\n\n")

        for t in self.allbeans.values():
            out.write("const struct bean_descriptor_s descr_struct_"+t.c_name+" =\n{\n")
            out.write("\t"+dquoted(t.name)+",\n")
            out.write("\t"+dquoted(t.sql_name)+",\n")
            out.write("\t"+str(len(t.sql_name))+",\n")

            sql = "DELETE FROM "+t.sql_name+" WHERE "
            out.write('\t'+dquoted(sql)+',\n')
            out.write('\t'+str(len(sql))+',\n')

            sql = "SELECT "+(",".join(t.get_fields_names()))+" FROM "+t.sql_name
            out.write('\t'+dquoted(sql)+',\n')
            out.write('\t'+str(len(sql))+',\n')

            sql = "SELECT COUNT(*) FROM "+t.sql_name
            out.write('\t'+dquoted(sql)+',\n')
            out.write('\t'+str(len(sql))+',\n')

            # sql_insert
            t0 = ",".join(t.get_fields_names())
            t1 = ",".join(['?' for f in t.fields])
            sql = "INSERT OR ABORT INTO "+t.sql_name+"("+t0+") VALUES ("+t1+")"
            out.write('\t'+dquoted(sql)+',\n')
            out.write('\t'+str(len(sql))+',\n')

            # sql_replace
            sql = "INSERT OR REPLACE INTO "+t.sql_name+"("+t0+") VALUES ("+t1+")"
            out.write('\t'+dquoted(sql)+',\n')
            out.write('\t'+str(len(sql))+',\n')

            # sql_update
            t0 = ",".join([f.name+'=?' for f in t.fields if f.name not in t.pk])
            t1 = " AND ".join([f.name+'=?' for f in t.fields if f.name in t.pk])
            sql = "UPDATE "+t.name+" SET "+t0+" WHERE "+t1
            out.write('\t'+dquoted(sql)+',\n')
            out.write('\t'+str(len(sql))+',\n')

            # sql_substitue
            t0 = ",".join([f.name+'=?' for f in t.fields])
            t1 = " AND ".join([f.name+'=?' for f in t.fields if f.name in t.pk])
            sql = "UPDATE "+t.name+" SET "+t0+" WHERE "+t1
            out.write('\t'+dquoted(sql)+',\n')
            out.write('\t'+str(len(sql))+',\n')

            out.write("\toffsetof(struct bean_"+t.c_name+"_s,fields),\n")
            out.write("\tsizeof(struct bean_"+t.c_name+"_s),\n")
            out.write('\t'+str(len(t.fields))+",\n")
            out.write("\tdescr_fields_"+t.c_name+",\n")
            out.write("\tdescr_fk_"+t.c_name+",\n")
            out.write("\tdescr_fk_names_"+t.c_name+",\n")
            out.write("\t"+str(t.order)+"\n")
            out.write("};\n\n")

        for t in self.allbeans.values():
            out.write("\n")
            for f in t.fields:
                out.write("void\n"+t.c_name+"_set_"+f.name+"(struct bean_"+t.c_name+"_s *bean, "+f.type_c+" v)\n{\n")
                out.write("\tEXTRA_ASSERT(bean != NULL);\n")
                out.write("\tEXTRA_ASSERT(DESCR(bean) == &descr_struct_"+t.c_name+");\n")
                out.write("\t_bean_set_field_value(bean, "+str(f.position)+", &v);\n")
                out.write("}\n\n")
                if isinstance(f, Text):
                    out.write("void\n"+t.c_name+"_set2_"+f.name+"(struct bean_"+t.c_name+"_s *bean, const gchar *v)\n{\n")
                    out.write("\tEXTRA_ASSERT(bean != NULL);\n")
                    out.write("\tEXTRA_ASSERT(v != NULL);\n")
                    out.write("\tGString *gs = g_string_new(v);\n")
                    out.write("\t"+t.c_name+"_set_"+f.name+"(bean, gs);\n")
                    out.write("\tg_string_free(gs, TRUE);\n")
                    out.write("}\n\n")
                if isinstance(f, Blob):
                    out.write("void\n"+t.c_name+"_set2_"+f.name+"(struct bean_"+t.c_name+"_s *bean, const guint8 *v, gsize vlen)\n{\n")
                    out.write("\tEXTRA_ASSERT(bean != NULL);\n")
                    out.write("\tEXTRA_ASSERT(v != NULL);\n")
                    # Let the GByteArray think it owns the array...
                    out.write("\tGByteArray *gba = g_byte_array_new_take((guint8*)v, vlen);\n")
                    out.write("\t"+t.c_name+"_set_"+f.name+"(bean, gba);\n")
                    # ...but do not actually free it!
                    out.write("\tg_byte_array_free(gba, FALSE);\n")
                    out.write("}\n\n")
                if not f.mandatory:
                    out.write("void\n"+t.c_name+"_nullify_"+f.name+"(struct bean_"+t.c_name+"_s *bean)\n{\n")
                    out.write("\tEXTRA_ASSERT(bean != NULL);\n")
                    out.write("\tif (_bean_has_field(bean, "+str(f.position)+")) {\n")
                    out.write("\t\tHDR(bean)->flags |= BEAN_FLAG_DIRTY;\n")
                    out.write("\t\t_bean_del_field(bean, "+str(f.position)+");\n")
                    out.write("\t}\n")
                    out.write("}\n\n")
                out.write(f.type_c+"\n"+t.c_name+"_get_"+f.name+"(struct bean_"+t.c_name+"_s *bean)\n{\n")
                out.write("\tEXTRA_ASSERT(bean != NULL);\n")
                out.write("\tEXTRA_ASSERT(DESCR(bean) == &descr_struct_"+t.c_name+");\n")
                out.write("\treturn *(("+f.type_c+"*)(FIELD(bean,"+str(f.position)+")));\n")
                out.write("}\n\n")

    def dump_c_storage(self, out):
        out.write(agpl)
        out.write("/* !!!AUTOGENERATED!!! */\n")
        out.write("#include <metautils/lib/metautils.h>\n")
        out.write("#include <meta2v2/generic.h>\n")
        out.write("#include <meta2v2/autogen.h>\n")
        out.write("#include <glib.h>\n")
        out.write("#include <sqlite3.h>\n")
        out.write("\n")

        for t in self.allbeans.values():
            out.write("GError*\n"+t.c_name+"_load(sqlite3 *db, const gchar *clause, GVariant **params,")
            out.write(" void (*cb)(gpointer u, gpointer bean), gpointer u)\n{\n")
            out.write("\tEXTRA_ASSERT(db != NULL);\n")
            out.write("\tEXTRA_ASSERT(clause != NULL);\n")
            out.write("\tEXTRA_ASSERT(params != NULL);\n")
            out.write("\treturn _db_get_bean(&descr_struct_"+t.c_name+", db, clause, params, cb, u);\n")
            out.write("}\n\n")


generator = Generator()

alias = generator.add_bean(Struct("aliases")
                           .field(Text("alias"))
                           .field(Int("version"))
                           .field(Blob("content"))
                           .field(Bool("deleted"))
                           .field(Int("ctime"))
                           .field(Int("mtime"))
                           .PK(("alias", "version"))
                           .index('alias_index_by_name', ['alias'])
                           .index('alias_index_by_header', ['content'])
                           .set_sql_name("aliases")).set_order(0)

properties = generator.add_bean(Struct("properties")
                                .field(Text("alias"))
                                .field(Int("version"))
                                .field(Text("key"))
                                .field(Blob("value"))
                                .PK(("alias", "version", "key"))
                                .index('properties_index_by_header_version', ['alias', 'version'])
                                .set_sql_name("properties")).set_order(5)

contents = generator.add_bean(Struct("contents_headers")
                              .field(Blob("id"))
                              .field(Blob("hash"), mandatory=False)
                              .field(Int("size"))
                              .field(Int("ctime"))
                              .field(Int("mtime"))
                              .field(Text("mime_type"))
                              .field(Text("chunk_method"))
                              .field(Text("policy"), mandatory=False)
                              .PK(("id", ))
                              .index('content_by_hash_size', ['hash', 'size'])
                              .set_sql_name("contents")).set_order(1)

chunks = generator.add_bean(Struct("chunks")
                            .field(Text("id"))
                            .field(Blob("content"))
                            .field(Text("position"))
                            .field(Blob("hash"))
                            .field(Int("size"))
                            .field(Int("ctime"))
                            .PK(("id", "content", "position"))
                            .index('chunk_index_by_header', ['content'])
                            .set_sql_name("chunks")).set_order(3)

shards = generator.add_bean(Struct('shard_range')
                            .field(Text('lower'), unique=True)
                            .field(Text('upper'), unique=True)
                            .field(Blob('cid'), unique=True)
                            .field(Text('metadata'), mandatory=False)
                            .PK(('lower', ))
                            .set_sql_name('shard_ranges')).set_order(6)

generator.add_fk(ForeignKey((properties, ('alias', 'version'), "alias"),
                            (alias, ('alias', 'version'), "properties")))

generator.add_fk(ForeignKey((alias, ('content', ), "image"),
                            (contents, ('id', ), "aliases")))

generator.add_fk(ForeignKey((chunks, ('content', ), "content"),
                            (contents, ('id', ), "chunks")))

with open("./autogen_codec.c", "w") as out:
    generator.dump_c_codec(out)

with open("./autogen_storage.c", "w") as out:
    generator.dump_c_storage(out)

with open("./autogen.h", "w") as out:
    generator.dump_c_header(out)
