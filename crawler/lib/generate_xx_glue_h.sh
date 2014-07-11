#!/bin/bash

dbus-binding-tool --mode=glib-server --prefix=crawler atos.grid.crawler.xml > crawler-glue.h
dbus-binding-tool --mode=glib-server --prefix=action  atos.grid.action.xml  > action-glue.h
dbus-binding-tool --mode=glib-server --prefix=crawlerCmd atos.grid.crawlerCmd.xml > crawlerCmd-glue.h


