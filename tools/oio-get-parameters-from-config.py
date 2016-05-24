#!/usr/bin/env python

# oio-get-parameters-from-config.py, a script to recover parameters from a json or yml file
# Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage
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

import sys
import json
import yaml
def main_function(argv):
    if len(argv) < 3:
        return
    obj = None
    if argv[1].find('.json') != -1 or sys.argv[1].find('.yml') != 1 :
        f=open(argv[1],"r")
        obj=json.load(f)
        f.close()
    if obj is None:
        return
    for i in range(2,len(argv)):
        if isinstance(obj, dict):
            obj=obj.get(argv[i], None)
        else:
            return
    if obj is not None and not isinstance(obj, dict):
        print obj
                                                                                                            
if __name__ == "__main__":
    main_function(sys.argv)
    
    
