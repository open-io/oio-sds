# Two parameters is possible
# filter_args : arguments of the filter_conf arg into the tiering config file
# obj_infos : some informations about the object
import time
import sys
import calendar
if not(obj_infos and filter_args):
    print 'False'
tiering_time = filter_args.get('tiering_time', None)
creation_date = obj_infos.get('ctime', None)
if not tiering_time and creation_date:
    print 'False'
date_creation = time.gmtime(creation_date)
actual_date = time.gmtime()
tiering_time =  time.gmtime(calendar.timegm(date_creation) + tiering_time)
if actual_date >= tiering_time:
    print 'True'
else:
    print 'False'
