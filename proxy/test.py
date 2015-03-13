#!/usr/bin/env python

# Metacd-http, a http proxy for object storage.
# Copyright (C) 2014 Worldine, original work aside of Redcurrant
# Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage
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

import sys, json, httplib, urlparse

CODE_NAMESPACE_NOTMANAGED = 418
PREFIX = 'v1.0'

suite_cs  = [
	( { 'method':'GET', 'url':'/cs', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'GET', 'url':'/cs/', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'GET', 'url':'/cs/xxx', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'GET', 'url':'/cs/info', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'GET', 'url':'/cs/info/', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/cs/info/ns', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/cs/info/ns/', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/cs/info/ns/NOTFOUND', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'GET', 'url':'/cs/info//ns/NOTFOUND', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/cs/info/ns/NS', 'body':None },
	  { 'status':200, 'body':None }),

	( { 'method':'GET', 'url':'/cs/srv', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'GET', 'url':'/cs/srv/', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/cs/srv//', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/cs/srv/ns', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/cs/srv/ns/', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/cs/srv/ns/NS', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/cs/srv/ns/NOTFOUND', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/cs/srv/ns/NS/type', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/cs/srv/ns/NS/type/', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/cs/srv/ns/NS/type/NOTFOUND', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'GET', 'url':'/cs/srv/ns/NS/type/meta0', 'body':None },
	  { 'status':200, 'body':None }),
	( { 'method':'GET', 'url':'/cs/srv/ns/NS/type/replicator', 'body':None },
	  { 'status':200, 'body':None }),

	( { 'method':'DELETE', 'url':'/cs/srv/ns/NS/type/replicator', 'body':None },
	  { 'status':200, 'body':None }),
	( { 'method':'DELETE', 'url':'/cs/srv/ns/NS/type/meta1', 'body':None },
	  { 'status':200, 'body':None }),
	( { 'method':'POST', 'url':'/cs/srv/ns/NS/type/meta1?action=lock', 'body':{
			"ns":"NS","type":"meta1","addr":"127.0.0.1:6004","score":1,"tags":[]
		}},
	  { 'status':200, 'body':None }),
	( { 'method':'POST', 'url':'/cs/srv/ns/NS/type/meta1?action=unlock', 'body':{
			"ns":"NS","type":"meta1","addr":"127.0.0.1:6004","score":1,"tags":[]
		}},
	  { 'status':200, 'body':None }),
	( { 'method':'PUT', 'url':'/cs/srv/ns/NS/type/meta1', 'body':{
			"ns":"NS","type":"meta1","addr":"127.0.0.1:7000","score":1,"tags":[]
		}},
	  { 'status':200, 'body':None }),
]

suite_dir = [
	( { 'method':'GET', 'url':'/dir', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'GET', 'url':'/dir/', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'GET', 'url':'/dir//', 'body':None },
	  { 'status':404, 'body':None }),

	( { 'method':'GET', 'url':'/dir/ref', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'GET', 'url':'/dir/ref/', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/dir/ref/ns', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/dir/ref/ns/NS', 'body':None },
	  { 'status':400, 'body':None }),

	( { 'method':'GET', 'url':'/dir/ref/ns/NS/ref/XXX', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'DELETE', 'url':'/dir/ref/ns/NS/ref/XXX', 'body':None },
	  { 'status':404, 'body':None }),

	( { 'method':'GET', 'url':'/dir/ref/ns/NS/ref/JFS', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'PUT', 'url':'/dir/ref/ns/NS/ref/JFS', 'body':None },
	  { 'status':200, 'body':None }),
	( { 'method':'GET', 'url':'/dir/ref/ns/NS/ref/JFS', 'body':None },
	  { 'status':200, 'body':None }),
	( { 'method':'PUT', 'url':'/dir/ref/ns/NS/ref/JFS', 'body':None },
	  { 'status':403, 'body':None }),
	( { 'method':'DELETE', 'url':'/dir/ref/ns/NS/ref/JFS', 'body':None },
	  { 'status':200, 'body':None }),
	( { 'method':'GET', 'url':'/dir/ref/ns/NS/ref/JFS', 'body':None },
	  { 'status':404, 'body':None }),

	( { 'method':'GET', 'url':'/dir/srv', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'GET', 'url':'/dir/srv/', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/dir/srv/ns/NS', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/dir/srv/ns/NS/ref/JFS', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/dir/srv/ns/NS/ref/JFS/type/xxx', 'body':None },
	  { 'status':404, 'body':None }),

	( { 'method':'GET', 'url':'/dir/srv/ns/NS/ref/JFS/type/meta0', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'GET', 'url':'/dir/srv/ns/NS/ref/JFS/type/meta0', 'body':None, 'hdr':{
			'X-disallow-empty-service-list':True,
		}},
	  { 'status':404, 'body':None }),

	( { 'method':'PUT', 'url':'/dir/ref/ns/NS/ref/JFS', 'body':None },
	  { 'status':200, 'body':None }),

		( { 'method':'GET', 'url':'/dir/srv/ns/NS/ref/JFS/type/meta0', 'body':None },
		  { 'status':200, 'body':[] }),
		( { 'method':'GET', 'url':'/dir/srv/ns/NS/ref/JFS/type/meta0', 'body':None, 'hdr':{
				'X-disallow-empty-service-list':True,
			}},
		  { 'status':404, 'body':None }),

		( { 'method':'POST', 'url':'/dir/srv/ns/NS/ref/JFS/type/meta0?action=link', 'body':None, },
		  { 'status':200, 'body':None }),

		( { 'method':'GET', 'url':'/dir/srv/ns/NS/ref/JFS/type/meta0', 'body':None },
		  { 'status':200, 'body':None }),
		( { 'method':'GET', 'url':'/dir/srv/ns/NS/ref/JFS/type/meta0', 'body':None, 'hdr':{
				'X-disallow-empty-service-list':True,
			}},
		  { 'status':200, 'body':None }),

		( { 'method':'DELETE', 'url':'/dir/srv/ns/NS/ref/JFS/type/meta0', 'body':None, },
		  { 'status':200, 'body':None }),

		( { 'method':'GET', 'url':'/dir/srv/ns/NS/ref/JFS/type/meta0', 'body':None },
		  { 'status':200, 'body':[] }),
		( { 'method':'GET', 'url':'/dir/srv/ns/NS/ref/JFS/type/meta0', 'body':None, 'hdr':{
				'X-disallow-empty-service-list':True,
			}},
		  { 'status':404, 'body':None }),

	( { 'method':'DELETE', 'url':'/dir/ref/ns/NS/ref/JFS', 'body':None },
	  { 'status':200, 'body':None }),
	( { 'method':'GET', 'url':'/dir/ref/ns/NS/ref/JFS', 'body':None, 'hdr':{
				'X-disallow-empty-service-list':True,
			} },
	  { 'status':404, 'body':None }),
]

suite_meta2 = [
	### Invalid URL, wrong method, no json in body, etc
	( { 'method':'GET', 'url':'/m3', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'GET', 'url':'/m2', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'GET', 'url':'/m2/', 'body':None },
	  { 'status':404, 'body':None }),

	( { 'method':'HEAD', 'url':'/m2/container', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'HEAD', 'url':'/m2/container/', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'HEAD', 'url':'/m2/container/ns/NS', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'HEAD', 'url':'/m2/container/ns/NS/ref/JFS', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'HEAD', 'url':'/m2/container/ns/NS/ref/JFS', 'body':None, 'hdr':{
			'X-disallow-empty-service-list':True,
		}},
	  { 'status':404, 'body':None }),

	( { 'method':'GET', 'url':'/m2/container/', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/m2/container/ns/NS/ref/JFS', 'body':None },
	  { 'status':404, 'body':None }),

	( { 'method':'POST', 'url':'/m2/container/ns/NS/ref/JFS?action=touch', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'POST', 'url':'/m2/container/ns/NS/ref/JFS?action=purge', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'POST', 'url':'/m2/container/ns/NS/ref/JFS?action=dedup', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'POST', 'url':'/m2/container/ns/NS/ref/JFS?action=stgpol', 'body':None },
	  { 'status':400, 'body':None }), # Missing the stgpol parameter
	( { 'method':'POST', 'url':'/m2/container/ns/NS/ref/JFS?action=stgpol&stgpol=NONE', 'body':None },
	  { 'status':404, 'body':None }),

	( { 'method':'PUT', 'url':'/m2/container/ns/NS/ref/JFS', 'body':None },
	  { 'status':403, 'body':None }), # Reference not created
	( { 'method':'PUT', 'url':'/dir/ref/ns/NS/ref/JFS', 'body':None },
	  { 'status':200, 'body':None }),
		( { 'method':'PUT', 'url':'/m2/container/ns/NS/ref/JFS', 'body':None },
		  { 'status':403, 'body':None }), # Reference created but no meta2 linked
		( { 'method':'POST', 'url':'/dir/srv/ns/NS/ref/JFS/type/meta2?action=link', 'body':None, },
		  { 'status':200, 'body':None }),

			( { 'method':'POST', 'url':'/m2/container/ns/NS/ref/JFS?action=touch', 'body':None },
			  { 'status':404, 'body':None }),
			( { 'method':'POST', 'url':'/m2/container/ns/NS/ref/JFS?action=purge', 'body':None },
			  { 'status':404, 'body':None }),
			( { 'method':'POST', 'url':'/m2/container/ns/NS/ref/JFS?action=dedup', 'body':None },
			  { 'status':404, 'body':None }),
			( { 'method':'POST', 'url':'/m2/container/ns/NS/ref/JFS?action=stgpol&stgpol=NONE', 'body':None },
			  { 'status':404, 'body':None }),

			( { 'method':'PUT', 'url':'/m2/container/ns/NS/ref/JFS', 'body':None },
			  { 'status':200, 'body':None }), # Reference created but no meta2 linked

				( { 'method':'POST', 'url':'/m2/container/ns/NS/ref/JFS?action=touch', 'body':None },
				  { 'status':200, 'body':None }),
				( { 'method':'POST', 'url':'/m2/container/ns/NS/ref/JFS?action=purge', 'body':None },
				  { 'status':200, 'body':None }),
				( { 'method':'POST', 'url':'/m2/container/ns/NS/ref/JFS?action=dedup', 'body':None },
				  { 'status':200, 'body':None }),
				( { 'method':'POST', 'url':'/m2/container/ns/NS/ref/JFS?action=stgpol&stgpol=NONE', 'body':None },
				  { 'status':200, 'body':None }),
				( { 'method':'POST', 'url':'/m2/container/ns/NS/ref/JFS?action=stgpol&stgpol=NOTFOUND', 'body':None },
				  { 'status':500, 'body':None }),

			( { 'method':'DELETE', 'url':'/m2/container/ns/NS/ref/JFS', 'body':None },
			  { 'status':200, 'body':None }), # Reference created but no meta2 linked
		( { 'method':'DELETE', 'url':'/dir/srv/ns/NS/ref/JFS/type/meta2', 'body':None, },
		  { 'status':200, 'body':None }),
	( { 'method':'DELETE', 'url':'/dir/ref/ns/NS/ref/JFS', 'body':None },
	  { 'status':200, 'body':None }),

	( { 'method':'GET', 'url':'/m2/content', 'body':None },
	  { 'status':404, 'body':None }),
	( { 'method':'GET', 'url':'/m2/content/', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/m2/content/ns/NS', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/m2/content/ns/NS/ref/JFS', 'body':None },
	  { 'status':400, 'body':None }),
	( { 'method':'GET', 'url':'/m2/content/ns/NS/ref/JFS/path/plop', 'body':None },
	  { 'status':404, 'body':None }),

	( { 'method':'PUT', 'url':'/m2/content/ns/NS/ref/JFS/path/plop', 'body':None },
	  { 'status':400, 'body':None }), # Missing body

	( { 'method':'PUT', 'url':'/m2/content/ns/XXX/ref/JFS/path/plop', 'body':None },
	  { 'status':404, 'body':None }), # Namespace not managed

	( { 'method':'PUT', 'url':'/m2/content/ns/NS/ref/JFS/path/plop', 'body':{
				"beans" : {
					"aliases" : [
						{ "name":"plop", "ver":0, "ctime":1, "header":"00", "system_metadata":"plop=plop"}
					],
					"headers" : [
						{ "id":"00", "hash":"00000000000000000000000000000000", "size":0 }
					],
					"contents" : [
						{ "hdr":"00", "pos":"0", "chunk":"http://127.0.0.1:6014/DATA/NS/localhost/rawx-2/0000000000000000000000000000000000000000000000000000000000000000" }
					],
					"chunks" : [
						{ "id":"http://127.0.0.1:6014/DATA/NS/localhost/rawx-2/0000000000000000000000000000000000000000000000000000000000000000", "hash":"00000000000000000000000000000000", "size":0 }
					]
				}
			}
		},
	  {'status':404}),

	# Create the reference
	( { 'method':'PUT', 'url':'/dir/ref/ns/NS/ref/JFS', 'body':None },
	  { 'status':200, 'body':None }),
		# Ensure a meta2 is linked
		( { 'method':'POST', 'url':'/dir/srv/ns/NS/ref/JFS/type/meta2?action=link', 'body':None, },
		  { 'status':200, 'body':None }),
			# Create the container
			( { 'method':'PUT', 'url':'/m2/container/ns/NS/ref/JFS', 'body':None },
			  { 'status':200, 'body':None }), # Reference created but no meta2 linked
				# Content not found
				( { 'method':'GET', 'url':'/m2/content/ns/NS/ref/JFS/path/plop', 'body':None },
				  { 'status':404, 'body':None }),
				# Regular PUT that should work
				( { 'method':'PUT', 'url':'/m2/content/ns/NS/ref/JFS/path/plop', 'body':{
							"beans" : {
								"aliases" : [
									{ "name":"plop", "ver":0, "ctime":1, "header":"00", "system_metadata":"key0=value0"}
								],
								"headers" : [
									{ "id":"00", "hash":"00000000000000000000000000000000", "size":0 }
								],
								"contents" : [
									{ "hdr":"00", "pos":"0", "chunk":"http://127.0.0.1:6014/DATA/NS/localhost/rawx-2/0000000000000000000000000000000000000000000000000000000000000000" }
								],
								"chunks" : [
									{ "id":"http://127.0.0.1:6014/DATA/NS/localhost/rawx-2/0000000000000000000000000000000000000000000000000000000000000000", "hash":"00000000000000000000000000000000", "size":0 }
								]
							}
						}
					},
				  {'status':200}),
				( { 'method':'GET', 'url':'/m2/content/ns/NS/ref/JFS/path/plop', 'body':None },
				  { 'status':200, 'body':None }),
				( { 'method':'GET', 'url':'/m2/container/ns/NS/ref/JFS', 'body':None },
				  { 'status':200, 'body':None }),

				( { 'method':'POST', 'url':'/m2/content/ns/NS/ref/JFS/path/plop?action=stgpol&stgpol=NONE', 'body':None },
				  { 'status':200, 'body':None }),

				( { 'method':'DELETE', 'url':'/m2/content/ns/NS/ref/JFS/path/plop', 'body':None },
				  { 'status':200, 'body':None }),

				( { 'method':'POST', 'url':'/m2/content/ns/NS/ref/JFS/path/plop', 'body':None },
				  { 'status':400, 'body':None }), # Missing action
				( { 'method':'POST', 'url':'/m2/content/ns/NS/ref/JFS/path/plop?action=beans', 'body':None },
				  { 'status':400, 'body':None }), # Missing size
				( { 'method':'POST', 'url':'/m2/content/ns/NS/ref/JFS/path/plop?action=beans&size=1024', 'body':None },
				  { 'status':200, 'body':None }),

				( { 'method':'POST', 'url':'/m2/content/ns/NS/ref/JFS/path/plop?action=touch', 'body':None },
				  { 'status':200, 'body':None }),

				( { 'method':'POST', 'url':'/m2/content/ns/NS/ref/JFS/path/plop?action=stgpol', 'body':None },
				  { 'status':400, 'body':None }), # Missing storage policy
				( { 'method':'POST', 'url':'/m2/content/ns/NS/ref/JFS/path/plop?action=stgpol&stgpol=XXX', 'body':None },
				  { 'status':500, 'body':None }), # Invalid storage policy or content not found

			( { 'method':'DELETE', 'url':'/m2/container/ns/NS/ref/JFS', 'body':None },
			  { 'status':200, 'body':None }),
		( { 'method':'DELETE', 'url':'/dir/srv/ns/NS/ref/JFS/type/meta2', 'body':None, },
		  { 'status':200, 'body':None }),
	( { 'method':'DELETE', 'url':'/dir/ref/ns/NS/ref/JFS', 'body':None },
	  { 'status':200, 'body':None }),

#	### PUT on a rawx not registered.
#	( { 'method':'POST', 'url':'/m2/put/ns/NS/ref/JFS', 'body':{
#				"beans" : {
#					"aliases" : [
#						{ "name":"content", "ver":0, "ctime":1, "header":"00", "system_metadata":"plop=plop"}
#					],
#					"headers" : [
#						{ "id":"00", "hash":"00000000000000000000000000000000", "size":0 }
#					],
#					"contents" : [
#						{ "hdr":"00", "pos":"0", "chunk":"http://127.0.0.1:1025/DATA/NS/localhost/rawx-2/0000000000000000000000000000000000000000000000000000000000000000" }
#					],
#					"chunks" : [
#						{ "id":"http://127.0.0.1:1025/DATA/NS/localhost/rawx-2/0000000000000000000000000000000000000000000000000000000000000000", "hash":"00000000000000000000000000000000", "size":0 }
#					]
#				}
#			}
#		}, {'status':200,'body':{'status':200} }),
#
#	### PUT with no chunk linked to the alias
#	( { 'method':'POST', 'url':'/m2/put/ns/NS/ref/JFS', 'body':{
#				"beans" : {
#					"aliases" : [
#						{ "name":"content", "ver":0, "ctime":1, "header":"00", "system_metadata":"plop=plop"}
#					],
#					"headers" : [
#						{ "id":"00", "hash":"00000000000000000000000000000000", "size":0 }
#					],
#					"contents" : [
#						{ "hdr":"00", "pos":"0", "chunk":"http://127.0.0.1:6014/DATA/NS/localhost/rawx-2/0000000000000000000000000000000000000000000000000000000000000000" }
#					],
#					"chunks" : [
#						{ "id":"http://127.0.0.1:1025/DATA/NS/localhost/rawx-2/0000000000000000000000000000000000000000000000000000000000000000", "hash":"00000000000000000000000000000000", "size":0 }
#					]
#				}
#			}
#		}, {'status':200,'body':{'status':400} }),
#
#	( { 'method':'POST', 'url':'/m2/append/ns/NS/ref/JFS', 'body':{
#				"beans" : {
#					"aliases" : [
#						{ "name":"content", "ver":0, "ctime":1, "header":"00", "system_metadata":"plop=plop"}
#					],
#					"headers" : [
#						{ "id":"00", "hash":"00000000000000000000000000000000", "size":0 }
#					],
#					"contents" : [
#						{ "hdr":"00", "pos":"0", "chunk":"http://127.0.0.1:6014/DATA/NS/localhost/rawx-2/0000000000000000000000000000000000000000000000000000000000000000" }
#					],
#					"chunks" : [
#						{ "id":"http://127.0.0.1:1025/DATA/NS/localhost/rawx-2/0000000000000000000000000000000000000000000000000000000000000000", "hash":"00000000000000000000000000000000", "size":0 }
#					]
#				}
#			}
#		}, {'status':200,'body':{'status':400}})
]

def _body (i):
	if not 'body' in i:
		return ''
	if i['body'] is None:
		return ''
	return json.dumps(i['body'])
	
def _headers (i):
	h = {}
	if 'hdr' in i:
		for k,v in i['hdr'].items():
			h [str(k)] = str(v)
	return h

def run_test_suite (addr, suite):
	count = 0
	for i, o in suite:
		url = urlparse.urlparse('http://' + str(addr) + '/' + PREFIX + '/' + i['url'])
		print "\n", repr(i), "\n", repr(o)
		cnx = httplib.HTTPConnection(url.netloc)
		u = url.path
		if url.query:
			u = u + '?' + url.query
		cnx.request(i['method'], u, _body(i), _headers(i))
		resp = cnx.getresponse()
		status, reason, body = resp.status, resp.reason, resp.read()
		cnx.close()
		print '***', status, reason, repr(body)
		decoded = None
		if body is not None and body:
			decoded = json.loads(body)
		if status != o['status']:
			raise Exception('Bad status at {0}, {1} instead of {2}'.format(count, status, o['status']))
		if 'body' in o and o['body'] is not None:
			for k in o['body']:
				if o['body'][k] != decoded[k]:
					raise Exception('Bad body at {0}'.format(count))
		count += 1


def run (addr):
	run_test_suite(addr, suite_cs)
	run_test_suite(addr, suite_dir)
	run_test_suite(addr, suite_meta2)

if __name__ == '__main__':
	metacd = sys.argv[1]
	for i in range(3):
		run(metacd)

