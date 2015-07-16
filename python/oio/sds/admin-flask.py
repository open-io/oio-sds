#!/usr/bin/python

# standard modules
import traceback, json
import requests, flask
import oio.config

app = flask.Flask(__name__)

class NotFound (Exception):
	pass

cfg = oio.config.load()

def endpoint (ns):
	return 'http://' + parser.get(ns, "endpoint")

def stat_container (session, ns, ref):
	ENDPOINT = endpoint(ns)
	raw = {
		"directory":{
			"meta0":None,
			"meta1":None,
			"services":{
				"meta2":None,
			},
			"properties":{
			},
		},
		"container":None
	}
	# Check the container exist and get its services
	r = session.get(ENDPOINT + '/v1.0/dir/{0}/{1}'.format(ns,ref))
	if r.status_code / 100 != 2: # container/content not found
		raise NotFound("Reference or container not found")
	# Extract its services
	decoded = r.json()
	for srv in decoded['dir']:
		raw['directory'][srv['type']] = srv['host']
	for srv in decoded['srv']:
		raw['directory']['services'][srv['type']] = srv['host']
	# Get the reference's properties
	r = session.post(ENDPOINT + '/v1.0/dir/{0}/{1}/action'.format(ns,ref),
			json.dumps({ 'action':'GetProperties', 'args':[], }))
	if r.status_code / 100 != 2:
		raw['directory']['properties'] = r.text
	else:
		raw['directory']['properties'] = r.json()
	# If a meta2 is present, get the container's properties
	if raw['directory']['services']['meta2'] is not None:
		r = session.head(ENDPOINT + '/v1.0/m2/{0}/{1}'.format(ns,ref))
		if r.status_code / 100 != 2:
			raw['container'] = r.json()
		else:
			prefix = "x-oio-container-meta-"
			raw['container'] = {'properties':{}}
			for k,v in r.headers.items():
				if not k.lower().startswith(prefix):
					continue
				k = k[len(prefix):]
				raw['container']['properties'][k] = str(v)
	return raw

def stat_content (session, ns, ref, path):
	ENDPOINT = endpoint(ns)
	r = session.get(ENDPOINT + '/v1.0/m2/{0}/{1}/{2}'.format(ns,ref,path))
	if r.status_code / 100 == 2:
		return r.json()
	else:
		return '"' + str(r.text) + '"'

@app.route('/v1.0/admin/info/<ns>/<ref>', methods=['GET'])
def info_container (ns,ref):
	try:
		session = requests.Session()
		raw = stat_container (session, ns, ref)
		return flask.Response(json.dumps(raw), mimetype='text/json')
	except cfg.NoOptionError as e:
		return "Namespace unknown", 502
	except:
		return traceback.format_exc(), 500

@app.route('/v1.0/admin/info/<ns>/<ref>/<path>', methods=['GET'])
def info_content (ns,ref,path):
	try:
		session = requests.Session()
		raw = stat_container (session, ns, ref)
		raw['content'] = stat_content (session, ns, ref, path)
		return flask.Response(json.dumps(raw), mimetype='text/json')
	except NotFound as e:
		return "Object not found", 404
	except cfg.NoOptionError as e:
		return "Namespace unknown", 502
	except:
		return traceback.format_exc(), 500

@app.route('/v1.0/admin/container/<ns>/<ref>', methods=['MOVE'])
def move_container (ns,ref):
	try:
		ENDPOINT = endpoint(ns)
		session = requests.Session()
		# ensure the container exists
		r = session.head(ENDPOINT + '/v1.0/m2/{0}/{1}'.format(ns,ref))
		if r.status_code / 100 != 2:
			return r.text, r.status_code

		# Freeze the source
		r = session.post(ENDPOINT + '/v1.0/sqlx/{0}/{1}/meta2/1/action'.format(ns,ref),
				json.dumps({"action":"Freeze","args":None}))
		if r.status_code / 100 != 2:
			return r.text, r.status_code

		# poll a new location
		r = session.post(ENDPOINT + '/v1.0/dir/{0}/{1}/meta2/action'.format(ns,ref),
				json.dumps({"action":"Renew","args":None}))
		if r.status_code / 100 == 2:
			decoded = r.json()
			item = decoded[0]
			# make the move now
			r = session.post(ENDPOINT + '/v1.0/sqlx/{0}/{1}/meta2/1/action'.format(ns,ref),
					json.dumps({"action":"CopyTo","args":item["host"]}))
			if r.status_code / 100 == 2:
				# enables the target
				r = session.post(ENDPOINT + '/v1.0/sqlx/{0}/{1}/meta2/1/action'.format(ns,ref),
						json.dumps({"action":"Enable","args":None}))
				if r.status_code / 100 == 2:
					# Success !
					return r.text, r.status_code
				else:
					# TODO retry on network error
					pass
				# TODO Delete the copy ?
			# TODO unregister the new location
		# TODO re-enables the old service	
	except:
		return traceback.format_exc(), 500

@app.route('/v1.0/admin/chunk/<ns>/<ref>/<path>', methods=['MOVE'])
def move_chunk (ns,ref,path):
	try:
		params = flask.request.get_json(force=True)
		if not isinstance(params,dict):
			raise Exception("Invalid JSON object in body")
		ENDPOINT = endpoint(ns)
		return "NYI", 200
	except:
		return traceback.format_exc(), 500

@app.route('/v1.0/admin/election/<ns>/<ref>/<srvtype>', methods=['GET', 'DELETE'])
def delete_election (ns,ref,srvtype):
	"""Debugs or Delete an election"""
	pass

