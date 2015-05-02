#!/usr/bin/python

# account-server.py, a script managing a backend of services.
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

import json, sqlite3
import flask

app = flask.Flask(__name__)

class Argl(Exception):
	def __init__(self, c=500, m="Argl"):
		Exception.__init__(self)
		self.message = str(m)
		self.status_code = c
	def __str__ (self):
		return self.message
	def __repr__(self):
		return self.__class__.__name__ + '/' + repr(self.to_dict())
	def to_dict(self):
		return {"message":self.message, "status":self.status_code}

class DB(object):
	def __init__(self):
		self.db = sqlite3.connect('/tmp/accounts.sqlite')
	def __enter__(self):
		#print repr(self), '__enter__'
		return self.db
	def __exit__(self, t, v, tb):
		#print repr(self), '__exit__', repr(t), repr(v)
		self.db.close()

with DB() as db:
	db.execute("CREATE TABLE IF NOT EXISTS items(key BLOB PRIMARY KEY, value BLOB NOT NULL)")

# Helpers ----------------------------------------------------------------------

CODE_SYSTEM_ERROR = 501
CODE_ACCOUNT_NOTFOUND = 431
CODE_USER_NOTFOUND = 432

account_fields = [ 'name', 'ctime',
	'user-count', 'container-count', 'content-count', 'bytes-count',
	'storage-policy', 'properties' ]

user_fields = [ 'name', 'ctime',
	'container-count', 'content-count', 'bytes-count',
	'properties' ]

container_fields = [
	'ns', 'account', 'reference', 'type',
	'object-count', 'bytes-count', 'ctime',
	'properties' ]

def key_account(account):
	return str(account)

def key_user(account, user):
	return '|'.join((account, user))

def key_container(account, user, container):
	return '|'.join((account, user, container))

def update_item (cursor, k, v):
	cursor.execute("INSERT OR UPDATE INTO items VALUES (?,?)", (k,v))

def create_item (cursor, k, v):
	cursor.execute("INSERT OR ABORT INTO items VALUES (?,?)", (k,v))

def get_item (cursor, k):
	cursor.execute("SELECT value FROM items WHERE key = ? LIMIT 1",(k,))
	for t in cursor:
		return json.loads(t[0])
	return None

def list_prefixed_items (cursor, prefix):
	cursor.execute("SELECT key, value FROM items WHERE key >= ? ORDER BY key ASC",(prefix,))
	for key, value in cursor:
		if not key.startswith(prefix):
			return
		decoded = json.loads(raw)
		yield (key, json.dumps(value))

def check_account_presence (cursor, account):
	account_data = get_item(cursor, key_account (account))
	if account_data is None:
		raise Argl(c=CODE_ACCOUNT_NOTFOUND, m="Account not found")

def check_user_presence (cursor, account, user):
	print "Checking", str(account), str(user)
	account_data = get_item(cursor, key_user (account, user))
	if account_data is None:
		raise Argl(c=CODE_USER_NOTFOUND, m="User not found")

def patch_dict (base, keys):
	for k in keys:
		if k not in base:
			base[k] = None

def check_account_content (h):
	global account_fields
	patch_dict (h, account_fields)

def check_user_content (h):
	global user_fields
	patch_dict (h, user_fields)

def check_container_content (h):
	global container_fields
	patch_dict (h, container_fields)

#@app.teardown_request
#def patch_code(exc):
#	print "plop", repr(exc)
#	return flask.Response("\n".join(items), status=exc.status_code, mimetype='text/json')

# Accounts ---------------------------------------------------------------------

@app.route('/status', methods=['GET', 'HEAD'])
def status ():
	items = list()
	with DB() as db:
		cursor = db.cursor()
		cursor.execute("SELECT COUNT(*) FROM items")
		for t in cursor:
			items.append("account.items.count = " + str(t[0]))
	return flask.Response("\n".join(items), mimetype='text/json')

@app.route('/v1.0/account/<ns>/<account>', methods=['PUT', 'POST'])
def account_create(ns, account):
	decoded = flask.request.get_json(force=True)
	with DB() as db:
		update_item(db.cursor(), key_account(account), json.dumps(decoded))
		db.commit()
	return ""

@app.route('/v1.0/account/<ns>/<account>', methods=['GET', 'HEAD'])
def account_info(ns, account):
	with DB() as db:
		raw = get_item(db.cursor(), key_account(account))
		if raw is not None:
			return flask.Response(json.dumps(raw), mimetype='text/json')
		return "Account not found", 404
	return "DB not found", CODE_SYSTEM_ERROR

@app.route('/v1.0/account/<ns>/<account>#users', methods=['GET'])
def account_list_users(ns, account):
	with DB() as db:
		cursor = db.cursor()
		check_account_presence (cursor, account)
		result = list()
		for key,_ in list_prefixed_items (cursor, k + '|'):
			tokens = key.split('|')
			if len(tokens) != 2:
				continue
			result.append(tokens[1])
		return flask.Response('['+",".join(result)+']', mimetype='text/json')

@app.route('/v1.0/account/<ns>/<account>#containers', methods=['GET'])
def account_list_containers(ns, account):
	with DB() as db:
		cursor = db.cursor()
		check_account_presence (cursor, account)
		result = list()
		for key,_ in list_prefixed_items (cursor, k + '|'):
			tokens = key.split('|')
			if len(tokens) != 3:
				continue
			result.append(tokens[2])
		return flask.Response('['+",".join(result)+']', mimetype='text/json')

# Users ------------------------------------------------------------------------

@app.route('/v1.0/account/<ns>/<account>/<user>', methods=['PUT', 'POST'])
def user_create(ns, account, user):
		decoded = flask.request.get_json(force=True)
		check_user_content (decoded)
		with DB() as db:
			cursor = db.cursor()
			check_account_presence (cursor, account)
			update_item (cursor, key_user(account, user), json.dumps(decoded))
			db.commit()
		return ""

@app.route('/v1.0/account/<ns>/<account>/<user>', methods=['GET', 'HEAD'])
def user_info(ns, account, user):
	with DB() as db:
		cursor = db.cursor()
		check_account_presence (cursor, account)
		raw = get_item(cursor, key_user(account, user))
		if raw is not None:
			return flask.Response(json.dumps(raw), mimetype='text/json')
		return "User not found", 404
	return "DB not found", CODE_SYSTEM_ERROR

@app.route('/v1.0/account/<ns>/<account>/<user>#containers', methods=['GET'])
def user_list_containers(ns, account, user):
	with DB() as db:
		cursor = db.cursor()
		check_account_presence (cursor, account)
		check_user_presence (cursor, account, user)
		result = list()
		for key,_ in list_prefixed_items (cursor, key_user(account, user) + '|'):
			tokens = key.split('|')
			if len(tokens) != 3:
				continue
			result.append(tokens[2])
		return flask.Response('['+",".join(result)+']', mimetype='text/json')

# Containers -------------------------------------------------------------------

@app.route('/v1.0/account/<ns>/<account>/<user>/<container>', methods=['GET', 'HEAD'])
def container_info(ns, account, user, container):
	with DB() as db:
		cursor = db.cursor()
		check_account_presence (cursor, account)
		check_user_presence (cursor, account, user)
		raw = get_item(cursor, key_container(account, user, container))
		if raw is not None:
			return flask.Response(json.dumps(raw), mimetype='text/json')
		return "Container not found", 404
	return "DB not found", CODE_SYSTEM_ERROR

@app.route('/v1.0/account/<ns>/<account>/<user>/<container>', methods=['PUT', 'POST'])
def container_update(ns, account, user, container):
	try:
		decoded = flask.request.get_json(force=True)
		check_container_content (decoded)
		with DB() as db:
			cursor = db.cursor()
			check_account_presence (cursor, account)
			check_user_presence (cursor, account, user)
			update_item (cursor, key_container (account, user, container),
					json.dumps(decoded))
			db.commit()
	except Argl as e:
		code = 404
		if e.status_code in (CODE_ACCOUNT_NOTFOUND, CODE_USER_NOTFOUND):
			code = 403
		return repr(e.to_dict()), code
	return ""

