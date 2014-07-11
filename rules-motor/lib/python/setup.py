#!/usr/bin/python

import sys
import string

def howto_install_setuptools():
	print """Error: You need setuptools Python package!"""

try:
	from setuptools import setup
	params = {
		'zip_safe': True
		}
except ImportError:
	for arg in sys.argv:
		if string.find(arg, 'egg') != -1:
			howto_install_setuptools()
			sys.exit(1)
	from distutils.core import setup
	params = {}

params.update({
	'name': 'python rules motor',
	'version': '0.0.1b',
	'description': 'rules motor python part',
	'author': 'Xin Lin',
	'license': 'Proprietary',
	'packages': ['pymotor']
	})

apply(setup, (), params);
