#!/usr/bin/env bash

SRC=$1
DST=$2

curl -X POST \
	-d "{\"action\":\"RawUpdate\",\"args\":{\"old\":[{\"type\":\"chunk\",\"id\":\"$SRC\", \"pos\":\"0\", \"size\":1684, \"hash\":\"BBCE6462DF72747CE27340570E6CE5EB\"}],\"new\":[{\"type\":\"chunk\",\"id\":\"$DST\", \"pos\":\"0\", \"size\":1684, \"hash\":\"BBCE6462DF72747CE27340570E6CE5EB\"}]}}" \
	http://127.0.0.1:6002/v1.0/m2/NS/JFS/action \
| python -m json.tool
	
