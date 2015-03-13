#!/usr/bin/env bash

URL=$1
curl -X GET "http://127.0.0.1:6003/v1.0/admin/info/$URL" | python -m json.tool

