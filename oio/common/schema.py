# Copyright (C) 2025 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.


import json

import importlib_resources
from jsonschema import ValidationError, validate


class SchemaNotFound(Exception):
    pass


class SchemaValidationError(Exception):
    pass


class SchemaRegistry:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SchemaRegistry, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        self.__cache = {}

    def validate(self, schema_name, data):
        schema = self.get(schema_name)
        try:
            validate(instance=data, schema=schema)
        except ValidationError as exc:
            raise SchemaValidationError(
                f"Error during schema validation: {exc.message}"
            )

    def get(self, schema_name):
        if schema_name in self.__cache:
            return self.__cache[schema_name]
        _schema_name = schema_name
        if not _schema_name.endswith(".schema.json"):
            _schema_name += ".schema.json"
        ref = importlib_resources.files(__name__) / "schemas" / _schema_name
        try:
            with importlib_resources.as_file(ref) as path:
                with open(path, "r") as fp:
                    data = json.load(fp)
                    self.__cache[schema_name] = data
                    return data
        except OSError as exc:
            raise SchemaNotFound(f"Schema '{schema_name}' not found") from exc
