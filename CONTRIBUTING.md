# Contributing

## Coding style
### C code

Existing code style may not be consistent everywhere. We provide a
configuration file for [indent](./.indent.pro) that should be OK for
new files. Be careful when applying it on existing files, ``indent`` may be
zealous and modify more lines than expected.

### Python code

The code must comply with [PEP8](https://www.python.org/dev/peps/pep-0008/).
Running ``tox -e pep8`` will tell what is wrong.
