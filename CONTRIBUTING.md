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


## Abbreviations

When using abbreviations, try to be consistent. Here is a list of
abbreviation commonly used in the existing code base.

- acct: account
- cid: container ID
- cs: conscience
- err: error
- exc: exception
- m0: meta0
- m1: meta1
- m2: meta2
- ns: namespace
- req: request
- reqid: request ID
- resp: response
