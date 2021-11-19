# Contributing

## Coding style
### C code

Existing code style may not be consistent everywhere. We provide a
configuration file for [indent](./.indent.pro) that should be OK for
new files. Be careful when applying it on existing files, ``indent`` may be
zealous and modify more lines than expected.

### Python code

The code must comply with [PEP8](https://www.python.org/dev/peps/pep-0008/).
Running ``tox -e pep8`` will tell what is wrong
(this will actually run ``flake8``).

Running pylint on your code is also a good practice.


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

## Pull requests

### Target branch

Pull requests implementing new features should be targeted at the master
branch.

Pull requests fixing bugs should be targeted at the maintenance branch for the
version you are using. Or better, if it applies, targeted at the oldest alive
maintenance branch (end-of-life branches have the prefix "eol-").
Old maintenance branches are merged into more recent branches from time to
time.

### Merge strategy

OpenIO's maintainers usually rebase and merge pull requests (instead of just
merging them). This avoids creating too many merge commits, since pull requests
often contain only one commit.

### Tips

When creating the pull request on GitHub, please select
"Allow edits from maintainers." so the maintainers can rebase it if needed.

If a pull request is still work-in-progress, prefix the title with "[WIP]",
and the maintainers won't touch it.


## Pre-commit hooks

There is a bunch of things you can add at the end of ``.git/hooks/pre-commit``:

- The [typos](https://github.com/crate-ci/typos) utility will check for typos.
- The script [oio-check-copyright.sh](./tools/oio-check-copyright.sh) will
  detect any missing or out-of-date copyright mention.
- Tox' pep8 environment will check for coding style issues in Python files.

Copy (or rename) ``.git/hooks/pre-commit.sample`` to ``.git/hooks/pre-commit``,
and add this at the end:

```bash
MODIFIED_FILES="$(git diff --diff-filter=d --name-only $against | grep -E -e '.py$' -e '.c$' -e '.h$' -e '.sh$' -e '.go$' || true)"
MODIFIED_PY_FILES="$(git diff --diff-filter=d --name-only $against | grep -E -e '.py$' || true)"
if [ -n "$MODIFIED_FILES" ]
then
    typos $MODIFIED_FILES
    ./tools/oio-check-copyright.sh $MODIFIED_FILES
fi
if [ -n "$MODIFIED_PY_FILES" ]
then
    tox -e pep8 -- $MODIFIED_PY_FILES
fi
```
