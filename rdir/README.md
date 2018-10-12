# Reverse Directory

## Chunks Reverse Directory
_(TBD)_

## Meta2 Reverse Directory
### Objectives:
- Have a list of all containers that are supposed to be stored in each meta2
server.
- Be able to retrieve that information in a flexible manner _(supply a prefix, 
paging)_.
- Be able to rebuild a meta2 server from this reverse directory.

### How it works:
> NOTE: This solution relies on the fact that the meta2 databases can only
> be created on a meta2 master server. 
>
> If modifications are made to invalidate this assumption, modifications should 
> be made to `meta2v2/meta2_backend.c` to accomodate for such changes.

- Proxy and/or other solicitors creates a meta2 database in the master meta2
server for the content path.
- After committing the transaction the meta2 server fires a 
`storage.container.created` event, containing the content path created, and
the peers that should hold this meta2 database.
- The Event Agent intercepts this event, and make `meta2_index.py` filter
handle it.
- `meta2_index.py` calls the RdirClient to push the appropriate records.

The same is valid for container deletion, the fired event in that case being
`storage.container.deleted`, which is handled by both `account_update.py` and
`meta2_index.py`

### API Endpoints:
Four endpoints are available for the meta2 rdir API:
- __/v1/meta2/create__: Create a database to hold the records relating to a 
certain meta2 server.
- __/v1/meta2/push__: Add a record pointing to a container on a specified meta2
server.
- __/v1/meta2/delete__: Remove a record pointing to a container on a specified
meta2 server.
- __/v1/meta2/fetch__: Fetch a subset of records, that have a certain prefix, 
with paging.

Documentation for the endpoint parameters and sample requests and responses are
available in the source code in `rdir.c`.

### Tests:
The meta2 part of the Rdir has several tests, pertaining to the correctness of
API endpoints:

_(TBD, list all tests relating to this)_
