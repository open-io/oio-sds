# PROXY protocol

OIO-SDS provides a proxy service for all its internal services.
The interface tends to be as restful as possible, where each URL identifies a resource.

When specific actions are proposed on a main resource, this is through POST methods on a special resource : the token "action" is suffixed to the path of the main resource.
Then there is a convention to encode the ation : the body of the request contains a JSON object with (at least) two fields: "action" and "args". "action" is a string valued to the name of the action, and "args" is wathever expected by the action.

All the route presented below are prefixed with a common prefix that denotes the version of the protocol.
We are currently using the "/v2.0" prefix.

## Conscience resources

### Namespaces ``/cs/{NS}``
  * **GET** Gets a namespace\_info in its JSON form in the body of the reply.
  * **HEAD** Check the namespace is known

### Services pools ``/cs/{NS}/{TYPE}``
Plays on collection on services. What identifies a collection is the NS it belongs to and its type name.
  * **PUT** registers a single service in the given collection
    * input body : a JSON encoded service description. The given score will be ignored.
    E.g. ``{"ns":"NS","type":"meta2","addr":"127.0.0.1:6002","score":0, "tags":{"tag.k":"value"}}``
  * **GET** get the list of services in the collection.
    * output body : a JSON encoded array of services.
  * **HEAD** Check the service type is known for this namespace
  * **DELETE** flush a service definition or a single service

### Services pools actions ``/cs/{NS}/{TYPE}/action``
Destined for the **POST** method, the following actions are currently available:
  * **Lock** : Lock a service, the argument is expected to be a full service description (as expect by the PUT).
    Locking a service consist in forcing its score to a given value, so that is won't be updated nor expired.
    E.g. ``{ "action":"Lock", "args":{"ns":"NS","type":"meta2","addr":"127.0.0.1:6002","score":0, "tags":{"tag.k":"value"}}}``
  * **Unlock** : Unlock a service, the argument is expected to be a full service description (as expected by the PUT).
    Unlocking a service consist in letting it expire and be updated.
    E.g. ``{ "action":"Unlock", "args":{"ns":"NS","type":"meta2","addr":"127.0.0.1:6002","score":0, "tags":{"tag.k":"value"}}}``

## Directory resources

### Reference ``/dir/{NS}/{ACCOUNT}/{REF}``
  * **PUT** Reference creation
  * **DELETE** Reference destruction
  * **HEAD** Reference presence check
  * **GET** Returns an abstract of all the services related to the given reference (user).

### References actions ``/dir/{NS}/{ACCOUNT}/{REF}/action``
Destined for the **POST** method, the following actions are currently available:
  * **GetProperties** : Returns a set of properties. The argument is expected to be an array of strings (the names of the properties) or the 'null' JSON object (considered as an empty array). An empty array will cause all the properties to be returned.
    * Request body: ``{ "action":"GetProperties", "args":["key1","key2"]}``
  * **DeleteProperties** : Delete a set of properties. The argument is expected to ba an array of strings (the names of the properties).
    * Request body: ``{ "action":"DeleteProperties", "args":["key1","key2"]}``
  * **SetProperties** : sets several properties. The argument is expected to be a JSON object mapping keys (strings) to their value (string).
    * Request body: ``{ "action":"SetProperties", "args":{"key1":"value1","key2":"value2"}}``

### Services ``/dir/{NS}/{ACCOUNT}/{REF}/{TYPE}``
  * **GET** List the services of the given type linked to the given 
  * **DELETE** Removes an associated service.

### Services actions ``/dir/{NS}/{ACCOUNT}/{REF}/{TYPE}/action``
Destined for the **POST** method, the following actions are currently available:
  * **Link** : polls and associates a new service to the reference. No argument expected (it will be ignored)
    E.g. ``{"action":"Link", "args":null}``
  * **Renew** : re-pools and re-associates a set of services to the reference. No argument expected (ignored).
    E.g. ``{"action":"Renew", "args":null}``
  * **Force** : associates the given set of services to the reference, for the given type. The expected argument is a set of service encoded in the meta1-url form.
    E.g. : ``{"action":"Force", "args":{"seq":1, "type":"$TYPE", "host":"127.0.0.1:22,127.0.0.1:23","args:""}}``
    * Optional Header **X-oio-action-mode: replace** If present, it allows the service to be replaced for the given reference and sequence number. If absent, it will be an error to insert the same entry twice.

### Shortcuts resources

#### ``/dir/{NS}/{CID}``
  * **GET** resolves the URL components or this container ID. If you don't know what a contaier ID is, this route is not for you.

## Meta2 resources

### Containers  ``/m2/{NS}/{ACCOUNT}/{REF}``
  * **HEAD** container existence check
  * **PUT** container creation. No input expected.
    * Optional Header **X-oio-action-mode: autocreate**
  * **GET** container listing. A few options a allowed as query options
    * **marker** list items lexically strictly greater than the marker (incompatible  with a prefix)
    * **marker_end** list items lexically lower than the marker
    * **prefix** list items whose name is prefixed by the given value.
    * **delimiter** single character to avoid in the portion of the name after the prefix. This helps emulating directory listing.
    * **max** limit to this number of keys
    * **deleted** also includ edeleted items (TRUE if present, FALSE if absent)
    * **all** also include past versions (TRUE if present, FALSE if absent)
    * Output body : ``{"prefixes":["a/","b/","c/"],"objects":[...]}``
    * Optional Header **X-oio-list-chunk-id: XXX**
    * Optional Header **X-oio-list-content-hash: XXX**
  * **DELETE** container existence check

### Containers actions ``/m2/{NS}/{ACCOUNT}/{REF}/action``
For **POST** methods only.

The following actions are currently available:
  * **Touch** : notifies the container to regenerates events for all its contents.
    E.g. ``{"action":"Touch"}``
  * **Dedup** : Call a deduplication round on the whole container.
    E.g. ``{"action":"Dedup"}``
  * **Purge** : Call a purge round on the whole container
    E.g. ``{"action":"Purge"}``
  * **SetStoragePolicy** : Change the default storage policy applied to new contents in the container
    E.g. ``{"action":"SetStoragePolicy", "args":"SOMESTORAGEPOLICY"}``
  * **GetProperties** :
    * Request body: ``{"action":"GetProperties","args":null}``
    * Reply body: ``{"k0":"v0","k1":"v1"}``
  * **SetProperties** :
    * Request body: ``{"action":"SetProperties","args":{"k0":"v0","k1":"v1"}}``
    * Reply body: none expected
  * **DelProperties** :
    * Request body: ``{"action":"DelProperties","args":["k0","k1"]}``
    * Reply body: none expected
  * **RawInsert** : 
    E.g. ``{"action":"RawInsert", "args":[
      {"type":"alias", ...},
      {"type":"header", ...},
      {"type":"content", ...},
      {"type":"chunk", ...}
]}``
  * **RawDelete** : 
    E.g. ``{"action":"RawDelete", "args":[
      {"type":"alias", ...},
      {"type":"header", ...},
      {"type":"content", ...},
      {"type":"chunk", ...}
]}``
  * **RawUpdate** : 
    E.g. ``{
    "action": "RawUpdate",
    "args": {
        "new": [
            {
                "hash": "BBCE6462DF72747CE27340570E6CE5EB",
                "id": "http://127.0.0.1:6015/A480C04C36464FB5D7A8AE21B960F87AE1720F9BFB8CC6416644DE8B3C972793",
                "pos": "0",
                "size": 1684,
                "type": "chunk"
            }
        ],
        "old": [
            {
                "hash": "BBCE6462DF72747CE27340570E6CE5EB",
                "id": "http://127.0.0.1:6015/A480C04C36464FB5D7A8AE21B960F87AE1720F9BFB8CC6416644DE8B3C972793",
                "pos": "0",
                "size": 1684,
                "type": "chunk"
            }
        ]
    }
}``

### Contents ``/m2/{NS}/{ACCOUNT}/{REF}/{PATH}``
  * **HEAD** Check for the content presence
  * **GET** Fetch the locations of the chunks belonging to the specified content. Some options are available:
    * **deleted** : set to (yes|true|1|on) to ignore the "deleted" flag set on contents. If not set or set to another value, a deleted content will be considered missing and trigger a 404 error reply.
  * **PUT** Store a new set of beans. This set of beans must be a coherent set of aliases.
    * Mandatory header **X-oio-content-meta-length: XXX**
	* Optional header **X-oio-content-meta-chunk-method: XXX**
	* Optional header **X-oio-content-meta-type: XXX**
	* Optional header **X-oio-content-type: XXX**
    * Optional header **X-oio-content-meta-policy: XXX**
    * Optional header **X-oio-content-meta-hash: XXX**
	* Optional header **X-oio-content-meta-x-Key: Value**
    * Optional header **X-oio-action-mode: force, append, autocreate**
  * **DELETE** 
  * **COPY** Copy the content pointed by the URL to another pointed by the "Destination:" header.

### Contents actions ``/m2/{NS}/{ACCOUNT}/{REF}/{PATH}/action``
Only for **POST** requests.

Currently suppported actions are:
  * **Beans** Generating places for a content.
    * Optional header **X-oio-action-mode: autocreate** to triggers the container's autocreation if not present.
  * **Spare** Generating additional places for a content, keeping a few, avoiding few others. The new set of places will respect the storage policy.
  * **Touch** : Touch a content
  * **SetStoragePolicy** : Change a content's storage policy
  * **GetProperties** :
    * Request body: ``{"action":"GetProperties","args":null}``
    * Reply body: ``{"k0":"v0","k1":"v1"}``
  * **SetProperties** :
    * Request body: ``{"action":"SetProperties","args":{"k0":"v0","k1":"v1"}}``
    * Reply body: none expected
  * **DelProperties** :
    * Request body: ``{"action":"DelProperties","args":["k0","k1"]}``
    * Reply body: none expected

## SQLX

### Administrative actions ``/sqlx/{NS}/{ACCOUNT}/{REF}/{TYPE}/{SEQ}/action``
Only for **POST** requests.

Currently suppported actions are:
  * **Ping** : Sends an applicative ping to all the bases 
  * **Status** : Get the perceived status from all the bases.
  * **Leanify** : Make the base more lean. In other words, make it drop as many cache entries as possible.
  * **Resync** : No-Op on a MASTER, it makes a SLAVE base resync on the MASTER.
  * **Leave** : Make the base cleanly leave it's election, if replicated.
  * **Debug** : Describes the internal status of the base, the last events it managed, etc.
  * **CopyTo** : Copies the base from one of its current places to the given place. The target is the string provided as action argument.
    E.g. ``{"action":"CopyTo","args":"127.0.0.1:5000"}``
  * **SetProperties** : 
    E.g. ``{"action":"SetProperties","args":{"key0":"value0","key1":"value1"}}``
  * **DeleteProperties** : 
    E.g. ``{"action":"DelProperties","args":["key0","key1"]}``
  * **GetProperties** : 
    E.g. ``{"action":"GetProperties","args":["key0","key1"]}``
    E.g. ``{"action":"GetProperties","args":null}``
  * **Freeze** : 
  * **Enable** : 
  * **Disable** : 
  * **DisableDisabled** : 

## Load Balancing

### Default algorithm ``/lb/{NS}/{POOL}``
Polls following the default policy for that service pool.

### Hash algorithm ``/lb/{NS}/{POOL}/{KEY}``
Peeks a random set of elements, using a weighted distribution of probabilities.

## Caches management

### Cache status ``/cache/status``
For **GET** methods only. It displays a small description of the internal cache usage.

### Cache configuration
For **POST** methods only. Currently managed:
  * URL ``/cache/flush/service/{IP:PORT}``
  * URL ``/cache/flush/local``
  * URL ``/cache/flush/low``
  * URL ``/cache/flush/high``
  * URL ``/cache/ttl/low/{INT}``
  * URL ``/cache/max/low/{INT}``
  * URL ``/cache/ttl/high/{INT}``
  * URL ``/cache/max/high/{INT}``

