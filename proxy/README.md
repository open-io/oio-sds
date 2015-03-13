# PROXY protocol

OIO-SDS provides a proxy service for all its internal services.
The interface tends to be as restful as possible, where each URL identifies a resource.

When specific actions are proposed on a main resource, this is through POST methods on a special resource : the token "action" is suffixed to the path of the main resource.
Then there is a convention to encode the ation : the body of the request contains a JSON object with (at least) two fields: "action" and "args". "action" is a string valued to the name of the action, and "args" is wathever expected by the action.

## Conscience resources

### Namespaces ``/cs/{NS}``
  * **GET** Gets a namespace\_info in its JSON form in the body of the reply.
  * **HEAD** Check the namespace is known

### Services pools ``/cs/{NS}/{TYPE}``
Plays on collection on services. What identifies a collection is the NS it belongs to and its type name.
  * **PUT** registers a list of services in the given collection
    * input body : a JSON encoded array of services. The given score will be ignored. (cf. below)
  * **GET** get the list of services in the collection.
    * output body : a JSON encoded array of services.
  * **HEAD** Check the service type is known for this namespace
  * **DELETE** flush a service definition or a single service

### Services pools actions ``/cs/{NS}/{TYPE}/action``
Destined for the **POST** method, the following actions are currently available:
  * **Lock** : Lock a service, the argument is expected to be a service description.
    E.g. ``{ "action":"Lock", "args":{"addr":"127.0.0.1:22", "score":1, "tags":{"tag.up":true}}}``
  * **Unlock** : Unlock a service, the argument is expected to be a service description.
    E.g. ``{ "action":"Unlock", "srv":{"addr":"127.0.0.1:22", "score":1, "tags":{"tag.up":true}}}``

## Directory resources

### Reference ``/dir/{NS}/{REF}``
  * **PUT** Reference creation
  * **DELETE** Reference destruction
  * **HEAD** Reference presence check
  * **GET** Reference presence check

### References actions ``/dir/{NS}/{REF}/action``
Destined for the **POST** method, the following actions are currently available:
  * **GetProperties** : Returns a set of properties. The argument is expected to ba an array of strings (the names of the properties).
    E.g. ``{ "action":"GetProperties", "args":["key1","key2"]}``
  * **DeleteProperties** : Delete a set of properties. The argument is expected to ba an array of strings (the names of the properties).
    E.g. ``{ "action":"DeleteProperties", "args":["key1","key2"]}``
  * **SetProperties** : sets several properties. The argument is expected to be a JSON object mapping keys (strings) to their value (string).
    E.g. ``{ "action":"SetProperties", "args":{"key1":"value1","key2":"value2"}}``

### Services ``/dir/{NS}/{REF}/{TYPE}``
  * **GET** List the associated services
  * **DELETE** Removes an associated service.

### Services actions ``/dir/{NS}/{REF}/{TYPE}/action``
Destined for the **POST** method, the following actions are currently available:
  * **Link** : polls and associates a new service to the reference. No argument expected (it will be ignored)
    E.g. ``{"action":"Link", "args":null}``
  * **Renew** : re-pools and re-associates a set of services to the reference. No argument expected (ignored).
    E.g. ``{"action":"Renew", "args":null}``
  * **Force** : associates the given set of services to the reference, for the given type. The expected argument is a set of service encoded in the meta1-url form.
    E.g. : ``{"action":"Force", "args":{"seq":1, "type":$TYPE, "host":"127.0.0.1:22,127.0.0.1:23}}``

## Meta2 resources

### Containers  ``/m2/{NS}/{REF}``
  * **HEAD** container existence check
  * **PUT** container creation. No input expected.
  * **GET** container listing. A few options a allowed as query options
    * **prefix** list items lexically greater or equal to the prefix
    * **marker** list items lexically strictly greater than the marker (incompatible  with a prefix)
    * **marker_end** list items lexically lower than the marker
    * **delimiter**
    * **max** limit to this number of keys
    * **deleted** also includ edeleted items (TRUE if present, FALSE if absent)
    * **all** also include past versions (TRUE if present, FALSE if absent)
  * **DELETE** container existence check

### Containers actions ``/m2/{NS}/{REF}/action``
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

### Contents ``/m2/{NS}/{REF}/{PATH}``
  * **HEAD** Check for the content presence
  * **GET** Fetch the locations of the chunks belonging to the specified content. Some options are available:
    * **deleted** : set to (yes|true|1|on) to ignore the "deleted" flag set on contents. If not set or set to another value, a deleted content will be considered missing and trigger a 404 error reply.
  * **PUT** Store a new set of beans. This set of beans must be a coherent set of aliases.
    * Optional Header **X-oio-mode: force**
    * Optional Header **X-oio-mode: append**
  * **DELETE** 
  * **COPY** Copy the content pointed by the URL to another pointed by the "Destination:" header.

### Contents actions ``/m2/{NS}/{REF}/{PATH}/action``
Only for **POST** requests.

Currently suppported actions are:
  * **Beans** Generating places for a content.
  * **Spare** Generating additional places for a content, keeping a few, avoiding few others. The new set of places will respect the storage policy.
  * **Touch** : Touch a content
  * **SetStoragePolicy** : Change a content's storage policy

## SQLX

### Administrative actions ``/sqlx/{NS}/{REF}/{TYPE}/{SEQ}/action``
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
    E.g. ``{"action":"PropSet","args":{"key0":"value0","key1":"value1"}}``
  * **DeleteProperties** : 
    E.g. ``{"action":"PropSet","args":["key0","key1"]}``
  * **GetProperties** : 
    E.g. ``{"action":"PropSet","args":["key0","key1"]}``
    E.g. ``{"action":"PropSet","args":null}``
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
  * URL ``/cache/flush/low``
  * URL ``/cache/flush/high``
  * URL ``/cache/ttl/low/{INT}``
  * URL ``/cache/max/low/{INT}``
  * URL ``/cache/ttl/high/{INT}``
  * URL ``/cache/max/high/{INT}``

