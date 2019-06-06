# FABX

## Introduction

FABX accepts 4 kinds of transactions: PUT, DELETE, GET, HEAD.

* PUT is the upload of a blob on the server. The request carries a payload but not
  the reply.
* DELETE is the removal of the blob on the server. Neither the request not the reply
  carry a payload.
* GET is the download of a blob from the service. The request carry no payload but
  the repy does. The reply also carries the metadata of the blob.
* HEAD is an existence check for a blob that returns the metadata but not the
  blob itself.

## Roadmap

* Refine both the request and reply headers for less overhead. The metadata
  sent in a PUT request should be sent in a second message, idem for the metadata
  replied on GET & APPEND requests. Those metadata are most of the space buut are
  pretty useless for 3/4 of the requests. 
* Upon a PUT, introduce a preliminary a "100-continue" reply from the server to
  ensure the service will be able to manage the data.
* Manage ranged GET requests

## Sample exchanges

Please find hereafter a description of messages exchanges, written in pseudo-json for
the sake of the readability.
 
### PUT

The request header contains the information of the block size that will be used in
in the subsequent data chunks messages. 

Client> Send FABX_REQUEST_HEADER `{version:1, type:PUT, reqid:"...", auth:"...", actual:{put:{id:"1234"}}}`
Client> Send data FABX_CHUNK `{length:4, data:"ABCD"}` 
Client> Send final empty FABX_CHUNK `{length:0, data:""}`
Server> Send FABX_REPLY_HEADER `{version:1, type:PUT, actual:{put:{status:201}}}`

### DELETE

Client> Send FABX_REQUEST_HEADER `{version:1, type:DEL, reqid:"...", auth:"...", actual:{del:{id:"1234"}}}`
Server> Send FABX_REPLY_HEADER `{version:1, type:PUT, actual:{del:{status:201}}}`

### GET

The reply header contains the information of the block size that will be used in
in the subsequent data chunks messages. 

Client> Send FABX_REQUEST_HEADER `{version:1, type:GET, reqid:"...", auth:"...", actual:{get:{id:"1234"}}}`
Server> Send FABX_REPLY_HEADER `{version:1, type:PUT, actual:{get:{status:201,...}}}`
Server> Send data FABX_CHUNK `{length:4, data:"ABCD"}`
Server> Send final empty FABX_CHUNK `{length:0, data:""}`

### HEAD

The reply header contains the information of a block size that is ignored.

Client> Send FABX_REQUEST_HEADER `{version:1, type:HEAD, reqid:"...", auth:"...", actual:{get:{id:"1234"}}}`
Server> Send FABX_REPLY_HEADER `{version:1, type:HEAD, actual:{get:{status:201,...}}}`
