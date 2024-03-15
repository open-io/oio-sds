Encryption tools
================

## Usage
- Get encrypted obj:  
`openio object save <container> <object> --file encrypted-body`  
- Write obj metadata to metadata.json :  
`./get-metadata.py --account <account> --container <container> --obj <object> > metadata.json`  
- Decrypt obj1 (decrypt object plaintext body:  
`cat encrypted-body | ./decrypter.py --account <account> --container <container> --obj <object> --metadata metadata.json --iv iv.json > decrypted-body`  
- cat decrypted object and decrypted user metadata :  
`cat decrypted-body`  
`cat metadata.json | jq | grep "keyname"`  
- Re encrypt obj :  
`cat decrypted-body | ./encrypter.py --account <account> --container <container> --obj <object> --metadata metadata.json --iv iv.json > test-reencrypted-body`  

## decrypter.py
### Input
#### Stdin:
- plaintext encrypted body
#### Parameters:
- account name
- container name
- object name
- path to object metadata json file to update with decrypted user metadata
- path to iv json file to create that will store IVs to keep for re-encryption

### Output
#### Stdout:
- plaintext decrypted body
#### File:
- metadata json file updated with decrypted user metadata
- iv json file written with the following IVs in order to re-use them during
  re-encryption:
    - body_ciphertext:      `body_iv`
    - wrapped_body_key:     `body_key_iv`
    - custom user metadata: `header_iv_1`
    - etag:                 `etag_iv`
    - override-etag:        `override-etag_iv`

## encrypter.py
### Input
#### Stdin:
- plaintext decrypted body
#### Parameters:
- account name
- container name
- object name
- path to object metadata json file to update
- path to iv json file that stores Ivs to re-use

### Output
#### Stdout:
- plaintext body encrypted with the new key
#### File:
- metadata json file with user metadata and the following metadata encrypted
  with the new key:
    - x-object-sysmeta-container-update-override-etag
    - x-object-sysmeta-crypto-etag-mac
    - x-object-sysmeta-crypto-etag
    - x-object-sysmeta-crypto-body-meta

## try_bucket_secret.py
### Example
```
#Get bucket secret form account server
$ curl "127.0.0.1:6001/v1.0/kms/get-secret?account=AUTH_demo&bucket=bucket&secret_id=0" | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   113  100   113    0     0  22600      0 --:--:-- --:--:-- --:--:-- 22600
{
  "account": "AUTH_demo",
  "bucket": "bucket",
  "secret_id": "0",
  "secret": "Xiup6SX2YpRhlIIC8+Dat3yazd3+qziiYFWgHnXcPpA="
}
#use try_bucket_secret.py to show HMAC calculated with ETag and provided key and show HMAC stored in metadata
$ cat encrypted-body | ./try_bucket_secret.py --container bucket --obj obj --metadata metadata.json --bucket_secret Xiup6SX2YpRhlIIC8+Dat3yazd3+qziiYFWgHnXcPpA=
Calculate HMAC with ETag from X-Object-Sysmeta-Crypto-Etag metadata and provided key:
+vwvg8IUMAa/mXLR7B+OEOSprvAoqojG9UKP4LYYLL8=
HMAC form X-Object-Sysmeta-Crypto-Etag-Mac metadata:
+vwvg8IUMAa/mXLR7B+OEOSprvAoqojG9UKP4LYYLL8=
```
