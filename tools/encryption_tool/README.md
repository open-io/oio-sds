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
**Stdin:**
- plaintext encrypted body
**Parameters:**
- account name
- container name
- object name
- path to object metadata json file to update with decrypted user metadata
- path to iv json file to create that will store IVs to keep for re-encryption

### Output
**Stdout:**
- plaintext decrypted body
**File:**
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
**Stdin:**
- plaintext decrypted body
**Parameters:**
- account name
- container name
- object name
- path to object metadata json file to update
- path to iv json file that stores Ivs to re-use

### Output
**Stdout:**
- plaintext body encrypted with the new key
**File:**
- metadata json file with user metadata and the following metadata encrypted
  with the new key:
    - x-object-sysmeta-container-update-override-etag
    - x-object-sysmeta-crypto-etag-mac
    - x-object-sysmeta-crypto-etag
    - x-object-sysmeta-crypto-body-meta
