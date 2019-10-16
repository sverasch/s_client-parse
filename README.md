# Overview
This project is a quick collection of scripts to take the output of `openssl s_client` and generate json to be used for further processing

# Requirements
This software was built with python 3.7.0 and optionally utilizes zcertificate https://github.com/zmap/zcertificate 

* python3 3.7.0 
* cryptography - https://pypi.org/project/cryptography/
* distance - https://pypi.org/project/Distance/ (for unit tests)
* zcertificate - https://github.com/zmap/zcertificate

# OpenSSL
To gather TLS connection data run `openssl s_client -state -prexit -showcerts -connect github.com:443 2>/dev/null`

Or redirect it to a file `openssl s_client -state -prexit -showcerts -connect github.com:443 2>/dev/null > tls-handshake.out`

```
$ head -5 handhsake.out
 
CONNECTED(00000005)
---
Certificate chain
 0 s:businessCategory = Private Organization, jurisdictionC = US, jurisdictionST = Delaware, serialNumber = 5157550, C = US, ST = California, L = San Francisco, O = "GitHub, Inc.", CN = github.com
   i:C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert SHA2 Extended Validation Server CA`
```

Or terminate the conneciton immediately by piping a Q to openssl

`echo "Q" | openssl s_client -state -prexit -showcerts -connect github.com:443 2>/dev/null`

You can then utilize openssl-parse to generate json

# openssl-parse
```usage: openssl-parse [-h] [--infile [INFILE]] [--outfile [OUTFILE]]

openssl-parse takes the output of a openssl s_client result and returns a json
object

optional arguments:
  -h, --help            show this help message and exit
  --infile [INFILE], -i [INFILE]
                        the s_client file to be used, otherwise stdin
  --outfile [OUTFILE], -o [OUTFILE]
                        the output file to write to, otherwise stdout
  --parser {zcertificate,standard}
                        choose the parser used to parse the certificate
                        information
```

If the zcertificate binary is installed, one can gain additional information about the certificates

## Pipe a file
`cat handshake.out |  ./openssl-parse`

## input a file
` ./openssl-parse --infile handshake.out`


# jpp
jpp is a utility to pretty print the outputted json to human readable format

`jpp handshake.json`

It can also be utlized inline as a stream

`cat handshake.json | jpp -`

# Combining them all

`echo "Q" | openssl s_client -state -prexit -showcerts -connect github.com:443 2>/dev/null | ./openssl-parse | ./jpp -`

Will yield a human readable json output of the tls session