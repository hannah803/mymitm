#!/bin/sh
echo EOF|openssl s_client -connect $1:443 -tls1 -cipher EXP-RC4-MD5 -msg -quiet | grep -A 21 ServerKeyExchange >> $1
