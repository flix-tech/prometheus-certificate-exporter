#!/bin/bash

DIR="$(dirname $0)"
CERT_DIR=./certs
SUBJECT="/C=DE/ST=Berlin/L=Berlin/O=Platform/CN=test.flix.tech"

cd "$DIR" || exit 2

# Clean up cert index
cleanup() {
    echo "Emptying index.txt"
    rm index* || echo "Nothing deleted"
    touch index.txt index.txt.attr
}

#Clean UP
rm ./*csr ./*pem $CERT_DIR/*
cleanup

# Create $CERT_DIR
[ -d $CERT_DIR ] || mkdir $CERT_DIR

# Generate private key and CA
openssl genrsa 2048 > private.pem
openssl req -x509 -config openssl.cnf -days 1000 -new -key private.pem -out ca.pem -subj "$SUBJECT"

# Generate certificate request
openssl req -config openssl.cnf -new -key private.pem -out public.csr -subj "$SUBJECT"

# Valid certificate
cleanup
openssl ca -batch -config openssl.cnf -in public.csr -out "$CERT_DIR/valid.pem" -startdate $(date -d '-1 month' +'%Y%m%d000000Z') -enddate $(date -d '+2 year' +'%Y%m%d000000Z') -cert ca.pem -keyfile private.pem  -create_serial -subj "$SUBJECT"

# Certificate with "Not Before" date in the future
cleanup
openssl ca -batch -config openssl.cnf -in public.csr -out "$CERT_DIR/still-not-valid.pem" -startdate $(date -d '+1 year' +'%Y%m%d000000Z') -enddate $(date -d '+2 year' +'%Y%m%d000000Z') -cert ca.pem -keyfile private.pem  -create_serial -subj "$SUBJECT"

# Expired certificate
cleanup
openssl ca -batch -config openssl.cnf -in public.csr -out "$CERT_DIR/expired.pem" -startdate $(date -d '-1 year' +'%Y%m%d000000Z') -enddate $(date -d '-2 months' +'%Y%m%d000000Z') -cert ca.pem -keyfile private.pem  -create_serial -subj "$SUBJECT"
