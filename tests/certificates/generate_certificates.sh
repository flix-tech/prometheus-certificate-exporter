#!/bin/bash

DIR="$(dirname $0)"
CERT_DIR=./certs
SUBJECT_CA="/C=DE/ST=Berlin/L=Berlin/O=Platform/CN=Test CA"
SUBJECT_CA_INT="/C=DE/ST=Berlin/L=Berlin/O=Platform/CN=Test CA Intermediate"
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
openssl req -x509 -config openssl.cnf -days 1000 -new -key private.pem -out ca.pem -subj "$SUBJECT_CA"

# Generate intermediate certificate and CA
openssl genrsa 2048 > int_private.pem
openssl req -x509 -config openssl.cnf -days 1000 -new -key int_private.pem -out int_ca.pem -subj "$SUBJECT_CA_INT"

# Generate expirated intermediate CA
openssl req -new -key int_private.pem -out int_ca_expired.csr -config openssl.cnf -subj "$SUBJECT_CA_INT"
openssl x509 -req -days -1 -in int_ca_expired.csr -signkey int_private.pem -out int_ca_expired.pem

# Generate certificate request
openssl req -config openssl.cnf -new -key private.pem -out public.csr -subj "$SUBJECT"

# Valid certificate
cleanup
openssl ca -batch -config openssl.cnf -in public.csr -out "$CERT_DIR/valid.pem" -startdate $(date -d '-1 month' +'%Y%m%d000000Z') -enddate $(date -d '+2 year' +'%Y%m%d000000Z') -cert ca.pem -keyfile private.pem  -create_serial -subj "$SUBJECT" -notext

# Certificate with "Not Before" date in the future
cleanup
openssl ca -batch -config openssl.cnf -in public.csr -out "$CERT_DIR/still-not-valid.pem" -startdate $(date -d '+1 year' +'%Y%m%d000000Z') -enddate $(date -d '+2 year' +'%Y%m%d000000Z') -cert ca.pem -keyfile private.pem  -create_serial -subj "$SUBJECT" -notext

# Expired certificate
cleanup
openssl ca -batch -config openssl.cnf -in public.csr -out "$CERT_DIR/expired.pem" -startdate $(date -d '-1 year' +'%Y%m%d000000Z') -enddate $(date -d '-2 months' +'%Y%m%d000000Z') -cert ca.pem -keyfile private.pem  -create_serial -subj "$SUBJECT" -notext

# Valid certificate bundle
cleanup
openssl ca -batch -config openssl.cnf -in public.csr -out "$CERT_DIR/valid_bundle.pem" -startdate $(date -d '-1 month' +'%Y%m%d000000Z') -enddate $(date -d '+2 year' +'%Y%m%d000000Z') -cert int_ca.pem -keyfile int_private.pem  -create_serial -subj "$SUBJECT" -notext
cat int_ca.pem >> "$CERT_DIR/valid_bundle.pem"

# Certificate bundle with expired intermediate
cleanup
openssl ca -batch -config openssl.cnf -in public.csr -out "$CERT_DIR/expired_int_bundle.pem" -startdate $(date -d '-1 month' +'%Y%m%d000000Z') -enddate $(date -d '+2 year' +'%Y%m%d000000Z') -cert int_ca_expired.pem -keyfile int_private.pem  -create_serial -subj "$SUBJECT" -notext
cat int_ca_expired.pem >> "$CERT_DIR/expired_int_bundle.pem"

# Generate a second certificate dir
cp -r ${CERT_DIR} ${CERT_DIR}_copy

# Generate a failing certificate dir
[ -d ${CERT_DIR}_invalid ] || mkdir ${CERT_DIR}_invalid
echo "Not a cert" > ${CERT_DIR}_invalid/not-a-cert.pem
echo "Also not a cert" > ${CERT_DIR}_invalid/wrong.suffix
[ -p ${CERT_DIR}_invalid/fifo.pem  ] || mkfifo ${CERT_DIR}_invalid/fifo.pem
[ -d ${CERT_DIR}_invalid/directory.pem ] || mkdir ${CERT_DIR}_invalid/directory.pem
