#!/bin/sh

DEST=../test/cert

# clean old certs
rm -f $DEST/server.* $DEST/root* $DEST/client*

# www cert
certtool --generate-privkey --outfile $DEST/server.key --bits=4096
certtool --generate-request --load-privkey $DEST/server.key --outfile $DEST/server.csr --template $DEST/template-server.cfg
certtool --generate-self-signed --load-privkey $DEST/server.key --outfile $DEST/server.crt --template $DEST/template-server.cfg

# CA root
certtool --generate-privkey --outfile $DEST/root1.key --bits=4096
certtool --generate-request --load-privkey $DEST/root1.key --outfile $DEST/root1.csr --template $DEST/template-ca.cfg
certtool --generate-self-signed --load-privkey $DEST/root1.key --outfile $DEST/root1.crt --template $DEST/template-ca.cfg

# client 1
certtool --generate-privkey --outfile $DEST/client1.key --bits=4096
certtool --generate-request --load-privkey $DEST/client1.key --outfile $DEST/client1.csr --template $DEST/template-client.cfg
certtool --generate-certificate --load-request $DEST/client1.csr --load-ca-certificate $DEST/root1.crt --load-ca-privkey $DEST/root1.key --outfile $DEST/client1.crt --template $DEST/template-client.cfg
certtool --certificate-info --infile $DEST/client1.crt --outder |base64 > $DEST/client1.crt.der

# client 2
certtool --generate-privkey --outfile $DEST/client2.key --bits=4096
certtool --generate-request --load-privkey $DEST/client2.key --outfile $DEST/client2.csr --template $DEST/template-client.cfg
certtool --generate-certificate --load-request $DEST/client2.csr --load-ca-certificate $DEST/root1.crt --load-ca-privkey $DEST/root1.key --outfile $DEST/client2.crt --template $DEST/template-client.cfg
certtool --certificate-info --infile $DEST/client2.crt --outder |base64 > $DEST/client2.crt.der

# CA root 2
certtool --generate-privkey --outfile $DEST/root2.key --bits=4096
certtool --generate-request --load-privkey $DEST/root2.key --outfile $DEST/root2.csr --template $DEST/template-ca2.cfg
certtool --generate-self-signed --load-privkey $DEST/root2.key --outfile $DEST/root2.crt --template $DEST/template-ca2.cfg

# client 3
certtool --generate-privkey --outfile $DEST/client3.key --bits=4096
certtool --generate-request --load-privkey $DEST/client3.key --outfile $DEST/client3.csr --template $DEST/template-client.cfg
certtool --generate-certificate --load-request $DEST/client3.csr --load-ca-certificate $DEST/root2.crt --load-ca-privkey $DEST/root2.key --outfile $DEST/client3.crt --template $DEST/template-client.cfg
certtool --certificate-info --infile $DEST/client3.crt --outder |base64 > $DEST/client3.crt.der
