#!/bin/sh

DEST=../test/cert

# clean old certs
rm -f $DEST/server.* $DEST/root* $DEST/client*

echo >> $DEST/certtool.log
echo Generate Glewlwyd test certificates >> $DEST/certtool.log
echo >> $DEST/certtool.log

# www cert
certtool --generate-privkey --outfile $DEST/server.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "server.key      \033[0;32mOK\033[0m\n"
else
  printf "server.key      \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/server.key --outfile $DEST/server.csr --template $DEST/template-server.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "server.csr      \033[0;32mOK\033[0m\n"
else
  printf "server.csr      \033[0;31mError\033[0m\n"
fi
certtool --generate-self-signed --load-privkey $DEST/server.key --outfile $DEST/server.crt --template $DEST/template-server.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "server.crt      \033[0;32mOK\033[0m\n"
else
  printf "server.crt      \033[0;31mError\033[0m\n"
fi

# CA root
certtool --generate-privkey --outfile $DEST/root1.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root1.key       \033[0;32mOK\033[0m\n"
else
  printf "root1.key       \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/root1.key --outfile $DEST/root1.csr --template $DEST/template-ca.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root1.csr       \033[0;32mOK\033[0m\n"
else
  printf "root1.csr       \033[0;31mError\033[0m\n"
fi
certtool --generate-self-signed --load-privkey $DEST/root1.key --outfile $DEST/root1.crt --template $DEST/template-ca.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root1.crt       \033[0;32mOK\033[0m\n"
else
  printf "root1.crt       \033[0;31mError\033[0m\n"
fi

# client 1
certtool --generate-privkey --outfile $DEST/client1.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client1.key     \033[0;32mOK\033[0m\n"
else
  printf "client1.key     \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/client1.key --outfile $DEST/client1.csr --template $DEST/template-client.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client1.key     \033[0;32mOK\033[0m\n"
else
  printf "client1.key     \033[0;31mError\033[0m\n"
fi
certtool --generate-certificate --load-request $DEST/client1.csr --load-ca-certificate $DEST/root1.crt --load-ca-privkey $DEST/root1.key --outfile $DEST/client1.crt --template $DEST/template-client.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client1.crt     \033[0;32mOK\033[0m\n"
else
  printf "client1.crt     \033[0;31mError\033[0m\n"
fi
certtool --certificate-info --infile $DEST/client1.crt --outder |base64 > $DEST/client1.crt.der 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client1.crt.der \033[0;32mOK\033[0m\n"
else
  printf "client1.crt.der \033[0;31mError\033[0m\n"
fi

# client 2
certtool --generate-privkey --outfile $DEST/client2.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client2.key     \033[0;32mOK\033[0m\n"
else
  printf "client2.key     \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/client2.key --outfile $DEST/client2.csr --template $DEST/template-client.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client2.csr     \033[0;32mOK\033[0m\n"
else
  printf "client2.csr     \033[0;31mError\033[0m\n"
fi
certtool --generate-certificate --load-request $DEST/client2.csr --load-ca-certificate $DEST/root1.crt --load-ca-privkey $DEST/root1.key --outfile $DEST/client2.crt --template $DEST/template-client.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client2.crt     \033[0;32mOK\033[0m\n"
else
  printf "client2.crt     \033[0;31mError\033[0m\n"
fi
certtool --certificate-info --infile $DEST/client2.crt --outder |base64 > $DEST/client2.crt.der 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client2.crt.der \033[0;32mOK\033[0m\n"
else
  printf "client2.crt.der \033[0;31mError\033[0m\n"
fi

# CA root 2
certtool --generate-privkey --outfile $DEST/root2.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root2.key       \033[0;32mOK\033[0m\n"
else
  printf "root2.key       \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/root2.key --outfile $DEST/root2.csr --template $DEST/template-ca2.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root2.csr       \033[0;32mOK\033[0m\n"
else
  printf "root2.csr       \033[0;31mError\033[0m\n"
fi
certtool --generate-self-signed --load-privkey $DEST/root2.key --outfile $DEST/root2.crt --template $DEST/template-ca2.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root2.crt       \033[0;32mOK\033[0m\n"
else
  printf "root2.crt       \033[0;31mError\033[0m\n"
fi

# client 3
certtool --generate-privkey --outfile $DEST/client3.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client3.key     \033[0;32mOK\033[0m\n"
else
  printf "client3.key     \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/client3.key --outfile $DEST/client3.csr --template $DEST/template-client.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client3.csr     \033[0;32mOK\033[0m\n"
else
  printf "client3.csr     \033[0;31mError\033[0m\n"
fi
certtool --generate-certificate --load-request $DEST/client3.csr --load-ca-certificate $DEST/root2.crt --load-ca-privkey $DEST/root2.key --outfile $DEST/client3.crt --template $DEST/template-client.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client3.crt     \033[0;32mOK\033[0m\n"
else
  printf "client3.crt     \033[0;31mError\033[0m\n"
fi
certtool --certificate-info --infile $DEST/client3.crt --outder |base64 > $DEST/client3.crt.der 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client3.crt.der \033[0;32mOK\033[0m\n"
else
  printf "client3.crt.der \033[0;31mError\033[0m\n"
fi
