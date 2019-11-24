#!/bin/sh

DEST=../test/cert

# clean old certs
rm -f $DEST/server.* $DEST/root* $DEST/client* $DEST/packed*

echo >> $DEST/certtool.log
echo Generate Glewlwyd test certificates >> $DEST/certtool.log
echo >> $DEST/certtool.log

# www cert
certtool --generate-privkey --outfile $DEST/server.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "server.key         \033[0;32mOK\033[0m\n"
else
  printf "server.key         \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/server.key --outfile $DEST/server.csr --template $DEST/template-server.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "server.csr         \033[0;32mOK\033[0m\n"
else
  printf "server.csr         \033[0;31mError\033[0m\n"
fi
certtool --generate-self-signed --load-privkey $DEST/server.key --outfile $DEST/server.crt --template $DEST/template-server.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "server.crt         \033[0;32mOK\033[0m\n"
else
  printf "server.crt         \033[0;31mError\033[0m\n"
fi

# CA root
certtool --generate-privkey --outfile $DEST/root1.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root1.key          \033[0;32mOK\033[0m\n"
else
  printf "root1.key          \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/root1.key --outfile $DEST/root1.csr --template $DEST/template-ca.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root1.csr          \033[0;32mOK\033[0m\n"
else
  printf "root1.csr          \033[0;31mError\033[0m\n"
fi
certtool --generate-self-signed --load-privkey $DEST/root1.key --outfile $DEST/root1.crt --template $DEST/template-ca.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root1.crt          \033[0;32mOK\033[0m\n"
else
  printf "root1.crt          \033[0;31mError\033[0m\n"
fi

# client 1
certtool --generate-privkey --outfile $DEST/client1.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client1.key        \033[0;32mOK\033[0m\n"
else
  printf "client1.key        \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/client1.key --outfile $DEST/client1.csr --template $DEST/template-client.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client1.key        \033[0;32mOK\033[0m\n"
else
  printf "client1.key        \033[0;31mError\033[0m\n"
fi
certtool --generate-certificate --load-request $DEST/client1.csr --load-ca-certificate $DEST/root1.crt --load-ca-privkey $DEST/root1.key --outfile $DEST/client1.crt --template $DEST/template-client.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client1.crt        \033[0;32mOK\033[0m\n"
else
  printf "client1.crt        \033[0;31mError\033[0m\n"
fi
certtool --certificate-info --infile $DEST/client1.crt --outder | base64 > $DEST/client1.crt.der 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client1.crt.der    \033[0;32mOK\033[0m\n"
else
  printf "client1.crt.der    \033[0;31mError\033[0m\n"
fi

# client 2
certtool --generate-privkey --outfile $DEST/client2.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client2.key        \033[0;32mOK\033[0m\n"
else
  printf "client2.key        \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/client2.key --outfile $DEST/client2.csr --template $DEST/template-client.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client2.csr        \033[0;32mOK\033[0m\n"
else
  printf "client2.csr        \033[0;31mError\033[0m\n"
fi
certtool --generate-certificate --load-request $DEST/client2.csr --load-ca-certificate $DEST/root1.crt --load-ca-privkey $DEST/root1.key --outfile $DEST/client2.crt --template $DEST/template-client.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client2.crt        \033[0;32mOK\033[0m\n"
else
  printf "client2.crt        \033[0;31mError\033[0m\n"
fi
certtool --certificate-info --infile $DEST/client2.crt --outder | base64 > $DEST/client2.crt.der 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client2.crt.der    \033[0;32mOK\033[0m\n"
else
  printf "client2.crt.der    \033[0;31mError\033[0m\n"
fi

# CA root 2
certtool --generate-privkey --outfile $DEST/root2.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root2.key          \033[0;32mOK\033[0m\n"
else
  printf "root2.key          \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/root2.key --outfile $DEST/root2.csr --template $DEST/template-ca2.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root2.csr          \033[0;32mOK\033[0m\n"
else
  printf "root2.csr          \033[0;31mError\033[0m\n"
fi
certtool --generate-self-signed --load-privkey $DEST/root2.key --outfile $DEST/root2.crt --template $DEST/template-ca2.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root2.crt          \033[0;32mOK\033[0m\n"
else
  printf "root2.crt          \033[0;31mError\033[0m\n"
fi

# client 3
certtool --generate-privkey --outfile $DEST/client3.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client3.key        \033[0;32mOK\033[0m\n"
else
  printf "client3.key        \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/client3.key --outfile $DEST/client3.csr --template $DEST/template-client.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client3.csr        \033[0;32mOK\033[0m\n"
else
  printf "client3.csr        \033[0;31mError\033[0m\n"
fi
certtool --generate-certificate --load-request $DEST/client3.csr --load-ca-certificate $DEST/root2.crt --load-ca-privkey $DEST/root2.key --outfile $DEST/client3.crt --template $DEST/template-client.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client3.crt        \033[0;32mOK\033[0m\n"
else
  printf "client3.crt        \033[0;31mError\033[0m\n"
fi
certtool --certificate-info --infile $DEST/client3.crt --outder | base64 > $DEST/client3.crt.der 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client3.crt.der    \033[0;32mOK\033[0m\n"
else
  printf "client3.crt.der    \033[0;31mError\033[0m\n"
fi

# CA packed
certtool --generate-privkey --outfile $DEST/packed.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "packed.key         \033[0;32mOK\033[0m\n"
else
  printf "packed.key         \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/packed.key --outfile $DEST/packed.csr --template $DEST/template-ca-packed.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "packed.csr         \033[0;32mOK\033[0m\n"
else
  printf "packed.csr         \033[0;31mError\033[0m\n"
fi
certtool --generate-self-signed --load-privkey $DEST/packed.key --outfile $DEST/packed.crt --template $DEST/template-ca-packed.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "packed.crt         \033[0;32mOK\033[0m\n"
else
  printf "packed.crt         \033[0;31mError\033[0m\n"
fi

# CA packed 2
certtool --generate-privkey --outfile $DEST/packed-2.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "packed-2.key       \033[0;32mOK\033[0m\n"
else
  printf "packed-2.key       \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/packed-2.key --outfile $DEST/packed-2.csr --template $DEST/template-ca-packed.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "packed-2.csr       \033[0;32mOK\033[0m\n"
else
  printf "packed-2.csr       \033[0;31mError\033[0m\n"
fi
certtool --generate-self-signed --load-privkey $DEST/packed-2.key --outfile $DEST/packed-2.crt --template $DEST/template-ca-packed.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "packed-2.crt       \033[0;32mOK\033[0m\n"
else
  printf "packed-2.crt       \033[0;31mError\033[0m\n"
fi

# client packed valid
certtool --generate-privkey --outfile $DEST/client-p-v.key --key-type=ecdsa --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-v.key     \033[0;32mOK\033[0m\n"
else
  printf "client-p-v.key     \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/client-p-v.key --outfile $DEST/client-p-v.csr --template $DEST/template-client-packed.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-v.csr     \033[0;32mOK\033[0m\n"
else
  printf "client-p-v.csr     \033[0;31mError\033[0m\n"
fi
certtool --generate-certificate --load-request $DEST/client-p-v.csr --load-ca-certificate $DEST/packed.crt --load-ca-privkey $DEST/packed.key --outfile $DEST/client-p-v.crt --template $DEST/template-client-packed.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-v.crt     \033[0;32mOK\033[0m\n"
else
  printf "client-p-v.crt     \033[0;31mError\033[0m\n"
fi

# client packed invalid ou
certtool --generate-privkey --outfile $DEST/client-p-iu.key --key-type=ecdsa --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-iu.key    \033[0;32mOK\033[0m\n"
else
  printf "client-p-iu.key    \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/client-p-iu.key --outfile $DEST/client-p-iu.csr --template $DEST/template-client-packed-invalid-ou.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-iu.csr    \033[0;32mOK\033[0m\n"
else
  printf "client-p-iu.csr    \033[0;31mError\033[0m\n"
fi
certtool --generate-certificate --load-request $DEST/client-p-iu.csr --load-ca-certificate $DEST/packed.crt --load-ca-privkey $DEST/packed.key --outfile $DEST/client-p-iu.crt --template $DEST/template-client-packed-invalid-ou.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-iu.crt    \033[0;32mOK\033[0m\n"
else
  printf "client-p-iu.crt    \033[0;31mError\033[0m\n"
fi

# client packed invalid c
certtool --generate-privkey --outfile $DEST/client-p-ic.key --key-type=ecdsa --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-ic.key    \033[0;32mOK\033[0m\n"
else
  printf "client-p-ic.key    \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/client-p-ic.key --outfile $DEST/client-p-ic.csr --template $DEST/template-client-packed-invalid-c.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-ic.csr    \033[0;32mOK\033[0m\n"
else
  printf "client-p-ic.csr    \033[0;31mError\033[0m\n"
fi
certtool --generate-certificate --load-request $DEST/client-p-ic.csr --load-ca-certificate $DEST/packed.crt --load-ca-privkey $DEST/packed.key --outfile $DEST/client-p-ic.crt --template $DEST/template-client-packed-invalid-c.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-ic.crt    \033[0;32mOK\033[0m\n"
else
  printf "client-p-ic.crt    \033[0;31mError\033[0m\n"
fi

# client packed c not present
certtool --generate-privkey --outfile $DEST/client-p-mc.key --key-type=ecdsa --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-mc.key    \033[0;32mOK\033[0m\n"
else
  printf "client-p-mc.key    \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/client-p-mc.key --outfile $DEST/client-p-mc.csr --template $DEST/template-client-packed-missing-c.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-mc.csr    \033[0;32mOK\033[0m\n"
else
  printf "client-p-mc.csr    \033[0;31mError\033[0m\n"
fi
certtool --generate-certificate --load-request $DEST/client-p-mc.csr --load-ca-certificate $DEST/packed.crt --load-ca-privkey $DEST/packed.key --outfile $DEST/client-p-mc.crt --template $DEST/template-client-packed-missing-c.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-mc.crt    \033[0;32mOK\033[0m\n"
else
  printf "client-p-mc.crt    \033[0;31mError\033[0m\n"
fi

# client packed o not present
certtool --generate-privkey --outfile $DEST/client-p-mo.key --key-type=ecdsa --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-mo.key    \033[0;32mOK\033[0m\n"
else
  printf "client-p-mo.key    \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/client-p-mo.key --outfile $DEST/client-p-mo.csr --template $DEST/template-client-packed-missing-o.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-mo.csr    \033[0;32mOK\033[0m\n"
else
  printf "client-p-mo.csr    \033[0;31mError\033[0m\n"
fi
certtool --generate-certificate --load-request $DEST/client-p-mo.csr --load-ca-certificate $DEST/packed.crt --load-ca-privkey $DEST/packed.key --outfile $DEST/client-p-mo.crt --template $DEST/template-client-packed-missing-o.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-mo.crt    \033[0;32mOK\033[0m\n"
else
  printf "client-p-mo.crt    \033[0;31mError\033[0m\n"
fi

# client packed cn not present
certtool --generate-privkey --outfile $DEST/client-p-mcn.key --key-type=ecdsa --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-mcn.key   \033[0;32mOK\033[0m\n"
else
  printf "client-p-mcn.key   \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/client-p-mcn.key --outfile $DEST/client-p-mcn.csr --template $DEST/template-client-packed-missing-cn.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-mcn.csr   \033[0;32mOK\033[0m\n"
else
  printf "client-p-mcn.csr   \033[0;31mError\033[0m\n"
fi
certtool --generate-certificate --load-request $DEST/client-p-mcn.csr --load-ca-certificate $DEST/packed.crt --load-ca-privkey $DEST/packed.key --outfile $DEST/client-p-mcn.crt --template $DEST/template-client-packed-missing-cn.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-mcn.crt   \033[0;32mOK\033[0m\n"
else
  printf "client-p-mcn.crt   \033[0;31mError\033[0m\n"
fi

# client packed invalid extension aaguid
certtool --generate-privkey --outfile $DEST/client-p-ia.key --key-type=ecdsa --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-ia.key    \033[0;32mOK\033[0m\n"
else
  printf "client-p-ia.key    \033[0;31mError\033[0m\n"
fi
certtool --generate-request --load-privkey $DEST/client-p-ia.key --outfile $DEST/client-p-ia.csr --template $DEST/template-client-packed-invalid-aaguid.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-ia.csr    \033[0;32mOK\033[0m\n"
else
  printf "client-p-ia.csr    \033[0;31mError\033[0m\n"
fi
certtool --generate-certificate --load-request $DEST/client-p-ia.csr --load-ca-certificate $DEST/packed.crt --load-ca-privkey $DEST/packed.key --outfile $DEST/client-p-ia.crt --template $DEST/template-client-packed-invalid-aaguid.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-ia.crt    \033[0;32mOK\033[0m\n"
else
  printf "client-p-ia.crt    \033[0;31mError\033[0m\n"
fi
