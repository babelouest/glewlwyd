#!/bin/sh

#
# Glewlwyd SSO
#
# Create certificates
#
# Public domain, no copyright. Use at your own risk.
#

DEST=../test/cert
RET=0

case "$OSTYPE" in
*"darwin"*)
  # Apple has its own certtool which is incompatible. GnuTLS' certtool is renamed as
  # gnutls-certtool in MacPorts/homebrew.
  CERTTOOL=gnutls-certtool;;
         *)
  CERTTOOL=certtool;;
esac

$CERTTOOL --generate-privkey --key-type=ecdsa >/dev/null 2>&1

if [ $? -eq 0 ]; then
  ECDSA="--key-type=ecdsa"
else
  ECDSA="--ecdsa"
fi

# clean old certs
rm -f $DEST/server.* $DEST/root* $DEST/client* $DEST/user* $DEST/packed*

echo >> $DEST/certtool.log
echo Generate Glewlwyd test certificates >> $DEST/certtool.log
echo >> $DEST/certtool.log

# www cert
$CERTTOOL --generate-privkey --outfile $DEST/server.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "server.key         \033[0;32mOK\033[0m\n"
else
  printf "server.key         \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-self-signed --load-privkey $DEST/server.key --outfile $DEST/server.crt --template $DEST/template-server.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "server.crt         \033[0;32mOK\033[0m\n"
else
  printf "server.crt         \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# CA root
$CERTTOOL --generate-privkey --outfile $DEST/root1.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root1.key          \033[0;32mOK\033[0m\n"
else
  printf "root1.key          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-self-signed --load-privkey $DEST/root1.key --outfile $DEST/root1.crt --template $DEST/template-ca.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root1.crt          \033[0;32mOK\033[0m\n"
else
  printf "root1.crt          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# user 1
$CERTTOOL --generate-privkey --outfile $DEST/user1.key $ECDSA --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "user1.key          \033[0;32mOK\033[0m\n"
else
  printf "user1.key          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/user1.key --load-ca-certificate $DEST/root1.crt --load-ca-privkey $DEST/root1.key --outfile $DEST/user1.crt --template $DEST/template-user.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "user1.crt          \033[0;32mOK\033[0m\n"
else
  printf "user1.crt          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --certificate-info --infile $DEST/user1.crt --outder | base64 > $DEST/user1.crt.der 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "user1.crt.der      \033[0;32mOK\033[0m\n"
else
  printf "user1.crt.der      \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# user 2
$CERTTOOL --generate-privkey --outfile $DEST/user2.key $ECDSA --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "user2.key          \033[0;32mOK\033[0m\n"
else
  printf "user2.key          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/user2.key --load-ca-certificate $DEST/root1.crt --load-ca-privkey $DEST/root1.key --outfile $DEST/user2.crt --template $DEST/template-user.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "user2.crt          \033[0;32mOK\033[0m\n"
else
  printf "user2.crt          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --certificate-info --infile $DEST/user2.crt --outder | base64 > $DEST/user2.crt.der 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "user2.crt.der      \033[0;32mOK\033[0m\n"
else
  printf "user2.crt.der      \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# CA root 2
$CERTTOOL --generate-privkey --outfile $DEST/root2.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root2.key          \033[0;32mOK\033[0m\n"
else
  printf "root2.key          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-self-signed --load-privkey $DEST/root2.key --outfile $DEST/root2.crt --template $DEST/template-ca2.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root2.crt          \033[0;32mOK\033[0m\n"
else
  printf "root2.crt          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# user 3
$CERTTOOL --generate-privkey --outfile $DEST/user3.key $ECDSA --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "user3.key          \033[0;32mOK\033[0m\n"
else
  printf "user3.key          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/user3.key --load-ca-certificate $DEST/root2.crt --load-ca-privkey $DEST/root2.key --outfile $DEST/user3.crt --template $DEST/template-user.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "user3.crt          \033[0;32mOK\033[0m\n"
else
  printf "user3.crt          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --certificate-info --infile $DEST/user3.crt --outder | base64 > $DEST/user3.crt.der 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "user3.crt.der      \033[0;32mOK\033[0m\n"
else
  printf "user3.crt.der      \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# CA packed
$CERTTOOL --generate-privkey --outfile $DEST/packed.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "packed.key         \033[0;32mOK\033[0m\n"
else
  printf "packed.key         \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-self-signed --load-privkey $DEST/packed.key --outfile $DEST/packed.crt --template $DEST/template-ca-packed.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "packed.crt         \033[0;32mOK\033[0m\n"
else
  printf "packed.crt         \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# CA packed 2
$CERTTOOL --generate-privkey --outfile $DEST/packed-2.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "packed-2.key       \033[0;32mOK\033[0m\n"
else
  printf "packed-2.key       \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-self-signed --load-privkey $DEST/packed-2.key --outfile $DEST/packed-2.crt --template $DEST/template-ca-packed.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "packed-2.crt       \033[0;32mOK\033[0m\n"
else
  printf "packed-2.crt       \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# client packed valid
$CERTTOOL --generate-privkey --outfile $DEST/client-p-v.key $ECDSA --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-v.key     \033[0;32mOK\033[0m\n"
else
  printf "client-p-v.key     \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/client-p-v.key --load-ca-certificate $DEST/packed.crt --load-ca-privkey $DEST/packed.key --outfile $DEST/client-p-v.crt --template $DEST/template-client-packed.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-v.crt     \033[0;32mOK\033[0m\n"
else
  printf "client-p-v.crt     \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# client packed invalid ou
$CERTTOOL --generate-privkey --outfile $DEST/client-p-iu.key $ECDSA --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-iu.key    \033[0;32mOK\033[0m\n"
else
  printf "client-p-iu.key    \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/client-p-iu.key --load-ca-certificate $DEST/packed.crt --load-ca-privkey $DEST/packed.key --outfile $DEST/client-p-iu.crt --template $DEST/template-client-packed-invalid-ou.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-iu.crt    \033[0;32mOK\033[0m\n"
else
  printf "client-p-iu.crt    \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# client packed invalid c
$CERTTOOL --generate-privkey --outfile $DEST/client-p-ic.key $ECDSA --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-ic.key    \033[0;32mOK\033[0m\n"
else
  printf "client-p-ic.key    \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/client-p-ic.key --load-ca-certificate $DEST/packed.crt --load-ca-privkey $DEST/packed.key --outfile $DEST/client-p-ic.crt --template $DEST/template-client-packed-invalid-c.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-ic.crt    \033[0;32mOK\033[0m\n"
else
  printf "client-p-ic.crt    \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# client packed c not present
$CERTTOOL --generate-privkey --outfile $DEST/client-p-mc.key $ECDSA --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-mc.key    \033[0;32mOK\033[0m\n"
else
  printf "client-p-mc.key    \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/client-p-mc.key --load-ca-certificate $DEST/packed.crt --load-ca-privkey $DEST/packed.key --outfile $DEST/client-p-mc.crt --template $DEST/template-client-packed-missing-c.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-mc.crt    \033[0;32mOK\033[0m\n"
else
  printf "client-p-mc.crt    \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# client packed o not present
$CERTTOOL --generate-privkey --outfile $DEST/client-p-mo.key $ECDSA --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-mo.key    \033[0;32mOK\033[0m\n"
else
  printf "client-p-mo.key    \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/client-p-mo.key --load-ca-certificate $DEST/packed.crt --load-ca-privkey $DEST/packed.key --outfile $DEST/client-p-mo.crt --template $DEST/template-client-packed-missing-o.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-mo.crt    \033[0;32mOK\033[0m\n"
else
  printf "client-p-mo.crt    \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# client packed cn not present
$CERTTOOL --generate-privkey --outfile $DEST/client-p-mcn.key $ECDSA --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-mcn.key   \033[0;32mOK\033[0m\n"
else
  printf "client-p-mcn.key   \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/client-p-mcn.key --load-ca-certificate $DEST/packed.crt --load-ca-privkey $DEST/packed.key --outfile $DEST/client-p-mcn.crt --template $DEST/template-client-packed-missing-cn.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-mcn.crt   \033[0;32mOK\033[0m\n"
else
  printf "client-p-mcn.crt   \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# client packed invalid extension aaguid
$CERTTOOL --generate-privkey --outfile $DEST/client-p-ia.key $ECDSA --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-ia.key    \033[0;32mOK\033[0m\n"
else
  printf "client-p-ia.key    \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/client-p-ia.key --load-ca-certificate $DEST/packed.crt --load-ca-privkey $DEST/packed.key --outfile $DEST/client-p-ia.crt --template $DEST/template-client-packed-invalid-aaguid.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client-p-ia.crt    \033[0;32mOK\033[0m\n"
else
  printf "client-p-ia.crt    \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# client 1
$CERTTOOL --generate-privkey --outfile $DEST/client1.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client1.key        \033[0;32mOK\033[0m\n"
else
  printf "client1.key        \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/client1.key --load-ca-certificate $DEST/root1.crt --load-ca-privkey $DEST/root1.key --outfile $DEST/client1.crt --template $DEST/template-client.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client1.crt        \033[0;32mOK\033[0m\n"
else
  printf "client1.crt        \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --certificate-info --infile $DEST/client1.crt --outder | base64 > $DEST/client1.crt.der 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client1.crt.der    \033[0;32mOK\033[0m\n"
else
  printf "client1.crt.der    \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# client 2
$CERTTOOL --generate-privkey --outfile $DEST/client2.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client2.key        \033[0;32mOK\033[0m\n"
else
  printf "client2.key        \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/client2.key --load-ca-certificate $DEST/root2.crt --load-ca-privkey $DEST/root2.key --outfile $DEST/client2.crt --template $DEST/template-client.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client2.crt        \033[0;32mOK\033[0m\n"
else
  printf "client2.crt        \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --certificate-info --infile $DEST/client2.crt --outder | base64 > $DEST/client2.crt.der 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client2.crt.der    \033[0;32mOK\033[0m\n"
else
  printf "client2.crt.der    \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# client self-signed
$CERTTOOL --generate-privkey --outfile $DEST/client3.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client3.key        \033[0;32mOK\033[0m\n"
else
  printf "client3.key        \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/client3.key --generate-self-signed --outfile $DEST/client3.crt --template $DEST/template-client.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client3.crt        \033[0;32mOK\033[0m\n"
else
  printf "client3.crt        \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --certificate-info --infile $DEST/client3.crt --outder | base64 > $DEST/client3.crt.der 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "client3.crt.der    \033[0;32mOK\033[0m\n"
else
  printf "client3.crt.der    \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# CA apple
$CERTTOOL --generate-privkey --outfile $DEST/apple.key $ECDSA --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "apple.key          \033[0;32mOK\033[0m\n"
else
  printf "apple.key          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-self-signed --load-privkey $DEST/apple.key --outfile $DEST/apple.crt --template $DEST/template-ca-apple.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "apple.crt          \033[0;32mOK\033[0m\n"
else
  printf "apple.crt          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# CA intermediate apple
$CERTTOOL --generate-privkey --outfile $DEST/apple-int.key $ECDSA --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "apple-int.key      \033[0;32mOK\033[0m\n"
else
  printf "apple-int.key      \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/apple-int.key --load-ca-certificate $DEST/apple.crt --load-ca-privkey $DEST/apple.key --outfile $DEST/apple-int.crt --template $DEST/template-int-apple.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "apple-int.crt      \033[0;32mOK\033[0m\n"
else
  printf "apple-int.crt      \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --certificate-info --infile $DEST/apple-int.crt --outder | base64 > $DEST/apple-int.crt.der 2>>$DEST/certtool.log

# CA intermediate 2 apple
$CERTTOOL --generate-privkey --outfile $DEST/apple-int2.key $ECDSA --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "apple-int2.key     \033[0;32mOK\033[0m\n"
else
  printf "apple-int2.key     \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/apple-int2.key --load-ca-certificate $DEST/apple-int.crt --load-ca-privkey $DEST/apple-int.key --outfile $DEST/apple-int2.crt --template $DEST/template-int-apple.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "apple-int2.crt     \033[0;32mOK\033[0m\n"
else
  printf "apple-int2.crt     \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --certificate-info --infile $DEST/apple-int.crt --outder | base64 > $DEST/apple-int.crt.der 2>>$DEST/certtool.log

# CA apple 2
$CERTTOOL --generate-privkey --outfile $DEST/apple2.key $ECDSA --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "apple2.key         \033[0;32mOK\033[0m\n"
else
  printf "apple2.key         \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-self-signed --load-privkey $DEST/apple2.key --outfile $DEST/apple2.crt --template $DEST/template-ca-apple.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "apple2.crt         \033[0;32mOK\033[0m\n"
else
  printf "apple2.crt         \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# CA intermediate apple 2
$CERTTOOL --generate-privkey --outfile $DEST/apple2-int.key $ECDSA --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "apple2-int.key     \033[0;32mOK\033[0m\n"
else
  printf "apple2-int.key     \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/apple2-int.key --load-ca-certificate $DEST/apple2.crt --load-ca-privkey $DEST/apple2.key --outfile $DEST/apple2-int.crt --template $DEST/template-int-apple.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "apple2-int.crt     \033[0;32mOK\033[0m\n"
else
  printf "apple2-int.crt     \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --certificate-info --infile $DEST/apple-int.crt --outder | base64 > $DEST/apple-int.crt.der 2>>$DEST/certtool.log

exit $RET
