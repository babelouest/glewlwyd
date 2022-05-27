#!/bin/bash

if [ ! -f "/var/cache/glewlwyd/glewlwyd.db" ]; then
  mkdir /var/cache/glewlwyd/
  sqlite3 /var/cache/glewlwyd/glewlwyd.db < /usr/share/glewlwyd/docs/database/init.sqlite3.sql
fi

rm /usr/share/glewlwyd/webapp/config.json
cp /etc/glewlwyd/config.json /usr/share/glewlwyd/webapp/config.json

glewlwyd --config-file=/etc/glewlwyd/glewlwyd.conf -mconsole -e
