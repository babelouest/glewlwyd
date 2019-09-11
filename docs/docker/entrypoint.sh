#!/bin/bash

if [ ! -f "/var/cache/glewlwyd/glewlwyd.db" ]; then
  mkdir /var/cache/glewlwyd/
  sqlite3 /var/cache/glewlwyd/glewlwyd.db < /usr/share/glewlwyd/docs/database/init.sqlite3.sql
fi

glewlwyd --config-file=/etc/glewlwyd/glewlwyd.conf -mconsole
