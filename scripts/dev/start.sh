#!/bin/bash
# start mysqld under mhp, wait for it, run mysqlslap in background
S=$(dirname "$0"); cd /data/ai/memprofiler
rm -f /dev/shm/mhp.*
nohup ./bin/mhp run -addr 0.0.0.0:8080 -- /usr/sbin/mysqld --user=mysql > $S/mysqld-run.log 2>&1 &
for i in $(seq 40); do mysql -e "select 1" >/dev/null 2>&1 && break; sleep 1; done
echo "mysqld up"
nohup mysqlslap --concurrency=16 --iterations=100 --number-of-queries=20000 --auto-generate-sql \
  --auto-generate-sql-load-type=mixed --auto-generate-sql-add-autoincrement --number-char-cols=8 --number-int-cols=4 > $S/slap.log 2>&1 &
