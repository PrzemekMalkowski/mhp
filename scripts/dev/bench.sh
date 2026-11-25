#!/bin/bash
# usage: bench.sh plain|shim  — start mysqld (optionally under mhp), run a fixed mysqlslap, print timing, stop
S=$(dirname "$0"); cd /data/ai/memprofiler; rm -f /dev/shm/mhp.*
if [ "$1" = shim ]; then
  nohup ./bin/mhp run -addr 0.0.0.0:8080 -- /usr/sbin/mysqld --user=mysql > $S/bench-mhp.log 2>&1 &
else
  nohup /usr/sbin/mysqld --user=mysql > $S/bench-plain.log 2>&1 &
fi
for i in $(seq 40); do mysql -e "select 1" >/dev/null 2>&1 && break; sleep 1; done
mysqlslap --concurrency=16 --iterations=3 --number-of-queries=40000 --auto-generate-sql \
  --auto-generate-sql-load-type=mixed --auto-generate-sql-add-autoincrement --number-char-cols=8 --number-int-cols=4 2>&1 | grep -E "Average|Minimum"
ps -o rss=,pcpu= -C mysqld
if [ "$1" = shim ]; then pkill -INT -x mhp; else pkill -TERM -x mysqld; fi
for i in $(seq 60); do pgrep -x mysqld >/dev/null || break; sleep 1; done
