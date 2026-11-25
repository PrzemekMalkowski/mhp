#!/bin/bash
# watch.sh start|stop [extra mhp args]: run "mhp watch" on mysqld in background (pidfile), port 8081
S=$(dirname "$0"); cd /data/ai/memprofiler
case "$1" in
start) shift; nohup ./bin/mhp watch -pid $(pgrep -x mysqld) -addr 127.0.0.1:8081 "$@" > $S/watch.log 2>&1 & echo $! > $S/watch.pid ;;
stop)  [ -f $S/watch.pid ] && kill -INT $(cat $S/watch.pid) 2>/dev/null; rm -f $S/watch.pid ;;
esac
