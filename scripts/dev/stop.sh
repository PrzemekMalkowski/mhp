#!/bin/bash
pkill -INT -f '^./bin/mhp run' ; pkill -x mysqlslap
for i in $(seq 60); do pgrep -x mysqld >/dev/null || exit 0; sleep 1; done; echo "mysqld still running"
