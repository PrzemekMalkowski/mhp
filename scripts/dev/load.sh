#!/bin/bash
# load.sh [concurrency] [iterations]: background mysqlslap mixed load
S=$(dirname "$0")
nohup mysqlslap --concurrency=${1:-32} --iterations=${2:-20} --number-of-queries=40000 --auto-generate-sql \
  --auto-generate-sql-load-type=mixed --auto-generate-sql-add-autoincrement --number-char-cols=8 --number-int-cols=4 > $S/slap.log 2>&1 &
