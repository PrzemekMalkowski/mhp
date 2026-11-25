#!/bin/bash
# bench-ebpf.sh plain|ebpf|ebpf-all|shim [secs] [test]: sysbench (default oltp_read_only, CPU-bound) (16 threads) against mysqld with no tracer,
# the eBPF heap tracer attached, eBPF + perf faults + PFS (mhp defaults), or libmhp (mhp run). Run as root.
# Needs: sysbench db "sbtest" prepared with 8 tables x 100k rows.
S=$(dirname "$(readlink -f "$0")"); cd "$S/../.."
mode=$1; secs=${2:-30}; test=${3:-oltp_read_only}
sb() { sysbench "$test" --mysql-user=root --mysql-socket=/var/run/mysqld/mysqld.sock --tables=8 \
	--table-size=100000 --threads=16 "$@"; }
up() { for i in $(seq 60); do mysql -e "select 1" >/dev/null 2>&1 && return; sleep 1; done; echo "mysqld not up"; exit 1; }

if [ "$mode" = shim ]; then
	systemctl stop mysql
	install -d -o mysql -g mysql /run/mysqld # systemd removes it on stop
	nohup ./bin/mhp run -addr 127.0.0.1:8090 -faults off -pfs off -- /usr/sbin/mysqld --user=mysql > "$S/bench-shim.log" 2>&1 &
else
	systemctl start mysql
fi
up
case $mode in
ebpf) nohup ./bin/mhp watch -pid "$(pgrep -x mysqld)" -addr 127.0.0.1:8090 -faults off -pfs off > "$S/bench-ebpf.log" 2>&1 & ;;
ebpf-all) nohup ./bin/mhp watch -pid "$(pgrep -x mysqld)" -addr 127.0.0.1:8090 > "$S/bench-ebpf.log" 2>&1 & ;;
esac
sleep 2
sb --time=10 run >/dev/null # warm-up
sb --time="$secs" --report-interval=0 run | awk -v m="$mode" '/transactions:/ {tps=$3} /95th percentile/ {p95=$3}
	END {gsub(/\(/, "", tps); printf "%-9s tps %8.1f  p95 %6.2f ms\n", m, tps, p95}'
ps -o rss=,pcpu= -C mhp | awk '{printf "          mhp rss %d MiB, cpu %s%%\n", $1/1024, $2}'
pkill -INT -x mhp; sleep 1
if [ "$mode" = shim ]; then
	for i in $(seq 60); do pgrep -x mysqld >/dev/null || break; sleep 1; done
	systemctl start mysql
fi
