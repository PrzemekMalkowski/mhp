# tcache.py before|after: sum live bytes under table-cache parents (TABLE objects vs TABLE_SHARE) from mhp's /stacks
import json, sys, urllib.request
d = json.load(urllib.request.urlopen("http://localhost:8080/stacks?metric=live"))
tot = {"open_table_from_share (TABLE, table_open_cache)": 0, "get_table_share (TABLE_SHARE, table_definition_cache)": 0}
for r in d:
    f = r["f"]
    if "open_table_from_share" in f:
        tot["open_table_from_share (TABLE, table_open_cache)"] += r["v"]
    elif "get_table_share" in f:
        tot["get_table_share (TABLE_SHARE, table_definition_cache)"] += r["v"]
json.dump(tot, open(f"/tmp/claude-1000/tcache-{sys.argv[1]}.json", "w"))
print(sys.argv[1], {k: "%.1f MiB" % (v / 2**20) for k, v in tot.items()})
