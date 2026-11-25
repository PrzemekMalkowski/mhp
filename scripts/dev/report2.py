import json,sys,urllib.request
port=sys.argv[1] if len(sys.argv)>1 else '8080'
o=urllib.request.build_opener(urllib.request.ProxyHandler({}))
v=json.load(o.open(f'http://127.0.0.1:{port}/history'))[-1]
M=lambda x:round((x or 0)/1048576,1)
p=v['proc']; pf=v.get('pfs') or {}
print('RSS',M(p['rss']),'anon',M(p['anon']),'| traced',M(v['traced']),'| PFS total',M(pf.get('total')),'| fault MiB/s',M(v['fault_rate']))
print('PFS by area',{k:M(x) for k,x in sorted((pf.get('by_area') or {}).items(),key=lambda x:-x[1])[:6]})
print('mhp by subsys',{k:M(x) for k,x in sorted(v['by_subsys'].items(),key=lambda x:-x[1])})
for t in v['tracers']: print('tracer',t)
th=[t for t in v['threads'] if t.get('pfs')]
print('threads with PFS join:',len(th),'of',len(v['threads']))
for t in sorted(th,key=lambda t:-t['live'])[:6]: print('  %6d %-16s live %7s MiB  PFS %7s MiB  %s #%s %s'%(t['tid'],t['comm'],M(t['live']),M(t['pfs']['bytes']),t['pfs']['name'],t['pfs']['conn_id'],t['pfs']['user']))
