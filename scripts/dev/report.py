import json,sys,urllib.request
o=urllib.request.build_opener(urllib.request.ProxyHandler({}))
h=json.load(o.open('http://127.0.0.1:8080/history')); v=h[-1]
M=lambda x:round(x/1048576,1)
print('rss',M(v['proc']['rss']),'anon',M(v['proc']['anon']),'traced',M(v['traced']),'alloc/s',M(v['alloc_rate']),'tracer',v.get('tracer'))
print('by_subsys',{k:M(x) for k,x in v['by_subsys'].items()})
alive=[t for t in v['threads'] if t['alive']]
print('threads alive',len(alive),'total rows',len(v['threads']))
for t in sorted(alive,key=lambda t:-t['alloc_rate'])[:8]: print(' ',t['tid'],t['comm'],'live',M(t['live']),'alloc/s',M(t['alloc_rate']),'flt/s',round(t['minflt_s']),'cpu',round(t['cpu']))
print('growers'); [print(' ',M(r['growth']),' <- '.join(r['stack'][::-1][:6])) for r in v['growers'][:5]]
