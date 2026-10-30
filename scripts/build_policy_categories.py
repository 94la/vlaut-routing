"""Compile policy inputs into GeoSite/GeoIP categories, preserving semantics."""
import argparse,hashlib,ipaddress,json
from pathlib import Path
from extend_blocklists import fields,pack,enc

def categories(blob):
 result={}
 for f,w,v,raw in fields(blob):
  if f==1:result[next(x.decode().lower() for ff,ww,x,rr in fields(v) if ff==1)]=v
 return result

def replace(blob,entries):
 names=set(entries)
 kept=[]
 for f,w,v,raw in fields(blob):
  if f==1 and next(x.decode().lower() for ff,ww,x,rr in fields(v) if ff==1) in names:continue
  kept.append(raw)
 return b''.join(kept)+b''.join(pack(1,v) for v in entries.values())

def compile_site(rules,cats,name):
 entries=[]
 for rule in rules:
  kind,value=rule.split(':',1)
  if kind=='geosite':
   assert '@' not in value
   entries.extend(raw for f,w,v,raw in fields(cats[value.lower()]) if f==2)
  else:
   typ={'regexp':1,'domain':2,'full':3}[kind]
   entries.append(pack(2,b'\x08'+enc(typ)+pack(2,value.encode())))
 return pack(1,name.upper().encode())+b''.join(dict.fromkeys(entries))

def compile_ip(rules,cats,name):
 entries=[]
 for rule in rules:
  if rule.startswith('geoip:'):
   cat=cats[rule[6:].lower()]
   assert not any(f==3 and v for f,w,v,raw in fields(cat))
   entries.extend(raw for f,w,v,raw in fields(cat) if f==2)
  else:
   net=ipaddress.ip_network(rule,strict=True)
   entries.append(pack(2,pack(1,net.network_address.packed)+b'\x10'+enc(net.prefixlen)))
 return pack(1,name.upper().encode())+b''.join(dict.fromkeys(entries))

def build(root):
 policy=json.loads((Path(__file__).resolve().parents[1]/'policy-inputs.json').read_text())
 site=(root/'geosite.dat').read_bytes();ip=(root/'geoip.dat').read_bytes();sc=categories(site);ic=categories(ip)
 site=replace(site,{'wlout-direct':compile_site(policy['DirectSites'],sc,'wlout-direct'),'wlout-proxy':compile_site(policy['ProxySites'],sc,'wlout-proxy')})
 ip=replace(ip,{'wlout-direct':compile_ip(policy['DirectIp'],ic,'wlout-direct')})
 (root/'geosite.dat').write_bytes(site);(root/'geoip.dat').write_bytes(ip)
 m=json.loads((root/'manifest.json').read_text());m.update(geosite_sha256=hashlib.sha256(site).hexdigest(),geoip_sha256=hashlib.sha256(ip).hexdigest(),policy_categories={'geosite':['WLOUT-DIRECT','WLOUT-PROXY'],'geoip':['WLOUT-DIRECT'],'source':'policy-inputs.json'})
 (root/'manifest.json').write_text(json.dumps(m,indent=2)+'\n')
 print('POLICY_CATEGORIES_BUILT',len(site),len(ip))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=Path(__file__).resolve().parents[1]);build(p.parse_args().output)
