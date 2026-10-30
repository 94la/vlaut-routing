"""Conservative domain-only conversion; never widen scoped/path filters.
Snapshots are retained with licenses for reproducibility. No live malware requests.
"""
import gzip, hashlib, ipaddress, json, re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def varint(b,p):
 n=s=0
 while True:
  v=b[p];p+=1;n|=(v&127)<<s
  if v<128:return n,p
  s+=7

def fields(b):
 p=0
 while p<len(b):
  start=p;k,p=varint(b,p);w=k&7
  if w==2:n,p=varint(b,p);v=b[p:p+n];p+=n
  elif w==0:v,p=varint(b,p)
  elif w in (1,5):n=8 if w==1 else 4;v=b[p:p+n];p+=n
  else:raise ValueError('wire')
  yield k>>3,w,v,b[start:p]
def enc(n):
 r=bytearray()
 while n>127:r.append((n&127)|128);n>>=7
 r.append(n);return bytes(r)
def pack(f,b):return enc(f*8+2)+enc(len(b))+b

def domain(s):
 s=s.lower().rstrip('.')
 try:ipaddress.ip_address(s);return None
 except ValueError:pass
 if len(s)>253 or '.' not in s:return None
 if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in s.split('.')):return None
 return s

def parse(text,kind):
 candidates=set();exceptions=set();depth=0
 for line in text.splitlines():
  line=line.strip()
  # Ignore ALL conditional branches; their applicability cannot be preserved.
  if line.startswith('!#if'):depth+=1;continue
  if line.startswith('!#endif'):depth-=1;assert depth>=0;continue
  if depth or not line or line.startswith(('!','#','[')):continue
  # Any host-anchored exception conservatively excludes related candidates,
  # even if its path/type/site conditions cannot be represented.
  if line.startswith('@@||'):
   m=re.match(r'@@\|\|([a-zA-Z0-9.-]+)(?:[\^/$]|$)',line)
   if m and domain(m[1]):exceptions.add(domain(m[1]))
   continue
  host=None
  if kind=='hosts':
   m=re.fullmatch(r'(?:127\.0\.0\.1|0\.0\.0\.0)\s+([^\s]+)',line)
   if m:host=m[1]
  elif kind=='malware' and domain(line):host=line
  else:
   m=re.fullmatch(r'\|\|([a-zA-Z0-9.-]+)\^(?:\$(?:all|important))?',line)
   if m:host=m[1]
  if host and domain(host):candidates.add(domain(host))
 assert depth==0
 return candidates,exceptions

def build(output=None):
 global ROOT
 ROOT=Path(output) if output else ROOT
 sources=json.loads((ROOT/'source-snapshots/manifest.json').read_text());all_domains=set();exceptions=set();stats={}
 for source in sources:
  blob=gzip.decompress((ROOT/'source-snapshots'/source['file']).read_bytes())
  assert hashlib.sha256(blob).hexdigest()==source['sha256']
  candidates,exc=parse(blob.decode('utf-8-sig'),source['kind'])
  all_domains|=candidates;exceptions|=exc;stats[source['name']]=len(candidates)
 def intersects(d,e):return d==e or d.endswith('.'+e) or e.endswith('.'+d)
 # Never block major service roots or shared hosting through conversion.
 protected={'yandex.ru','google.com','github.com','youtube.com','animego.me','wlout.xyz','cloudflare.com','amazonaws.com','github.io','pages.dev','blogspot.com','appspot.com','workers.dev','azurewebsites.net','cloudfront.net','t.me','telegram.org','vk.com'}
 # Apply exceptions only to these new imports; existing upstream policy remains intact.
 rejected={d for d in all_domains if d in protected or any(intersects(d,e) for e in exceptions)}
 domains=all_domains-rejected
 # Suffix deduplication only among newly imported domains.
 minimal=set()
 for d in sorted(domains,key=lambda x:(x.count('.'),x)):
  if not any('.'.join(d.split('.')[i:]) in minimal for i in range(1,len(d.split('.')))):minimal.add(d)
 blob=(ROOT/'geosite.dat').read_bytes();result=[];found=False;added=0
 for f,w,v,raw in fields(blob):
  if f==1 and next(x for ff,ww,x,rr in fields(v) if ff==1)==b'WLOUT-ADS':
   found=True;existing=set()
   for ff,ww,x,rr in fields(v):
    if ff==2:
     attrs={a:b for a,_,b,_ in fields(x)}
     if attrs.get(1)==2:existing.add(attrs.get(2,b'').decode())
   fresh={d for d in minimal if not any('.'.join(d.split('.')[i:]) in existing for i in range(len(d.split('.'))))}
   v+=b''.join(pack(2,b'\x08\x02'+pack(2,d.encode())) for d in sorted(fresh));added=len(fresh)
   raw=pack(1,v)
  result.append(raw)
 assert found and added>0
 output=b''.join(result);(ROOT/'geosite.dat').write_bytes(output)
 (ROOT/'imported-domains.txt').write_text('\n'.join(sorted(minimal))+'\n')
 manifest=json.loads((ROOT/'manifest.json').read_text());manifest.update(geosite_sha256=hashlib.sha256(output).hexdigest(),domain_import={'sources':sources,'eligible_per_source':stats,'exception_or_protected_removed':len(rejected),'deduplicated_import_domains':len(minimal),'new_geosite_entries':added,'policy':'unconditional whole-domain only; conditional branches and scoped rules skipped; host exceptions conservatively excluded; IPs skipped'})
 (ROOT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest['domain_import'],indent=2))
if __name__=='__main__':
 import argparse
 parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path)
 build(parser.parse_args().output)
