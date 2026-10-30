import urllib.request,json,hashlib,pathlib,argparse
parser=argparse.ArgumentParser()
parser.add_argument('--output',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1])
out=parser.parse_args().output
out.mkdir(parents=True,exist_ok=True)
import shutil
snapshot_source=pathlib.Path(__file__).resolve().parents[1]/"source-snapshots"
if out.resolve()!=snapshot_source.parent.resolve():
 shutil.copytree(snapshot_source,out/"source-snapshots",dirs_exist_ok=True)
def get(url):
 return urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'wlout-routing-builder'}),timeout=60).read()
def varint(b,p):
 n=0;s=0
 while True:
  v=b[p];p+=1;n|=(v&127)<<s
  if v<128:return n,p
  s+=7
def fields(b):
 p=0
 while p<len(b):
  start=p;k,p=varint(b,p);w=k&7
  if w==2:
   n,p=varint(b,p);val=b[p:p+n];p+=n
  elif w==0:val,p=varint(b,p)
  elif w in (1,5):n=8 if w==1 else 4;val=b[p:p+n];p+=n
  else:raise ValueError('wire')
  yield k>>3,w,val,b[start:p]
def enc(n):
 b=bytearray()
 while n>127:b.append((n&127)|128);n>>=7
 b.append(n);return bytes(b)
def pack(field,b):return enc(field*8+2)+enc(len(b))+b
sources=[];blobs={}
for repo,filename in [('hydraponique/roscomvpn-geosite','geosite.dat'),('hydraponique/roscomvpn-geoip','geoip.dat'),('Loyalsoldier/v2ray-rules-dat','geosite.dat')]:
 d=json.loads(get('https://api.github.com/repos/'+repo+'/releases/latest'))
 asset=next(a for a in d['assets'] if a['name']==filename)
 blob=get(asset['browser_download_url']);sha=hashlib.sha256(blob).hexdigest()
 checksum=next(a for a in d['assets'] if a['name'] in (filename+'.sha256',filename+'.sha256sum'))
 assert sha in get(checksum['browser_download_url']).decode()
 sources.append({'repository':repo,'version':d['tag_name'],'asset':filename,'sha256':sha,'source':asset['browser_download_url']})
 blobs[repo]=blob
 print(repo,d['tag_name'],len(blob))
ros=blobs['hydraponique/roscomvpn-geosite'];loy=blobs['Loyalsoldier/v2ray-rules-dat'];codes=[];reject=None
for f,w,b,raw in fields(ros):
 if f==1:codes.append(next(v.decode() for ff,ww,v,rr in fields(b) if ff==1))
for f,w,b,raw in fields(loy):
 if f==1:
  code=next(v.decode() for ff,ww,v,rr in fields(b) if ff==1)
  if code.lower()=='category-ads-all':reject=b;break
assert reject is not None
new=b''.join(pack(1,b'WLOUT-ADS') if ff==1 else raw for ff,ww,v,raw in fields(reject))
ros+=pack(1,new)
(out/'geosite.dat').write_bytes(ros);(out/'geoip.dat').write_bytes(blobs['hydraponique/roscomvpn-geoip'])
(out/'manifest.json').write_text(json.dumps({'sources':sources,'derived_category':'WLOUT-ADS from Loyalsoldier category-ads-all','geosite_sha256':hashlib.sha256(ros).hexdigest(),'geoip_sha256':hashlib.sha256((out/'geoip.dat').read_bytes()).hexdigest()},indent=2))
print('ROSCOM_CATEGORIES',codes)

# Add reviewed, versioned domain-only source snapshots.
import subprocess,sys
subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name("extend_blocklists.py")),"--output",str(out)],check=True)

subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name("build_policy_categories.py")),"--output",str(out)],check=True)
