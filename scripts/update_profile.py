"""Regenerate Happ import link after editing the public profile."""
import base64,json,time
from pathlib import Path
root=Path(__file__).resolve().parents[1]
p=json.loads((root/'profile.json').read_text())
p['LastUpdated']=str(int(time.time()))
manifest=json.loads((root/'manifest.json').read_text())
p['Geoipurl']=p['Geoipurl'].split('?')[0]+'?v='+manifest['geoip_sha256'][:12]
p['Geositeurl']=p['Geositeurl'].split('?')[0]+'?v='+manifest['geosite_sha256'][:12]
(root/'profile.json').write_text(json.dumps(p,ensure_ascii=False,indent=2)+'\n')
raw=json.dumps(p,ensure_ascii=False,separators=(',',':')).encode()
(root/'import.txt').write_text('happ://routing/onadd/'+base64.b64encode(raw).decode()+'\n')
