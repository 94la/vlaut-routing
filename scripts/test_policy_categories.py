import json,unittest
from pathlib import Path
from build_policy_categories import categories,compile_site,compile_ip,fields
ROOT=Path(__file__).resolve().parents[1]
class PolicyCategories(unittest.TestCase):
 def test_compiled_rules_equal_original_inputs(self):
  p=json.loads((ROOT/'policy-inputs.json').read_text());s=categories((ROOT/'geosite.dat').read_bytes());i=categories((ROOT/'geoip.dat').read_bytes())
  self.assertEqual(s['wlout-direct'],compile_site(p['DirectSites'],s,'wlout-direct'))
  self.assertEqual(s['wlout-proxy'],compile_site(p['ProxySites'],s,'wlout-proxy'))
  self.assertEqual(i['wlout-direct'],compile_ip(p['DirectIp'],i,'wlout-direct'))
  profile=json.loads((ROOT/'profile.json').read_text())
  self.assertEqual(profile['DirectSites'],['geosite:wlout-direct'])
  self.assertEqual(profile['DirectIp'],['geoip:wlout-direct'])
  self.assertEqual(profile['ProxySites'],['geosite:wlout-proxy'])
 def test_custom_domain_and_private_network_present(self):
  s=categories((ROOT/'geosite.dat').read_bytes());vals=[]
  for f,w,v,raw in fields(s['wlout-direct']):
   if f==2:vals.append({ff:x for ff,ww,x,rr in fields(v)})
  self.assertIn({1:2,2:b'animego.me'},vals)
  for zone in ['ru','su','xn--p1ai']:
   self.assertIn({1:1,2:('.*\\.'+zone+'$').encode()},vals)
if __name__=='__main__':unittest.main()
