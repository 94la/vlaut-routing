import unittest
from extend_blocklists import parse
class Conversion(unittest.TestCase):
 def test_never_widen_scopes(self):
  text='\n'.join(['||ads.example.com^','||tracker.example.com^$important','||yandex.ru/an/count/$all','||scoped.example.com^$third-party','||script.example.com^$script','||site.example.com^$domain=other.example','@@||ads.example.com/allowed$script','!#if env_mobile','||conditional.example.com^','!#endif'])
  hosts,exceptions=parse(text,'abp')
  self.assertEqual(hosts,{'ads.example.com','tracker.example.com'})
  self.assertEqual(exceptions,{'ads.example.com'})
 def test_malware_and_hosts(self):
  self.assertEqual(parse('1.2.3.4\nmalware.example.com\n||github.com/user/bad.exe^$all','malware')[0],{'malware.example.com'})
  self.assertEqual(parse('127.0.0.1 ads.example.com\n0.0.0.0 tracker.example.com','hosts')[0],{'ads.example.com','tracker.example.com'})
if __name__=='__main__':unittest.main()
