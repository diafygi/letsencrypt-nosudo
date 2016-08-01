import os,sys
key,domain = sys.argv[1:3]
if len(sys.argv) == 4:
	os.execlp("openssl","openssl",
	          "req","-new", "-sha256", "-key", key,
	          "-subj", "/CN="+domain)
	raise RuntimeError

domains = [domain]
for prefix in sys.argv[4:]:
	domains.append(prefix+"."+domain)

domains = ("DNS:"+domain for domain in domains)
domains = ",".join(domains)

with open("/etc/ssl/openssl.cnf","r",encoding='utf-8') as inp:
	config = inp.read()
config += """
[SAN]
subjectAltName="""+domains

os.execlp("openssl","openssl",
          "req", "-new", "-sha256","-key", key, "-subj", "/",
          "-reqexts", "SAN", "-config", config)
