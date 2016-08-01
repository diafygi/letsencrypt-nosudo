import os,sys
import subprocess as s
call = s.check_call
import shutil
import tempfile

def make_csr(csr,domain,key,*prefixes):
	if len(prefixes) == 0:
		return call(["openssl",
		      "req","-new", "-sha256", "-key", key,
		      "-subj", "/CN="+domain,"-out",csr])
	domains = [domain]
	for prefix in prefixes:
		domains.append(prefix+"."+domain)
	domains = ("DNS:"+domain for domain in domains)
	domains = ",".join(domains)
	with tempfile.NamedTemporaryFile() as out:
		with open("/etc/ssl/openssl.cnf","rb") as inp:
			shutil.copyfileobj(inp,out)
		out.write(("""
[SAN]
subjectAltName="""+domains).encode('utf-8'))
		out.flush()
		call(["openssl",
		      "req", "-new", "-sha256","-key", key, "-subj", "/",
		      "-reqexts", "SAN", "-config", out.name,"-out",csr])

if __name__ == '__main__':
	key,domain = sys.argv[1:3]
	if len(sys.argv) > 4:
	  status = make_csr(domain+"/csr",domain,key,*sys.argv[4:])
	else:
		status = make_csr(domain+"/csr",domain,key)	   
	if status != 0:
		raise SystemExit(status)


