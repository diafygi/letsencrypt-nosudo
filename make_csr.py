import os,sys
import subprocess as s
call = s.check_call

def make_csr(out,domain,key,*prefixes):
	if len(prefixes) == 0:
		return call(["openssl","openssl",
		      "req","-new", "-sha256", "-key", key,
		      "-subj", "/CN="+domain])
	domains = [domain]
	for prefix in prefixes:
		domains.append(prefix+"."+domain)
	domains = ("DNS:"+domain for domain in domains)
	domains = ",".join(domains)
	req = s.Popen(["openssl",
	               "req", "-new", "-sha256","-key", key, "-subj", "/",
	               "-reqexts", "SAN", "-config", "fd:0"],stdin=s.PIPE)
	
	with open("/etc/ssl/openssl.cnf","rb") as inp:
		shutil.copyfileobj(inp,req.stdin)
	req.stdin.write(("""
[SAN]
subjectAltName="""+domains).encode('utf-8'))

	return req.wait()

if __name__ == '__main__':
	key,domain = sys.argv[1:3]
	if len(sys.argv) > 4:
	  status = make_csr(domain+"/csr",domain,key,*sys.argv[4:])
	else:
		status = make_csr(domain+"/csr",domain,key)	   
	if status != 0:
		raise SystemExit(status)


