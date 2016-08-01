import os,sys
mkdir = os.mkdir
exists = os.path.exists
J = os.path.join

import subprocess as s
call = s.check_call

if not 'domain' in os.environ:
	raise SystemExit("domain=foo.bar.com python make.py www smtp derp")

def need_update(target,*deps):
	if not exists(target): return True
	test = os.stat(target).st_mtime
	for dep in deps:
		# this is eager, not lazy like make
		assert(exists(dep),"Dependencies should be built first")
		if test < os.stat(dep).st_mtime:
			return True
	return False
U = needs_update

domain = os.environ['domain']
out = os.environ.get("out","")
prefixes = sys.argv[1:]

def check_location(loc):
	if not exists(loc):
		os.makedirs(loc)
	key = J(loc,"key")
	pub = J(loc,"pub")

	if not exists(key):
		call(["openssl","genrsa","-out",key,"4096"])
	if U(pub,key):
		call(["openssl","rsa", "-in", key,"-pubout","-out",pub])
	return key,pub

def user(name):
	return J("user",name)

def check_cert(loc):
	key,pub = check_location(loc)
	csr = J(loc,"csr")
	cert = J(loc,"cert")
	if U(csr,key):
		from make_csr import make_csr
		make_csr(csr, domain, key, *prefixes)
	if U(cert,key):
		from sign_csr import sign_csr
		sign_csr( pubkey=user("pub"),
csr=
