#!/bin/env python3
import os,sys

if not 'domain' in os.environ:
	raise SystemExit("domain=foo.bar.com python make.py www smtp derp")

domain = os.environ['domain']
out = os.environ.get("out","/etc/letsencrypt/")
prefixes = sys.argv[1:]

mkdir = os.mkdir
exists = os.path.exists
J = os.path.join

import subprocess
call = subprocess.check_call

def need_update(target,*deps):
	def deco(handle):
		if exists(target):
			test = os.stat(target).st_mtime
			for dep in deps:
				# this is eager, not lazy like make
				assert exists(dep),"Dependencies should be built first"
				if test < os.stat(dep).st_mtime:
					break
			else:
				return
		else:
			test = None
		# need rebuild
		try:
			return handle()
		except:
			# don't leave targets around if they've been touched
			# and we errored out!
			if (exists(target) and 
			    (test is None or
			     os.stat(target).st_mtime != test)):
				os.unlink(target)
			raise
	return deco
U = need_update

def check_location(loc):
	if not exists(loc):
		os.makedirs(loc)
	key = J(loc,"key")
	pub = J(loc,"pub")

	if not exists(key):
		call(["openssl","genrsa","-out",key,"4096"])
	@U(pub,key)
	def _():
		call(["openssl","rsa", "-in", key,"-pubout","-out",pub])
	return key,pub

def user(name):
	return J("user",name)

def check_cert(loc):
	key,pub = check_location(loc)
	csr = J(loc,"csr")
	cert = J(loc,"cert")
	import json
	info = J(loc,"info.json")
	try:
		with open(info) as inp:
			info = json.load(inp)
	except (IOError,json.JSONDecodeError):
		# Ask user for info
		from info import get_info
		derp = get_info(domain);		
		with open(info,"wt") as out:
			info = derp
			json.dump(info,out)

	@U(csr,key)
	def _():
		print('make CSR')
		from make_csr import make_csr
		make_csr(csr, domain, key, *prefixes)
	@U(cert,csr)
	def _():
		with open(cert,'wt') as out:
			from sign_csr import sign_csr
			out.write(sign_csr(pubkey=user("pub"),
			                csr=csr,
			                privkey=user("key"),
			                email=email,
			                file_based="run_server" not in os.environ))

check_location("user")

if out:
	if not exists(out):
		os.makedirs(out)
	out = J(out,domain)
else:
	out = domain

if not exists(out):
	os.mkdir(out)

check_cert(out)
