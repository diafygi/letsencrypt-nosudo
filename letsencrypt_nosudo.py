#!/usr/bin/env python2.7

import base64
import binascii
import copy
import hashlib
import json
import logging
import os
import random
import re
import subprocess
import sys
import tempfile
import textwrap
import time
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from contextlib import contextmanager
from multiprocessing import Process

import click
import requests

logger = logging.getLogger('letsencrypt_nosudo')
STAGING_CA = "https://acme-staging.api.letsencrypt.org"
PRODUCTION_CA = "https://acme-v01.api.letsencrypt.org"
TERMS = "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"
CA_CERT_URLS = [
    # 'https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem',
    # 'https://letsencrypt.org/certs/lets-encrypt-x2-cross-signed.pem',
    'https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem',
    # 'https://letsencrypt.org/certs/lets-encrypt-x4-cross-signed.pem',
]


@click.group()
def main():
    pass


@main.command(help='Generate user key pair')
@click.argument('name')
def generate_user_key(name):
    if name.endswith(('.key', '.pub')):
        name = name[:-4]

    privkey_filename = '{}.key'.format(name)
    pubkey_filename = '{}.pub'.format(name)

    if os.path.exists(privkey_filename):
        logger.critical('Private key file {} already exists. Not overwriting.'
                        .format(privkey_filename))
        raise click.Abort()

    if os.path.exists(pubkey_filename):
        logger.warning('Public key file {} already exists. Not overwriting.'
                       .format(pubkey_filename))
        raise click.Abort()

    logger.info('Generating private key: {}'.format(privkey_filename))
    with open(privkey_filename, 'w') as fp:
        subprocess.check_call(
            ('openssl', 'genrsa', '4096'), stdout=fp)

    logger.info('Exporting public key: {}'.format(pubkey_filename))
    with open(pubkey_filename, 'w') as fp:
        subprocess.check_call(
            ('openssl', 'rsa', '-in', privkey_filename, '-pubout'), stdout=fp)


@main.command(help='Generate private key for a domain')
@click.argument('name')
def generate_domain_key(name):
    if name.endswith(('.key', '.pub')):
        name = name[:-4]

    privkey_filename = '{}.key'.format(name)

    if os.path.exists(privkey_filename):
        logger.critical('Private key file {} already exists. Not overwriting.'
                        .format(privkey_filename))
        raise click.Abort()

    logger.info('Generating private key: {}'.format(privkey_filename))
    with open(privkey_filename, 'w') as fp:
        subprocess.check_call(
            ('openssl', 'genrsa', '4096'), stdout=fp)


@main.command(help='Generate certificate signing request for a domain')
@click.option('-d', '--domain-name', 'domain_names', multiple=True)
@click.option('-k', '--domain-key')
@click.option('-o', '--output')
@click.option('--base-openssl-config', default='/etc/ssl/openssl.cnf')
def generate_csr(domain_names, domain_key, base_openssl_config, output):
    if len(domain_names) < 1:
        logger.critical('You must pass at least one domain name')
        raise click.Abort()

    if domain_key is None:
        domain_key = '{}.key'.format(domain_names[0])
        logger.info('Domain key not specified. Try guessing {}'
                    .format(domain_key))

    if not os.path.exists(domain_key):
        logger.critical('Domain key not found: {}'.format(domain_key))
        raise click.Abort()

    if output is None:
        output = '{}.csr'.format(domain_names[0])
    logger.info('Creating CSR for {} domains: {}'
                .format(len(domain_names), output))

    if os.path.exists(output):
        if not click.confirm('File exists. Overwrite?', default=False):
            raise click.Abort()

    with open(base_openssl_config) as fp:
        openssl_config = fp.read()

    subj_alt_name = ','.join('DNS:{}'.format(x) for x in domain_names)

    with tempfile.NamedTemporaryFile(suffix='.cnf') as cfgfile:
        cfgfile.write(openssl_config)
        cfgfile.write('\n[SAN]\n')
        cfgfile.write('subjectAltName={}\n'.format(subj_alt_name))
        cfgfile.seek(0)

        command = [
            'openssl', 'req', '-new', '-sha256', '-key', domain_key,
            '-subj', '/', '-reqexts', 'SAN', '-config', cfgfile.name,
        ]

        with open(output, 'w') as fp:
            subprocess.check_call(command, stdout=fp)


@main.command(help='Sign a CSR via letsencrypt')
@click.option('-k', '--public-key', default='user.pub', metavar='PATH')
@click.option('-K', '--private-key', default='user.key', metavar='PATH')
@click.option('--email', default='Contact email', prompt='Contact email')
@click.option('--ca-url', default='production',
              help='URL to the CA API, or "production" (default) / "staging"')
@click.option('-m', '--method',
              type=click.Choice(['file', 'run-manual', 'run-local']))
@click.option('-p', '--port', default=80, type=int)
@click.option('-f', '--input-file', help='Path to the CSR to be signed')
@click.option('-o', '--output', help='Certificate file name')
def sign_csr(public_key, private_key, email, ca_url, method, port, input_file,
             output):

    if ca_url == 'production':
        ca_url = PRODUCTION_CA
    elif ca_url == 'staging':
        ca_url = STAGING_CA

    if input_file is None:
        # TODO guess
        logger.critical('An input file is required')
        raise click.Abort()

    if output is None:
        # TODO generate
        logger.critical('An output file is required')
        raise click.Abort()

    # ------------------------------------------------------------

    pubkey_info = _read_pubkey_file_info(public_key)
    csr_info = _read_csr_file_info(input_file)

    if email is None:
        raise NotImplementedError('TODO generate email from domain')

    client = LetsencryptClient(ca_url)

    # ------------------------------------------------------------
    # Step 4: Generate the payloads that need to be signed
    # registration

    logger.info("Building request payloads")
    reg_nonce = client.get_nonce()
    reg_raw = json.dumps({
        "resource": "new-reg",
        "contact": ["mailto:{0}".format(email)],
        "agreement": TERMS,
    })
    reg_b64 = _b64(reg_raw)

    reg_protected = copy.deepcopy(pubkey_info.header)
    reg_protected['nonce'] = reg_nonce
    reg_protected64 = _b64(json.dumps(reg_protected))

    reg_file = tempfile.NamedTemporaryFile(
        dir=".", prefix="register_", suffix=".json")
    reg_file.write("{0}.{1}".format(reg_protected64, reg_b64))
    reg_file.flush()
    reg_file_name = os.path.basename(reg_file.name)

    reg_file_sig = tempfile.NamedTemporaryFile(
        dir=".", prefix="register_", suffix=".sig")
    reg_file_sig_name = os.path.basename(reg_file_sig.name)

    # need signature for each domain identifiers
    ids = []
    for domain in csr_info.domain_names:
        logger.info("Building request for %s", domain)
        id_nonce = client.get_nonce()
        id_raw = json.dumps({
            "resource": "new-authz",
            "identifier": {
                "type": "dns",
                "value": domain,
            },
        })
        id_b64 = _b64(id_raw)
        id_protected = copy.deepcopy(pubkey_info.header)
        id_protected['nonce'] = id_nonce
        id_protected64 = _b64(json.dumps(id_protected))
        id_file = tempfile.NamedTemporaryFile(
            dir=".", prefix="domain_", suffix=".json")
        id_file.write("{0}.{1}".format(id_protected64, id_b64))
        id_file.flush()
        id_file_name = os.path.basename(id_file.name)
        id_file_sig = tempfile.NamedTemporaryFile(
            dir=".", prefix="domain_", suffix=".sig")
        id_file_sig_name = os.path.basename(id_file_sig.name)
        ids.append({
            "domain": domain,
            "protected64": id_protected64,
            "data64": id_b64,
            "file": id_file,
            "file_name": id_file_name,
            "sig": id_file_sig,
            "sig_name": id_file_sig_name,
        })

    # need signature for the final certificate issuance
    logger.info("Building request for CSR")
    csr_der = subprocess.check_output(
        ["openssl", "req", "-in", input_file, "-outform", "DER"])
    csr_der64 = _b64(csr_der)
    csr_nonce = client.get_nonce()
    csr_raw = json.dumps({
        "resource": "new-cert",
        "csr": csr_der64,
    }, sort_keys=True, indent=4)
    csr_b64 = _b64(csr_raw)
    csr_protected = copy.deepcopy(pubkey_info.header)
    csr_protected.update({"nonce": csr_nonce})
    csr_protected64 = _b64(json.dumps(csr_protected, sort_keys=True, indent=4))
    csr_file = tempfile.NamedTemporaryFile(
        dir=".", prefix="cert_", suffix=".json")
    csr_file.write("{0}.{1}".format(csr_protected64, csr_b64))
    csr_file.flush()
    csr_file_name = os.path.basename(csr_file.name)
    csr_file_sig = tempfile.NamedTemporaryFile(
        dir=".", prefix="cert_", suffix=".sig")
    csr_file_sig_name = os.path.basename(csr_file_sig.name)

    # ----------------------------------------------------------------------
    # Step 5: Ask the user to sign the registration and requests
    logger.info('Signing registration and  requests')
    SIGN_COMMAND = 'openssl dgst -sha256 -sign user.key -out {} {}'

    _openssl_sign(private_key, reg_file_sig_name, reg_file_name)
    for i in ids:
        _openssl_sign(private_key, i['sig_name'], i['file_name'])
    _openssl_sign(private_key, csr_file_sig_name, csr_file_name)

    # ----------------------------------------------------------------------
    # Step 6: Load the signatures

    reg_file_sig.seek(0)
    reg_sig64 = _b64(reg_file_sig.read())
    for n, i in enumerate(ids):
        i['sig'].seek(0)
        i['sig64'] = _b64(i['sig'].read())

    # ----------------------------------------------------------------------
    # Step 7: Register the user

    logger.info("Registering user: %s", email)
    try:
        client.register_user(
            key_header=pubkey_info.header,
            protected_b64=reg_protected64,
            payload_b64=reg_b64,
            sig_b64=reg_sig64)
    except LetsencryptClientError as exc:
        content = exc.response.content
        if "Registration key is already in use" in content:
            # TODO: check status_code as well?
            logger.warning("User is already registered. Skipping.")
        else:
            raise

    # ----------------------------------------------------------------------
    # Step 8: Request challenges for each domain

    responses = []
    tests = []
    for n, i in enumerate(ids):
        logger.info("Requesting challenges for %s [%s -> %s]",
                    i['domain'], n, i)

        result = client.new_authz(
            key_header=pubkey_info.header,
            protected_b64=i['protected64'],
            payload_b64=i['data64'],
            sig_b64=i['sig64'])
        challenge = [c for c in result['challenges']
                     if c['type'] == "http-01"][0]
        keyauthorization = "{0}.{1}".format(challenge['token'],
                                            pubkey_info.thumbprint)

        # challenge request
        logger.info("Building challenge responses for %s", i['domain'])
        test_nonce = client.get_nonce()
        test_raw = json.dumps({
            "resource": "challenge",
            "keyAuthorization": keyauthorization,
        }, sort_keys=True, indent=4)
        test_b64 = _b64(test_raw)
        test_protected = copy.deepcopy(pubkey_info.header)
        test_protected.update({"nonce": test_nonce})
        test_protected64 = _b64(json.dumps(test_protected))
        test_file = tempfile.NamedTemporaryFile(
            dir=".", prefix="challenge_", suffix=".json")
        test_file.write("{0}.{1}".format(test_protected64, test_b64))
        test_file.flush()
        test_file_name = os.path.basename(test_file.name)
        test_file_sig = tempfile.NamedTemporaryFile(
            dir=".", prefix="challenge_", suffix=".sig")
        test_file_sig_name = os.path.basename(test_file_sig.name)
        tests.append({
            "uri": challenge['uri'],
            "protected64": test_protected64,
            "data64": test_b64,
            "file": test_file,
            "file_name": test_file_name,
            "sig": test_file_sig,
            "sig_name": test_file_sig_name,
        })

        # challenge response for server
        responses.append({
            "uri": ".well-known/acme-challenge/{0}".format(challenge['token']),
            "data": keyauthorization,
        })

    # ----------------------------------------------------------------------
    # Step 9: Ask the user to sign the challenge responses
    for i in tests:
        _openssl_sign(private_key, i['sig_name'], i['file_name'])

    # ----------------------------------------------------------------------
    # Step 10: Load the response signatures
    for n, i in enumerate(ids):
        tests[n]['sig'].seek(0)
        tests[n]['sig64'] = _b64(tests[n]['sig'].read())

    # ----------------------------------------------------------------------
    # Step 11: Ask the user to host the token on their server

    for n, i in enumerate(ids):
        response = responses[n]
        verify_context = _get_verification_ctx(
            method, idx=n, domain=i['domain'], path=response['uri'],
            data=response['data'], port=port)

        with verify_context:

            # --------------------------------------------------------------
            # Step 12: Let the CA know you're ready for the challenge
            logger.info("Requesting verification for %s", i['domain'])
            test_url = tests[n]['uri']

            result = client.request_verification(
                url=test_url,
                key_header=pubkey_info.header,
                protected_b64=tests[n]['protected64'],
                payload_b64=tests[n]['data64'],
                signature_b64=tests[n]['sig64'])

            # --------------------------------------------------------------
            # Step 13: Wait for CA to mark test as valid
            logger.info("Waiting for %s challenge to pass", i['domain'])

            while True:
                logger.debug('Polling status at %s', test_url)
                challenge_status = client.get_challenge_status(test_url)

                if challenge_status == "pending":
                    time.sleep(2)

                elif challenge_status == "valid":
                    logger.info("Passed challenge for %s", i['domain'])
                    break

                else:
                    logger.critical('Challenge failed for %s (status: %s)',
                                    i['domain'], challenge_status)
                    raise click.Abort()

    # ----------------------------------------------------------------------
    # Step 14: Get the certificate signed
    logger.info('Requesting signature')
    csr_file_sig.seek(0)
    csr_sig64 = _b64(csr_file_sig.read())
    signed_der = client.new_cert(
        key_header=pubkey_info.header,
        protected_b64=csr_protected64,
        payload_b64=csr_b64,
        sig_b64=csr_sig64)

    # ----------------------------------------------------------------------
    # Step 15: Convert the signed cert from DER to PEM
    logger.info("Certificate signed successfully")

    signed_der64 = base64.b64encode(signed_der)
    signed_pem = (
        '-----BEGIN CERTIFICATE-----\n'
        '{}\n'
        '-----END CERTIFICATE-----\n'
        .format("\n".join(textwrap.wrap(signed_der64, 64))))

    logger.info('Writing signed certificate to %s', output)
    with open(output, 'w') as fp:
        fp.write(signed_pem)

    # ----------------------------------------------------------------------
    # Step 16: generate full PEM w/ chained certs (for NGINX)
    output_chained = output + '.pem'
    logger.info('Generating chained certificate %s', output_chained)
    url = random.choice(CA_CERT_URLS)
    logger.info('Chaining with %s', url)

    resp = requests.get(url)
    if not resp.ok:
        logger.critical('Getting CA certificate %s failed', url)
        raise click.Abort()
    cert_data = resp.content

    with open(output_chained, 'w') as fp:
        fp.write(signed_pem)
        fp.write('\n')
        fp.write(cert_data)
    logger.info('Chained certificate written to %s', output_chained)


class SimpleDataStructure(object):
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _read_pubkey_file_info(filename):
    logger.info('Reading pubkey file {} ...'.format(filename))
    cmd_output = subprocess.check_output(
        ('openssl', 'rsa', '-pubin', '-in', filename, '-noout', '-text'))

    pub_hex, pub_exp = re.search(
        r"Modulus(?: \((?:2048|4096) bit\)|)\:\s+00:([a-f0-9\:\s]+?)"
        r"Exponent\: ([0-9]+)", cmd_output, re.MULTILINE | re.DOTALL).groups()
    pub_mod = binascii.unhexlify(re.sub("(\s|:)", "", pub_hex))
    pub_mod64 = _b64(pub_mod)
    pub_exp = int(pub_exp)
    pub_exp = "{0:x}".format(pub_exp)
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    pub_exp = binascii.unhexlify(pub_exp)
    pub_exp64 = _b64(pub_exp)
    header = {
        "alg": "RS256",
        "jwk": {
            "e": pub_exp64,
            "kty": "RSA",
            "n": pub_mod64,
        },
    }
    accountkey_json = json.dumps(
        header['jwk'], sort_keys=True, separators=(',', ':'))
    thumbprint = _b64(hashlib.sha256(accountkey_json).digest())

    return PubkeyFileInfo(
        # TODO: which information is required outside?
        header=header,
        thumbprint=thumbprint,
    )


class PubkeyFileInfo(SimpleDataStructure):
    pass


def _read_csr_file_info(filename):
    logger.info("Reading CSR file {} ...".format(filename))
    cmd_output = subprocess.check_output(
        ["openssl", "req", "-in", filename, "-noout", "-text"])

    def _find_common_name():
        match = re.search(r"Subject:.*? CN=([^\s,;/]+)", cmd_output)
        if match is not None:
            return match.group(1)
        return None

    def _find_alt_names():
        match = re.search(
            r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", cmd_output,
            re.MULTILINE | re.DOTALL)
        if match is not None:
            for san in match.group(1).split(", "):
                if san.startswith("DNS:"):
                    yield san[4:]

    info = CSRFileInfo()

    info.common_name = _find_common_name()
    logger.info("Common name: %s", info.common_name)

    info.alt_names = list(_find_alt_names())
    logger.info("Alt names: %s", ", ".join(info.alt_names))

    info.domain_names = set()
    info.domain_names.add(info.common_name)
    info.domain_names.update(info.alt_names)
    info.domain_names.discard(None)
    logger.info("All domain names: %s", ", ".join(info.domain_names))

    return info


class CSRFileInfo(SimpleDataStructure):
    pass


class LetsencryptClient(object):

    def __init__(self, base_url):
        self.base_url = base_url

    def get_nonce(self):
        url = '{}/directory'.format(self.base_url)
        response = self._request('HEAD', url)
        return response.headers['Replay-Nonce']

    def register_user(self, key_header, protected_b64, payload_b64, sig_b64):

        url = "{}/acme/new-reg".format(self.base_url)
        data = {
            "header": key_header,
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": sig_b64,
        }
        response = self._request('POST', url, json=data)
        return response.json()

    def new_authz(self, key_header, protected_b64, payload_b64, sig_b64):
        url = "{}/acme/new-authz".format(self.base_url)
        data = {
            "header": key_header,
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": sig_b64,
        }
        response = self._request('POST', url, json=data)
        return response.json()

    def request_verification(
            self, url, key_header, protected_b64, payload_b64, signature_b64):
        data = {
            "header": key_header,
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64,
        }
        response = self._request('POST', url, json=data)
        return response.json()

    def get_challenge_status(self, url):
        response = self._request('GET', url)
        return response.json()['status']

    def new_cert(self, key_header, protected_b64, payload_b64, sig_b64):
        url = "{}/acme/new-cert".format(self.base_url)
        data = {
            "header": key_header,
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": sig_b64,
        }
        response = self._request('POST', url, json=data)
        return response.content

    def _request(self, method, url, *a, **kw):
        response = requests.request(method, url, *a, **kw)
        if not response.ok:
            raise LetsencryptClientError(
                'HTTP Error {}: {}'
                .format(response.status_code, response.content[:200]),
                response=response)
        return response


class LetsencryptClientError(Exception):
    def __init__(self, *a, **kw):
        response = kw.pop('response')
        super(LetsencryptClientError, self).__init__(*a, **kw)
        self.response = response


def _b64(b):
    "Shortcut function to go from bytes to jwt base64 string"
    return base64.urlsafe_b64encode(b).replace("=", "")


def _openssl_sign(privkey, outfile, infile):
    command = ('openssl', 'dgst', '-sha256', '-sign', privkey,
               '-out', outfile, infile)
    logger.info('Signing command: %s', str(command))
    subprocess.check_call(command)


def _get_verification_ctx(method, idx, domain, path, data, port):
    if method == 'file':
        return _verification_file_based_ctx(idx, domain, path, data)
    if method == 'run-manual':
        return _verification_run_remote_ctx(idx, domain, data, port)
    if method == 'run-local':
        return _verification_run_local_ctx(idx, domain, path, data, port)
    raise AssertionError


@contextmanager
def _verification_file_based_ctx(idx, domain, path, data):
    click.echo(
        'STEP 4.{idx}: Please update your server to serve the following '
        'file at this URL:\n\n'

        '--------------\n'
        'URL: http://{domain}/{path}\n'
        'File contents: \"{contents}\"\n'
        '--------------\n\n'

        'Notes:\n'
        '- Do not include the quotes in the file.\n'
        '- The file should be one line without any spaces.\n'

        .format(idx=idx, domain=domain, path=path, data=data), err=True)
    click.prompt('Press ENTER to continue', err=True)
    yield
    click.echo("You can now remove the acme-challenge file "
               "from your webserver", err=True)


@contextmanager
def _verification_run_remote_ctx(idx, domain, data, port):
    click.echo(
        'STEP 4.{idx}: You need to run this command on {domain} '
        '(don\'t stop the python command until the next step).\n'

        'sudo python -c "import BaseHTTPServer; \\\n'
        '    h = BaseHTTPServer.BaseHTTPRequestHandler; \\\n'
        '    h.do_GET = lambda r: r.send_response(200) or r.end_headers() '
        'or r.wfile.write(\'{data}\'); \\\n'
        '    s = BaseHTTPServer.HTTPServer((\'0.0.0.0\', {port}), h); \\\n'
        '    s.serve_forever()"\n'

        .format(idx=idx, domain=domain, data=data, port=port), err=True)
    click.prompt('Press ENTER to continue', err=True)
    yield
    click.echo('You can stop running the python command on your server '
               '(Ctrl+C works).', err=True)


@contextmanager
def _verification_run_local_ctx(idx, domain, path, data, port):
    full_url = 'http://{}/{}'.format(domain, path)
    click.echo(
        'Starting HTTP server locally on port {port}\n\n'

        'To allow the remote server to connect back, use a reverse SSH tunnel '
        'like this:\n\n'

        '    ssh -R "127.0.0.1:8080:127.0.0.1:{port}" -N {domain}\n\n'

        '(This will listen on connections to port 8080/tcp on the remote '
        'machine and forward to the process running locally on port {port})\n'

        'Then, make sure that a GET request to this URL:\n\n'

        '    {url}\n\n'

        'Returns the expected verification data:\n\n    {data}\n'

        .format(idx=idx, domain=domain, port=port, url=full_url, data=data))

    class MyHttpHandler(BaseHTTPRequestHandler):
        def do_GET(r):
            r.send_response(200)
            r.end_headers()
            r.wfile.write(data)

    server = HTTPServer(('0.0.0.0', port), MyHttpHandler)
    proc = Process(target=server.serve_forever)
    proc.start()
    logger.info('Server started with PID %s', proc.pid)

    # Double-check..
    resp = requests.get(full_url)
    if not resp.ok:
        logger.warning('A request to %s returned status code %s',
                       full_url, resp.status_code)
    if resp.content != data:
        logger.warning('A request to %s returned a mismatching response',
                       full_url)
    logger.info('All good, %s is responding properly', full_url)

    yield

    logger.info('Waiting for server process %s to terminate', proc.pid)
    proc.terminate()
    proc.join()


def setup_logging():
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.INFO)

    class MyFormatter(logging.Formatter):
        def __init__(self, fmt='[%(name)s] %(message)s', datefmt=None):
            super(MyFormatter, self).__init__(fmt, datefmt)

        def format(self, record):
            colors = {
                logging.DEBUG: 'cyan',
                logging.INFO: 'green',
                logging.WARNING: 'yellow',
                logging.ERROR: 'red',
                logging.CRITICAL: 'red',
            }

            color = colors.get(record.levelno)
            levelname = click.style(record.levelname, fg=color, bold=True)
            message = super(MyFormatter, self).format(record)
            if record.name.split('.')[0] == 'letsencrypt_nosudo':
                message = click.style(message, fg=color)
            else:
                message = click.style(message, fg='white')
            return '{} {}'.format(levelname, message)

    handler.setFormatter(MyFormatter())

    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)


if __name__ == '__main__':
    setup_logging()
    main()
