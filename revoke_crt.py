#!/usr/bin/env python
import argparse, subprocess, json, os, urllib2, sys, base64, binascii, copy, \
    tempfile, re


def revoke_crt(pubkey, crt):
    """Use the ACME protocol to revoke an ssl certificate signed by a
    certificate authority.

    :param string pubkey: Path to the user account public key.
    :param string crt: Path to the signed certificate.
    """
    #CA = "https://acme-staging.api.letsencrypt.org"
    CA = "https://acme-v01.api.letsencrypt.org"
    TERMS = "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"
    nonce_req = urllib2.Request("{0}/directory".format(CA))
    nonce_req.get_method = lambda : 'HEAD'

    def _b64(b):
        "Shortcut function to go from bytes to jwt base64 string"
        return base64.urlsafe_b64encode(b).replace("=", "")

    def _a64(a):
        "Shortcut function to go from jwt base64 string to bytes"
        return base64.urlsafe_b64decode(str(a + ("=" * (len(a) % 4))))

    # Step 1: Get account public key
    sys.stderr.write("Reading pubkey file...\n")
    proc = subprocess.Popen(["openssl", "rsa", "-pubin", "-in", pubkey, "-noout", "-text"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("Error loading {0}".format(pubkey))
    pub_hex, pub_exp = re.search("Modulus\:\s+00:([a-f0-9\:\s]+?)Exponent\: ([0-9]+)", out, re.MULTILINE|re.DOTALL).groups()
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
    sys.stderr.write("Found public key!\n".format(header))

    # Step 2: Generate the payload that needs to be signed
    # revokation request
    proc = subprocess.Popen(["openssl", "x509", "-in", crt, "-outform", "DER"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    crt_der, err = proc.communicate()
    crt_der64 = _b64(crt_der)
    crt_raw = json.dumps({
        "resource": "revoke-cert",
        "certificate": crt_der64,
    }, sort_keys=True, indent=4)
    crt_b64 = _b64(crt_raw)
    crt_protected = copy.deepcopy(header)
    crt_protected.update({"nonce": urllib2.urlopen(nonce_req).headers['Replay-Nonce']})
    crt_protected64 = _b64(json.dumps(crt_protected, sort_keys=True, indent=4))
    crt_file = tempfile.NamedTemporaryFile(dir=".", prefix="revoke_", suffix=".json")
    crt_file.write("{0}.{1}".format(crt_protected64, crt_b64))
    crt_file.flush()
    crt_file_name = os.path.basename(crt_file.name)
    crt_file_sig = tempfile.NamedTemporaryFile(dir=".", prefix="revoke_", suffix=".sig")
    crt_file_sig_name = os.path.basename(crt_file_sig.name)

    # Step 3: Ask the user to sign the revocation request
    sys.stderr.write("""\
STEP 1: You need to sign a file (replace 'user.key' with your user private key)

openssl dgst -sha256 -sign user.key -out {0} {1}

""".format(crt_file_sig_name, crt_file_name))

    temp_stdout = sys.stdout
    sys.stdout = sys.stderr
    raw_input("Press Enter when you've run the above command in a new terminal window...")
    sys.stdout = temp_stdout

    # Step 4: Load the signature and send the revokation request
    sys.stderr.write("Requesting revocation...\n")
    crt_file_sig.seek(0)
    crt_sig64 = _b64(crt_file_sig.read())
    crt_data = json.dumps({
        "header": header,
        "protected": crt_protected64,
        "payload": crt_b64,
        "signature": crt_sig64,
    }, sort_keys=True, indent=4)
    try:
        resp = urllib2.urlopen("{0}/acme/revoke-cert".format(CA), crt_data)
        signed_der = resp.read()
    except urllib2.HTTPError as e:
        sys.stderr.write("Error: crt_data:\n")
        sys.stderr.write(crt_data)
        sys.stderr.write("\n")
        sys.stderr.write(e.read())
        sys.stderr.write("\n")
        raise
    sys.stderr.write("Certificate revoked!\n")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""\
Get a SSL certificate revoked by a Let's Encrypt (ACME) certificate authority.
You do NOT need to run this script on your server and this script does not ask
for your private keys. It will print out commands that you need to run with
your private key, which gives you a chance to review the commands instead of
trusting this script.

NOTE: YOUR PUBLIC KEY NEEDS TO BE THE SAME KEY USED TO ISSUE THE CERTIFICATE.

Prerequisites:
* openssl
* python

Example:
--------------
$ python revoke_crt.py --public-key user.pub domain.crt
--------------

""")
    parser.add_argument("-p", "--public-key", required=True, help="path to your account public key")
    parser.add_argument("crt_path", help="path to your signed certificate")

    args = parser.parse_args()
    revoke_crt(args.public_key, args.crt_path)

