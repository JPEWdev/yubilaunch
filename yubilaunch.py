#! /usr/bin/env python3
#
# SPDX-License-Identifier: BSD-2-Clause

import argparse
import binascii
import os
import sys
import hashlib
import yubico
import hmac
import json
import logging
import time

from Crypto.Cipher import AES

PHRASE = "Test"
CHALLENGE_LENGTH = 20

def do_challenge(yk, state):
    """ Send a challenge to the YubiKey and use the result to decrypt the state file. """
    challenge = state["challenge"]
    logging.debug("Challenge : %s" % (challenge))

    try:
        response = yk.challenge_response(binascii.unhexlify(state["challenge"]).ljust(64, b'\0'), slot=state["slot"])
    except yubico.yubico_exception.YubicoError as e:
        logging.debug("YubiKey challenge-response failed (%s)" % e.reason)
        return False

    logging.debug("Got %i bytes response %s\n" % (len(response), binascii.hexlify(response)))

    inner_j = decrypt_with_response(state["inner"], response)
    logging.debug("Decrypted 'inner' :\n%s\n" % (inner_j))

    secret_dict = {}
    try:
        secret_dict = json.loads(inner_j.decode('ascii'))
        if secret_dict["phrase"] != PHRASE:
            print("Bad phrase")
            return False
    except (ValueError, KeyError) as e:
        logging.info("Could not parse decoded data as JSON (%s), you probably did not produce the right response." % str(e))
        return False

    secret_dict["count"] += 1
    secret_dict["nonce"] = binascii.hexlify(os.urandom(20)).decode('ascii'),

    logging.debug("Unique identifier is %s" % secret_dict["phrase"])
    logging.debug("Accessed %d times" % secret_dict["count"])

    roll_next_challenge(state, binascii.unhexlify(secret_dict["hmac_key"]), secret_dict)
    return True

def roll_next_challenge(state, hmac_key, inner_dict):
    """
    When we have the HMAC-SHA1 key in clear, generate a random challenge and compute the
    expected response for that challenge.
    hmac_key is a 20-byte bytestring
    """
    if len(hmac_key) != 20 or not isinstance(hmac_key, bytes):
        hmac_key = binascii.unhexlify(hmac_key)

    challenge = os.urandom(CHALLENGE_LENGTH)
    response = get_response(hmac_key, challenge)

    logging.debug("Generated challenge : %s" % binascii.hexlify(challenge).decode('ascii'))
    logging.debug("Expected response   : %s (sssh, don't tell anyone)" % binascii.hexlify(response).decode('ascii'))

    logging.debug("To manually verify that your YubiKey produces this response, use :")
    logging.debug("  $ ykchalresp -%i -x %s" % (state["slot"], binascii.hexlify(challenge).decode('ascii')))

    inner_dict["hmac_key"] = binascii.hexlify(hmac_key).decode('ascii')
    inner_j = json.dumps(inner_dict, indent = 4)
    logging.debug("Inner JSON :\n%s" % (inner_j))

    inner_ciphertext = encrypt_with_response(inner_j, response)
    state["challenge"] = binascii.hexlify(challenge).decode('ascii')
    state["inner"] = inner_ciphertext.decode('ascii')

def get_response(hmac_key, challenge):
    """ Compute the expected response for `challenge', as hexadecimal string """
    #print(binascii.hexlify(hmac_key), binascii.hexlify(challenge), hashlib.sha1)
    h = hmac.new(hmac_key, challenge, hashlib.sha1)
    return h.digest()

def encrypt_with_response(data, key):
    """
    Encrypt our secret inner data with the response we expect the next time.
    NOTE: The use of AES CBC has not been validated as cryptographically sound
          in this application.
    I would have done this with GPGme if it weren't for the fact that neither
    of the two versions for Python available in Ubuntu 10.10 have support for
    symmetric encrypt/decrypt (LP: #295918).
    """
    # pad data to multiple of 16 bytes for AES CBC
    pad = len(data) % 16
    data += ' ' * (16 - pad)

    # need to pad key as well
    aes_key = key
    aes_key += b'\0' * (32 - len(aes_key))
    logging.debug("AES-CBC encrypting 'inner' with key (%i bytes) : %s" % (len(aes_key), binascii.hexlify(aes_key)))

    obj = AES.new(aes_key, AES.MODE_CBC, b'\0' * 16)
    ciphertext = obj.encrypt(data)
    return binascii.hexlify(ciphertext)

def decrypt_with_response(data, key):
    """
    Try to decrypt the secret inner data with the response we got to this challenge.
    """
    aes_key = key
    try:
        aes_key = binascii.unhexlify(key)
    except (TypeError, binascii.Error):
        # was not hex encoded
        pass
    # need to pad key
    aes_key += b'\0' * (32 - len(aes_key))
    logging.debug("AES-CBC decrypting 'inner' using key (%i bytes) : %s" % (len(aes_key), binascii.hexlify(aes_key)))

    obj = AES.new(aes_key, AES.MODE_CBC, b'\0' * 16)
    plaintext = obj.decrypt(binascii.unhexlify(data))
    return plaintext

def write_state_file(filename, data):
    """ Save state to file. """
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4, sort_keys=True)

def load_state_file(filename):
    """ Load (and parse) the state file. """
    try:
        with open(filename) as f:
            return json.load(f)
    except FileNotFoundError:
        return dict()

def do_addkey(args):
    state = load_state_file(args.filename)

    if args.name in state:
        print("'%s' already exists. Aborting" % args.name)
        return 1

    if args.hmac_key:
        try:
            hmac_key = binascii.unhexlify(args.hmac_key)
        except:
            sys.stderr.write("Could not decode HMAC-SHA1 key. Please enter 40 hex-chars.\n")
            return 1
    else:
        hmac_key = os.urandom(20)

    print("To program a YubiKey >= 2.2 for challenge-response with this key, use :")
    print("")
    print("  $ ykpersonalize -%i -ochal-resp -ochal-hmac -ohmac-lt64 -a %s" % (args.slot, binascii.hexlify(hmac_key).decode('ascii')))
    print("")

    secret = {
        "count": 0,
        "nonce": binascii.hexlify(os.urandom(20)).decode('ascii'),
        "phrase": PHRASE
        }

    s = {
        'encryption': 'AES-CBC',
        'slot': args.slot,
        'type': 'HMAC-SHA1'
        }

    roll_next_challenge(s, hmac_key, secret)
    state[args.name] = s
    write_state_file(args.filename, state)

def do_exec(args):
    state = load_state_file(args.filename)
    while True:
        try:
            yk = yubico.find_yubikey(debug=args.debug)

            for k in state.keys():
                if state[k]['type'] != 'HMAC-SHA1':
                    logging.debug("Unknown type '%s' for '%s'" % (state[k]['type'], k))
                    continue

                if state[k]['encryption'] != 'AES-CBC':
                    logging.debug("Unknown encryption '%s' for '%s'" % (state[k]['encryption'], k))
                    continue

                if do_challenge(yk, state[k]):
                    logging.info("Authenticated with key '%s'" % k)
                    write_state_file(args.filename, state)
                    os.execvp(args.command[0], args.command)
                    logging.error("Exec Error!")
                    return 1

        except Exception as e:
            logging.info("Error finding yubikey: %s" % str(e))

        time.sleep(1)

def main():
    parser = argparse.ArgumentParser(description="Launch with yubikey")
    parser.add_argument('--debug', action='store_true', help='Show debug messages')
    parser.add_argument('--filename', '-F', help='State filename', default='state.json')
    parser.add_argument('--verbose', '-v', action='count', default=0, help='Verbose output')

    subparsers = parser.add_subparsers(title='subcommand', description='Subcommands')
    addkey_parser = subparsers.add_parser('add-key', help='Add a new key')
    addkey_parser.add_argument('name', help='Key name')
    addkey_parser.add_argument('--slot', type=int, default=2, choices=(1, 2),
                               help='Yubikey slot')
    addkey_parser.add_argument('--hmac-key', help='Use existing HMAC Key')
    addkey_parser.set_defaults(func=do_addkey)

    exec_parser = subparsers.add_parser('exec', help='Execute command after challenge response')
    exec_parser.add_argument('command', nargs='+', help='Command to execute')
    exec_parser.set_defaults(func=do_exec)

    args = parser.parse_args()

    if args.verbose == 0:
        logging.basicConfig(level=logging.WARNING)
    elif args.verbose == 1:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.DEBUG)

    args.func(args)

    return 0

if __name__ == "__main__":
    sys.exit(main())
