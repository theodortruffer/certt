import base64
import json
import math
from datetime import datetime, timedelta
from io import TextIOWrapper
from typing import Dict, Union, List

import cose.algorithms
import cryptography.x509 as x509
import jwt
import requests
from cose.headers import KID
from cose.keys import cosekey, keyparam, keyops, keytype
from cose.messages.cosemessage import CM
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.x509 import Certificate
from cwt.cose_key_interface import COSEKeyInterface

from bcolors import bcolors

KEY_FILE = "./data/trusted_keys.json"
ROOT_CERT_URL = "https://www.bit.admin.ch/dam/bit/en/dokumente/pki/scanning_center/swiss_governmentrootcaii.crt.download.crt/swiss_governmentrootcaii.crt"
ACTIVE_KEYS_URL = "https://www.cc.bit.admin.ch/trust/v1/keys/list"
KEY_LIST_URL = "https://www.cc.bit.admin.ch/trust/v1/keys/updates?certFormat=ANDROID"

ECDSA_ALGORITHMS = [
    cose.algorithms.Es256,
    cose.algorithms.Es384,
    cose.algorithms.Es512
]

RSASSA_PSS_ALGORITHMS = [
    cose.algorithms.Ps256,
    cose.algorithms.Ps384,
    cose.algorithms.Ps512
]

TEST_RESULT_MAPPING = {
    '260415000': f'{bcolors.OKGREEN}Not Detected{bcolors.ENDC}',
    '260373001': f'{bcolors.WARNING}Detected{bcolors.ENDC}'
}

headers = {
    'Accept': 'application/json+jws',
    'Accept-Encoding': 'gzip',
    'Authorization': 'Bearer 0795dc8b-d8d0-4313-abf2-510b12d50939',
    'User-Agent': 'ch.admin.bag.covidcertificate.wallet;2.1.1;1626211804080;Android;28'
}


def __num2b64(n: int) -> str:
    size = math.ceil(math.ceil(math.log(n, 2)) / 8)
    return base64.b64encode(n.to_bytes(size, 'big')).decode()


def __verify_jwt(token: str, root_cert: Certificate) -> None:
    header = jwt.get_unverified_header(token)
    certs = [base64.b64decode(k) for k in header['x5c']]
    cert_chain = [x509.load_der_x509_certificate(der) for der in certs]
    cert_chain.append(root_cert)
    padding = PKCS1v15()
    for i in range(len(cert_chain) - 1):
        signed, issuer = cert_chain[i:i + 2]
        issuer.public_key().verify(signed.signature,
                                   signed.tbs_certificate_bytes,
                                   padding,
                                   signed.signature_hash_algorithm)


def __load_trusted_keys() -> None:
    print("downloading trusted keys..")
    root_cert = x509.load_pem_x509_certificate(requests.get(ROOT_CERT_URL).text.encode())
    # fetch jwts
    active_keys_jwt = requests.get(ACTIVE_KEYS_URL, headers=headers).text
    key_list_jwt = requests.get(KEY_LIST_URL, headers=headers).text
    # verify signatures
    __verify_jwt(active_keys_jwt, root_cert)
    __verify_jwt(key_list_jwt, root_cert)
    # decode
    active_keys = jwt.decode(active_keys_jwt, options={"verify_signature": False})['activeKeyIds']
    key_list = jwt.decode(key_list_jwt, options={"verify_signature": False})['certs']

    keys = {}
    for key_data in key_list:
        # filter out inactive keys
        if key_data['keyId'] in active_keys:
            key_id = key_data.pop('keyId')
            keys[key_id] = key_data

    with open(KEY_FILE, 'w') as key_file:
        json.dump(keys, key_file, indent=2)


def get_trusted_keys(skip_download: bool = False) -> Dict[str, dict]:
    if not skip_download:
        try:
            __load_trusted_keys()
        except BaseException as e:
            print(f"ERROR: trusted keys could not be downloaded: {bcolors.FAIL}{e=} {type(e)=} {bcolors.ENDC}")
            use_file = input(f"{bcolors.UNDERLINE}Use trusted keys from local file?{bcolors.ENDC} (y/N)")
            if use_file.lower() != 'y':
                exit(1)

    with open(KEY_FILE, 'r') as key_file:
        return json.load(key_file)


def get_kid(cose_msg: CM) -> Union[bytes, None]:
    kid = cose_msg.phdr.get(KID)
    if not kid:
        kid = cose_msg.uhdr.get(KID)
        print("kid found in unprotected header")
        if not kid:
            print("no kid found")
    else:
        print("kid found in protected header")
    return kid


def build_cose_key(algorithm: cose.headers.Algorithm, kid: bytes, data: dict) -> cosekey:
    if algorithm in ECDSA_ALGORITHMS:
        print("using primary algorithm..")
        return cosekey.CoseKey.from_dict({
            keyparam.KpKeyOps: [keyops.VerifyOp],
            keyparam.KpKty: keytype.KtyEC2,
            keyparam.EC2KpCurve: data['crv'],
            keyparam.KpAlg: algorithm,
            keyparam.EC2KpX: base64.b64decode(data['x']),
            keyparam.EC2KpY: base64.b64decode(data['y']),
            keyparam.KpKid: kid
        })
    elif algorithm in RSASSA_PSS_ALGORITHMS:
        print("using secondary algorithm..")
        return cosekey.CoseKey.from_dict({
            keyparam.KpKeyOps: [keyops.VerifyOp],
            keyparam.KpKty: keytype.KtyRSA,
            keyparam.KpAlg: algorithm,
            keyparam.RSAKpN: base64.b64decode(data['n']),
            keyparam.RSAKpE: base64.b64decode(data['e']),
            keyparam.KpKid: kid
        })
    else:
        print(bcolors.FAIL + "algorithm not supported: {0}".format(data['alg']) + bcolors.ENDC)
        exit(1)


def verify_signature(cose_msg: CM):
    public_keys = get_trusted_keys()
    algorithm = cose_msg.phdr.get(cose.headers.Algorithm)
    kid = get_kid(cose_msg)
    cose_key = None
    for key, data in public_keys.items():
        bkey = base64.b64decode(key)
        if bkey == kid:
            print("kid found in trusted keys")
            cose_key = build_cose_key(algorithm, bytes(bkey.hex(), "ASCII"), data)

    if cose_key is None:
        print(bcolors.FAIL + "key could not be found in trusted keys, cannot verify signature" + bcolors.ENDC)
        exit(1)
    cose_msg.key = cose_key
    if not cose_msg.verify_signature():
        print(bcolors.FAIL + "signature could not be verified" + bcolors.ENDC)
        exit(1)


def print_certificate(rules: dict, cert_type: str, data: dict) -> None:
    print()
    if cert_type == 'v':
        __print_vaccination(data, rules["v"])
    elif cert_type == 'r':
        __print_recovered(data)
    elif cert_type == 't':
        __print_test(data, rules["t"])
    else:
        print(f'{bcolors.FAIL}Unknown certificate type: {cert_type}')
        exit(1)


def __print_vaccination(data: dict, rules: List[Dict]) -> None:
    print(f'{bcolors.BOLD}Vaccination{bcolors.ENDC}')
    print(f'Medicinal Product: {data["mp"]}')
    print(f'Vaccine: {data["vp"]}')
    print(f'Dose Number: {data["dn"]}')
    print(f'Total Series of Doses: {data["sd"]}')
    print(f'Country of Vaccination: {data["co"]}')
    print(f'Issuer: {data["is"]}')
    print(f'Issued At: {data["dt"]}')

    checked_date = datetime.strptime(data["dt"], '%Y-%m-%d')
    check_against_rules(checked_date, data, rules)


def __print_recovered(data: dict) -> None:
    print(f'{bcolors.BOLD}Recovered{bcolors.ENDC}')
    print(f'Country of Test: {data["co"]}')
    print(f'Issuer: {data["is"]}')
    print(f'First positive Test Result: {data["fr"]}')
    print(f'Valid From: {data["df"]}')
    print(f'Valid Until: {data["du"]}')
    if datetime.strptime(data["du"], '%Y-%m-%d').timestamp() < datetime.now().timestamp():
        print(f'{bcolors.FAIL}Certificate invalid{bcolors.ENDC}')
    else:
        print(f'{bcolors.OKGREEN}Certificate valid{bcolors.ENDC}')


def __print_test(data: dict, rules: List[Dict]) -> None:
    print(f'{bcolors.BOLD}Test{bcolors.ENDC}')
    print(f'Type of Test: {data["tt"]}')
    print(f'Test Result: {TEST_RESULT_MAPPING[data["tr"]]}')
    print(f'Sample Collection: {data["sc"]}')
    print(f'Testing Center: {data["tc"]}')
    print(f'Country of Test: {data["co"]}')
    print(f'Issuer: {data["is"]}')
    checked_date = datetime.strptime(data["sc"], '%Y-%m-%dT%H:%M:%SZ')
    check_against_rules(checked_date, data, rules)



def check_against_rules(checked_date: datetime, data: dict, rules: List[dict]) -> None:
    for rule in rules:
        delta = timedelta(rule["days"])
        check = True
        for key, value in rule["if"].items():
            if data[key] != value:
                check = False
        if check and (checked_date + delta).timestamp() < datetime.now().timestamp():
            print(f'{bcolors.FAIL}Certificate invalid{bcolors.ENDC}')
        elif check:
            print(f'{bcolors.OKGREEN}Certificate valid{bcolors.ENDC}')

# def verify_signature(cose_msg: CM, public_key: COSEKeyInterface):
#     algorithm = cose_msg.phdr.get(cose.headers.Algorithm)
#     bkey = get_kid(cose_msg)
#     public_numbers = {}
#     for k, v in public_key._key.public_numbers().__dict__.items():
#         public_numbers[k[1:]] = v   # remove underscore
#     cose_key = build_cose_key(algorithm, bytes(bkey.hex(), "ASCII"), public_numbers)
#     cose_msg.key = cose_key
#     if not cose_msg.verify_signature():
#         print(bcolors.FAIL + "signature could not be verified" + bcolors.ENDC)
#         exit(1)
