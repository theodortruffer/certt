import json
import re
import re
import sys
import zlib
from datetime import datetime
from io import TextIOWrapper

import PIL.Image
import base45
import cbor2
import click
import pyzbar.pyzbar
from cose.messages import CoseMessage
from cwt import load_pem_hcert_dsc, cwt

from bcolors import bcolors
from utilities import verify_signature, print_certificate


@click.command()
@click.argument('qr_file', type=click.Path(True))
@click.option('-c', '--certificate', type=click.File('r'))
@click.option('-r', '--rules', type=click.File('r'), default='./data/rules_ch.json')
def cli(qr_file: str, certificate: TextIOWrapper, rules: TextIOWrapper):
    """QR_FILE: path of an image file containing a qr code for a covid certificate"""
    with PIL.Image.open(qr_file) as image:
        image_decoded = pyzbar.pyzbar.decode(image)
        if len(image_decoded) < 1:
            print(bcolors.FAIL + "no qr code found in image" + bcolors.ENDC)
            exit(1)

        raw = image_decoded[0].data.decode()
        b45encoded = re.sub(r'^(HC1:|LT:)', '', raw)
        zlibcompressed = base45.b45decode(b45encoded)
        decompressed = zlib.decompress(zlibcompressed)
        cose_msg = CoseMessage.decode(decompressed)

        if certificate:
            print("verifying signature with given certificate..")
            public_key = load_pem_hcert_dsc(
                f'-----BEGIN CERTIFICATE-----\n{certificate.read()}\n-----END CERTIFICATE-----')
            certificate_payload = cwt.decode(decompressed, keys=[public_key], no_verify=True)
        else:
            print("verifying signature with trusted keys..")
            verify_signature(cose_msg)
            certificate_payload = cbor2.loads(cose_msg.payload)
            # print("Certificate Data: {0}".format(json.dumps(cbor, indent=2, default=str, ensure_ascii=False)))

    print(bcolors.OKGREEN + "Verification of signature successfull" + bcolors.ENDC)
    print()

    sig_expiration = datetime.fromtimestamp(certificate_payload[4])
    sig_issued_at = datetime.fromtimestamp(certificate_payload[6])
    print(bcolors.BOLD + 'General Data:' + bcolors.ENDC)
    print('Issued At: ' + sig_issued_at.strftime('%Y-%m-%d, %H:%M:%S'))
    print('Signature Expires: ' + sig_expiration.strftime('%Y-%m-%d, %H:%M:%S'))
    for key, cert in certificate_payload[-260].items():
        print('Name: ' + cert['nam']['gn'] + ' ' + cert['nam']['fn'])
        print('Date of Birth: ' + cert['dob'])
        for k in ['v', 'r', 't']:
            if k in cert:
                for data in cert[k]:
                    print_certificate(json.load(rules), k, data)



if __name__ == '__main__':
    cli(sys.argv[1:])
