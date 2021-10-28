CERTT
------

Decrypt and validate covid certificates.

### Get Started

Activate the virtual environment:

```source venv/bin/activate```

The script is added as an entry point, so it can be called directly via 'certt':

```certt --help```


#### Basic Usage

Call the base script with the path of an image file containing the qr code to read and validate a certificate:

```certt data/test-certificates/cert_theodor_truffer.jpg```

#### Test Certificates

Without any additional information, the script will validate the certificate with a list of trusted keys downloaded from 
the swiss admin site. If you want to test a code that is signed with a test certificate, add the certificate file with the -c parameter:

```certt data/test-certificates/qr_01.png -c data/test-certificates/qr_01.pem```

#### Rules

This script checks the certificates against a configured set of rules. The default rule set is at data/rules_ch.json.
To use a different set of rules, pass a json file containing the rules via the --rules/-r parameter:

```certt data/test-certificates/cert_theodor_truffer.jpg -r data/rules_way_too_strict.json```

The json file must have a specific structure:
* rules for vaccinations must be under the key "v"
* rules for tests must be under the key "t"
* every rule must have a "days" entry, which is an integer defining the duration of validity
* the duration will only be checked, if the rules inside the "if" set is true
  * the "if" set is check like this: 'if certificate_data\[key] == value'
  * the "if"s are connected by logical AND
* if the "if" set is true and the duration is not yet over, the certificate is valid
* if the "if" set is true and the duration is over, the certificate is invalid

