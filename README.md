# dkimsign
CLI tool for ad-hoc DKIM signing

dkimsign is very thin wrapper around
[emersion/go-msgauth](https://github.com/emersion/go-msgauth)
allowing signing an email payload with an arbitrary
key and canonicalization options.

```
dkim-keygen -t rsa -b 3072 -f dkim-rsa-3072.priv
dkimsign --key=dkim-rsa-3072.priv --selector=banana --domain=blighty.com <test.eml >signed.eml
```

If the message is signed successfully the DNS
record for the public key is printed to stderr.

dkim-keygen and dkim-verify are utilities copied
from [emersion/go-msgauth](https://github.com/emersion/go-msgauth)
for key generation and signature validation, solely
to include binaries for download from this repo.

