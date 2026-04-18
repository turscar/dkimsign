package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	flag "github.com/spf13/pflag"
)

var signHeaderKeys = []string{
	"From",
	"Reply-To",
	"Subject",
	"Date",
	"To",
	"Cc",
	"Resent-Date",
	"Resent-From",
	"Resent-To",
	"Resent-Cc",
	"In-Reply-To",
	"References",
	"List-Id",
	"List-Help",
	"List-Unsubscribe",
	"List-Unsubscribe-Post",
	"List-Subscribe",
	"List-Post",
	"List-Owner",
	"List-Archive",
}

func main() {
	var keyFile string
	var domain string
	var selector string
	var mailFile string
	var outFile string
	var canonicalization string
	var headers []string
	var silent bool
	flag.StringVar(&keyFile, "key", "", "Filename of private key")
	flag.StringVar(&domain, "domain", "", "DKIM d= to sign")
	flag.StringVar(&selector, "selector", "", "DKIM selector")
	flag.StringVar(&mailFile, "mail", "", "Mail file to be signed")
	flag.StringVar(&outFile, "out", "", "Write signed mail to file")
	flag.StringVar(&canonicalization, "canon", "relaxed/simple", "Canonicalization method header/body")
	flag.StringSliceVar(&headers, "headers", signHeaderKeys, "Headers to sign")
	flag.BoolVar(&silent, "silent", false, "Silent mode")
	flag.Parse()

	if domain == "" {
		log.Fatal("--domain is required")
	}
	if selector == "" {
		log.Fatal("--selector is required")
	}
	if keyFile == "" {
		log.Fatal("--key is required")
	}

	var headerCanon, bodyCanon string

	parts := strings.Split(canonicalization, "/")
	switch len(parts) {
	case 1:
		headerCanon = parts[0]
		bodyCanon = parts[0]
	case 2:
		headerCanon = parts[0]
		bodyCanon = parts[1]
	default:
		log.Fatal("--canonical value should have no more than one slash")
	}

	var inF io.Reader
	var outF io.Writer
	var err error
	switch mailFile {
	case "", "-":
		inF = os.Stdin
	default:
		f, err := os.Open(mailFile)
		if err != nil {
			log.Fatal(err)
		}
		defer func(f *os.File) {
			_ = f.Close()
		}(f)
		inF = f
	}

	switch outFile {
	case "", "-":
		outF = os.Stdout
	default:
		f, err := os.Create(outFile)
		if err != nil {
			log.Fatal(err)
		}
		defer func(f *os.File) {
			_ = f.Close()
		}(f)
		outF = f
	}

	privateKey, err := loadPrivateKey(keyFile)
	if err != nil {
		log.Fatal(err)
	}
	opts := &dkim.SignOptions{
		Domain:                 domain,
		Selector:               selector,
		Identifier:             "",
		Signer:                 privateKey,
		Hash:                   0,
		HeaderCanonicalization: parseCanon(headerCanon),
		BodyCanonicalization:   parseCanon(bodyCanon),
		HeaderKeys:             nil,
		Expiration:             time.Time{},
		QueryMethods:           nil,
	}
	err = dkim.Sign(outF, inF, opts)
	if err != nil {
		log.Fatal(err)
	}
	if !silent {
		printPubKey(selector, domain, privateKey.Public())
	}
}

func loadPrivateKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found")
	}

	switch strings.ToUpper(block.Type) {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return k.(crypto.Signer), nil
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EDDSA PRIVATE KEY":
		if len(block.Bytes) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid Ed25519 private key size")
		}
		return ed25519.PrivateKey(block.Bytes), nil
	default:
		return nil, fmt.Errorf("unknown private key type: '%v'", block.Type)
	}
}

func parseCanon(c string) dkim.Canonicalization {
	switch c {
	case "simple":
		return dkim.CanonicalizationSimple
	case "relaxed":
		return dkim.CanonicalizationRelaxed
	default:
		log.Fatalf("unknown canonicalization format: '%v'", c)
	}
	return dkim.CanonicalizationSimple
}

func printPubKey(selector, domain string, pubKey crypto.PublicKey) {
	var pubBytes []byte
	var keyType string
	const chunkSize = 200
	switch pubKey := pubKey.(type) {
	case *rsa.PublicKey:
		// RFC 6376 is inconsistent about whether RSA public keys should
		// be formatted as RSAPublicKey or SubjectPublicKeyInfo.
		// Erratum 3017 (https://www.rfc-editor.org/errata/eid3017)
		// proposes allowing both.  We use SubjectPublicKeyInfo for
		// consistency with other implementations including opendkim,
		// Gmail, and Fastmail.
		var err error
		pubBytes, err = x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			log.Fatalf("Failed to marshal public key: %v", err)
		}
		keyType = "rsa"
	case ed25519.PublicKey:
		pubBytes = pubKey
		keyType = "ed25519"
	default:
		panic("unreachable")
	}

	params := []string{
		"v=DKIM1",
		"k=" + keyType,
		"p=" + base64.StdEncoding.EncodeToString(pubBytes),
	}

	var builder strings.Builder
	_, _ = fmt.Fprintf(&builder, "%s._domainkey.%s 3600 IN TXT", selector, domain)

	record := strings.Join(params, "; ")
	for len(record) > chunkSize {
		_, _ = fmt.Fprintf(&builder, " %q", record[:chunkSize])
		record = record[chunkSize:]
	}
	if len(record) > 0 {
		_, _ = fmt.Fprintf(&builder, " %q", record)
	}

	_, _ = fmt.Fprintln(os.Stderr, builder.String())
}
