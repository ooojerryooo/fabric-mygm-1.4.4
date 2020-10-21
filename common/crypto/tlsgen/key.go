/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tlsgen

import (
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	ecdsa "github.com/tjfoc/gmsm/sm2"
	"math/big"
	"net"
	"time"
)

func (p *CertKeyPair) PrivKeyString() string {
	return base64.StdEncoding.EncodeToString(p.Key)
}

func (p *CertKeyPair) PubKeyString() string {
	return base64.StdEncoding.EncodeToString(p.Cert)
}

func newPrivKey() (*ecdsa.PrivateKey, []byte, error) {
	privateKey, err := ecdsa.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := ecdsa.MarshalSm2UnecryptedPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, privBytes, nil
}

func newCertTemplate() (ecdsa.Certificate, error) {
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return ecdsa.Certificate{}, err
	}
	return ecdsa.Certificate{
		Subject:      pkix.Name{SerialNumber: sn.String()},
		NotBefore:    time.Now().Add(time.Hour * (-24)),
		NotAfter:     time.Now().Add(time.Hour * 24),
		KeyUsage:     ecdsa.KeyUsageKeyEncipherment | ecdsa.KeyUsageDigitalSignature,
		SerialNumber: sn,
	}, nil
}

func newCertKeyPair(isCA bool, isServer bool, host string, certSigner crypto.Signer, parent *ecdsa.Certificate) (*CertKeyPair, error) {
	privateKey, privBytes, err := newPrivKey()
	if err != nil {
		return nil, err
	}

	template, err := newCertTemplate()
	if err != nil {
		return nil, err
	}

	tenYearsFromNow := time.Now().Add(time.Hour * 24 * 365 * 10)
	if isCA {
		template.NotAfter = tenYearsFromNow
		template.IsCA = true
		template.KeyUsage |= ecdsa.KeyUsageCertSign | ecdsa.KeyUsageCRLSign
		template.ExtKeyUsage = []ecdsa.ExtKeyUsage{ecdsa.ExtKeyUsageAny}
		template.BasicConstraintsValid = true
	} else {
		template.ExtKeyUsage = []ecdsa.ExtKeyUsage{ecdsa.ExtKeyUsageClientAuth}
	}
	if isServer {
		template.NotAfter = tenYearsFromNow
		template.ExtKeyUsage = append(template.ExtKeyUsage, ecdsa.ExtKeyUsageServerAuth)
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	// If no parent cert, it's a self signed cert
	if parent == nil || certSigner == nil {
		parent = &template
		certSigner = privateKey
	}
	rawBytes, err := ecdsa.CreateCertificate(rand.Reader, &template, parent, &privateKey.PublicKey, certSigner)
	if err != nil {
		return nil, err
	}
	pubKey := encodePEM("CERTIFICATE", rawBytes)

	block, _ := pem.Decode(pubKey)
	cert, err := ecdsa.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	privKey := encodePEM("EC PRIVATE KEY", privBytes)
	return &CertKeyPair{
		Key:     privKey,
		Cert:    pubKey,
		Signer:  privateKey,
		TLSCert: cert,
	}, nil
}

func encodePEM(keyType string, data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: data})
}

// CertKeyPairFromString converts the given strings in base64 encoding to a CertKeyPair
func CertKeyPairFromString(privKey string, pubKey string) (*CertKeyPair, error) {
	priv, err := base64.StdEncoding.DecodeString(privKey)
	if err != nil {
		return nil, err
	}
	pub, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		return nil, err
	}
	return &CertKeyPair{
		Key:  priv,
		Cert: pub,
	}, nil
}
