// Copyright © 2017-2019 Luis Ángel Méndez Gort

// This file is part of PMProxy.

// PMProxy is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General
// Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your
// option) any later version.

// PMProxy is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Affero General Public
// License for more details.

// You should have received a copy of the GNU Affero General
// Public License along with PMProxy.  If not, see
// <https://www.gnu.org/licenses/>.

// TODO the contents of this file are a version of
// github.com/aerogo/certificate, which is under a
// permissive license, but I don't know if his copyright
// should be kept

package pmproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/spf13/afero"
	"math/big"
	"net"
	"time"
)

// generate self-signed certificate for host
func genCert(host, srvKeyFl, srvCertFl string,
	fls afero.Fs) (e error) {
	validFor := 365 * 24 * time.Hour
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1),
		128)
	var serialNumber *big.Int
	var rootKey, serverKey *ecdsa.PrivateKey
	var certBytes []byte
	fs := []func(){
		func() {
			serialNumber, e = rand.Int(rand.Reader,
				serialNumberLimit)
		},
		func() {
			// Generate Root CA key
			rootKey, e = ecdsa.GenerateKey(elliptic.P256(),
				rand.Reader)
		},
		func() {
			// Generate server key
			serverKey, e = ecdsa.GenerateKey(elliptic.P256(),
				rand.Reader)
		},
		func() {
			// Generate server certificate
			e = keyToFile(srvKeyFl, serverKey, fls)
		},
		func() {
			serialNumber, e = rand.Int(rand.Reader,
				serialNumberLimit)
		},
		func() {
			serverTemplate := &x509.Certificate{
				SerialNumber: serialNumber,
				Subject: pkix.Name{
					Organization: []string{"Acme Co"},
					CommonName:   "Localhost Certificate",
				},
				NotBefore: notBefore,
				NotAfter:  notAfter,
				KeyUsage: x509.KeyUsageDigitalSignature |
					x509.KeyUsageKeyEncipherment,
				ExtKeyUsage: []x509.ExtKeyUsage{
					x509.ExtKeyUsageServerAuth,
				},
				BasicConstraintsValid: true,
				IsCA:                  false,
			}
			ip := net.ParseIP(host)

			if ip != nil {
				serverTemplate.IPAddresses = append(
					serverTemplate.IPAddresses, ip)
			} else {
				serverTemplate.DNSNames = append(
					serverTemplate.DNSNames, host)
			}

			rootTemplate := &x509.Certificate{
				SerialNumber: serialNumber,
				Subject: pkix.Name{
					Organization: []string{"Acme Co"},
					CommonName:   "Root CA",
				},
				NotBefore: notBefore,
				NotAfter:  notAfter,
				KeyUsage:  x509.KeyUsageCertSign,
				ExtKeyUsage: []x509.ExtKeyUsage{
					x509.ExtKeyUsageServerAuth,
				},
				BasicConstraintsValid: true,
				IsCA:                  true,
			}
			certBytes, e = x509.CreateCertificate(rand.Reader,
				serverTemplate, rootTemplate,
				&serverKey.PublicKey, rootKey)
		},
		func() {
			e = certToFile(srvCertFl, certBytes, fls)
		},
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

// certToFile writes a PEM serialization of |certBytes|
// to a new file called |fileName|.
func certToFile(fileName string,
	certBytes []byte, fls afero.Fs) (e error) {
	var file afero.File
	fs := []func(){
		func() { file, e = fls.Create(fileName) },
		func() {
			e = pem.Encode(file, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certBytes,
			})
		},
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

// keyToFile writes a PEM serialization of |key| to a new
// file called |fileName|.
func keyToFile(fileName string,
	key *ecdsa.PrivateKey, fls afero.Fs) (e error) {
	var file afero.File
	var bs []byte
	fs := []func(){
		func() { file, e = fls.Create(fileName) },
		func() {
			bs, e = x509.MarshalECPrivateKey(key)
		},
		func() {
			e = pem.Encode(file, &pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: bs,
			})
		},
	}
	trueFF(fs, func() bool { return e == nil })
	if file != nil {
		file.Close()
	}
	return
}
