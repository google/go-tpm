// Copyright (c) 2014, Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package tpm2 supports direct communication with a tpm 2.0 device under Linux.

package tpm2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
)

func GetPublicKeyFromDerCert(derCert []byte) (*rsa.PublicKey, error) {
	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		return nil, err
	}

	var publicKey *rsa.PublicKey
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		publicKey = k
	case *rsa.PrivateKey:
		publicKey = &k.PublicKey
	default:
		return nil, errors.New("Wrong public key type")
	}
	return publicKey, nil
}

func GenerateSelfSignedCertFromKey(signingKey *rsa.PrivateKey, subjectOrgName string,
	subjectCommonName string, serialNumber *big.Int,
	notBefore time.Time, notAfter time.Time) ([]byte, error) {
	signTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{subjectOrgName},
			CommonName:   subjectCommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
	}
	publicKey := &signingKey.PublicKey
	derCert, err := x509.CreateCertificate(rand.Reader, &signTemplate, &signTemplate,
		publicKey, signingKey)
	if err != nil {
		return nil, errors.New("Can't CreateCertificate")
	}
	return derCert, nil
}

func GenerateCertFromKeys(signingKey *rsa.PrivateKey, signerDerPolicyCert []byte,
	subjectKey *rsa.PublicKey, subjectOrgName string, subjectCommonName string,
	serialNumber *big.Int, notBefore time.Time, notAfter time.Time) ([]byte, error) {
	signingCert, err := x509.ParseCertificate(signerDerPolicyCert)
	if err != nil {
		return nil, errors.New("Can't parse signer certificate")
	}

	// fmt.Printf("Serial: %x\n", serialNumber)
	// fmt.Printf("notBefore: %s, notAfter: %s\n", notBefore, notAfter)
	signTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{subjectOrgName},
			CommonName:   subjectCommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// IsCA: false,
		IsCA: true,
	}
	derSignedCert, err := x509.CreateCertificate(rand.Reader, &signTemplate, signingCert,
		subjectKey, signingKey)
	if err != nil {
		glog.Infof("GenerateCertFromKeys: %s", err)
		fmt.Printf("%s\n", err)
		return nil, errors.New("Can't CreateCertificate")
	}
	return derSignedCert, nil
}

func SerializeRsaPrivateKey(key *rsa.PrivateKey) ([]byte, error) {
	msg, err := MarshalRsaPrivateToProto(key)
	if err != nil {
		return nil, errors.New("Can't marshall private key")
	}
	out, err := proto.Marshal(msg)
	if err != nil {
		return nil, errors.New("Can't serialize private key")
	}
	return out, nil
}

func DeserializeRsaKey(in []byte) (*rsa.PrivateKey, error) {
	msg := new(RsaPrivateKeyMessage)
	err := proto.Unmarshal(in, msg)
	key, err := UnmarshalRsaPrivateFromProto(msg)
	if err != nil {
		return nil, errors.New("Can't Unmarshal private key")
	}
	return key, nil
}

func PublicKeyFromPrivate(priv interface{}) *rsa.PublicKey {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func KDFA(alg uint16, key []byte, label string, contextU []byte,
	contextV []byte, bits int) ([]byte, error) {
	counter := uint32(0)
	bytes_left := (bits + 7) / 8
	var out []byte
	for bytes_left > 0 {
		counter = counter + 1
		if alg == AlgTPM_ALG_SHA1 {
			mac := hmac.New(sha1.New, key)
			// copy counter (big Endian), label, contextU, contextV, bits (big Endian)
			outa, _ := pack([]interface{}{&counter})
			var arr [32]byte
			copy(arr[0:], label)
			arr[len(label)] = 0
			outc := append(contextU, contextV...)
			u_bits := uint32(bits)
			outd, _ := pack([]interface{}{&u_bits})
			in := append(outa, append(arr[0:len(label)+1], append(outc, outd...)...)...)
			mac.Write(in)
			out = append(out, mac.Sum(nil)...)
			bytes_left -= 20
		} else if alg == AlgTPM_ALG_SHA256 {
			mac := hmac.New(sha256.New, key)
			// copy counter (big Endian), label, contextU, contextV, bits (big Endian)
			outa, _ := pack([]interface{}{&counter})
			var arr [32]byte
			copy(arr[0:], label)
			arr[len(label)] = 0
			outc := append(contextU, contextV...)
			u_bits := uint32(bits)
			outd, _ := pack([]interface{}{&u_bits})
			in := append(outa, append(arr[0:len(label)+1],
				append(outc, outd...)...)...)
			mac.Write(in)
			out = append(out, mac.Sum(nil)...)
			bytes_left -= 32
		} else {
			return nil, errors.New("Unsupported key hmac alg")
		}
	}
	return out, nil
}

//	Return: out_hmac, output_data
func EncryptDataWithCredential(encrypt_flag bool, hash_alg_id uint16,
	unmarshaled_credential []byte, inData []byte,
	inHmac []byte) ([]byte, []byte, error) {
	var contextV []byte
	derivedKeys, err := KDFA(hash_alg_id, unmarshaled_credential,
		"PROTECT", contextV, contextV, 512)
	if err != nil {
		fmt.Printf("EncryptDataWithCredential can't derive keys\n")
		glog.Infof("EncryptDataWithCredential: can't derive keys")
		return nil, nil, errors.New("KDFA failed")
	}
	var calculatedHmac []byte
	outData := make([]byte, len(inData), len(inData))
	iv := derivedKeys[16:32]
	key := derivedKeys[0:16]
	dec, err := aes.NewCipher(key)
	ctr := cipher.NewCTR(dec, iv)
	ctr.XORKeyStream(outData, inData)

	var toHash []byte
	if encrypt_flag == true {
		toHash = inData
	} else {
		toHash = outData
	}
	// Calculate hmac on output data
	if hash_alg_id == AlgTPM_ALG_SHA1 {
		hm := hmac.New(sha1.New, derivedKeys[48:64])
		hm.Write(toHash)
		calculatedHmac = hm.Sum(nil)
	} else if hash_alg_id == AlgTPM_ALG_SHA256 {
		hm := hmac.New(sha256.New, derivedKeys[32:64])
		hm.Write(toHash)
		calculatedHmac = hm.Sum(nil)
	} else {
		fmt.Printf("EncryptDataWithCredential unrecognized hmac alg\n")
		glog.Infof("EncryptDataWithCredential: unrecognized hmac alg")
		return nil, nil, errors.New("Unsupported Hash alg")
	}

	if encrypt_flag == false {
		if bytes.Compare(calculatedHmac, inHmac) != 0 {
			return nil, nil, errors.New("Integrity check fails")
		}
	}

	return calculatedHmac, outData, nil
}

func StringToIntList(in string) ([]int, error) {
	strList := strings.Split(in, ",")
	ints := make([]int, len(strList))
	for i, s := range strList {
		var err error
		ints[i], err = strconv.Atoi(strings.TrimPrefix(s, " "))
		if err != nil {
			return nil, errors.New("Can't convert strings to ints")
		}
	}
	return ints, nil
}

func ComputeHashValue(alg uint16, to_hash []byte) ([]byte, error) {
	if alg == uint16(AlgTPM_ALG_SHA1) {
		hash := sha1.New()
		hash.Write(to_hash)
		hash_value := hash.Sum(nil)
		return hash_value, nil
	} else if alg == uint16(AlgTPM_ALG_SHA256) {
		hash := sha256.New()
		hash.Write(to_hash)
		hash_value := hash.Sum(nil)
		return hash_value, nil
	} else {
		return nil, errors.New("unsupported hash alg")
	}
}

func SizeHash(alg_id uint16) int {
	if alg_id == uint16(AlgTPM_ALG_SHA1) {
		return 20
	} else if alg_id == uint16(AlgTPM_ALG_SHA256) {
		return 32
	} else {
		return -1
	}
}

func VerifyDerCert(der_cert []byte, der_signing_cert []byte) (bool, error) {
	roots := x509.NewCertPool()
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	// Verify key
	policy_cert, err := x509.ParseCertificate(der_signing_cert)
	if err != nil {
		return false, errors.New("Signing ParseCertificate fails")
	}
	roots.AddCert(policy_cert)
	// fmt.Printf("Root cert: %x\n", der_signing_cert)

	// Verify key
	cert, err := x509.ParseCertificate(der_cert)
	if err != nil {
		return false, errors.New("Cert ParseCertificate fails")
	}

	roots.AddCert(policy_cert)
	opts.Roots = roots
	chains, err := cert.Verify(opts)
	if err != nil {
		return false, errors.New("Verify fails")
	}
	if chains != nil {
		return true, nil
	} else {
		return false, nil
	}

}

func MarshalRsaPrivateToProto(key *rsa.PrivateKey) (*RsaPrivateKeyMessage, error) {
	if key == nil {
		return nil, errors.New("No key")
	}
	msg := new(RsaPrivateKeyMessage)
	msg.PublicKey = new(RsaPublicKeyMessage)
	msg.D = key.D.Bytes()
	msg.PublicKey.Exponent = []byte{0, 1, 0, 1}
	msg.PublicKey.Modulus = key.N.Bytes()
	l := int32(len(msg.PublicKey.Modulus) * 8)
	msg.PublicKey.BitModulusSize = &l
	// if len(key.Primes == 2 {
	// 	msg.PublicKey.P = msg.Primes[0].Bytes()
	// 	msg.PublicKey.Q = msg.Primes[1].Bytes()
	// }
	return msg, nil
}

func UnmarshalRsaPrivateFromProto(msg *RsaPrivateKeyMessage) (*rsa.PrivateKey, error) {
	if msg == nil {
		return nil, errors.New("No message")
	}
	key := new(rsa.PrivateKey)
	key.D = new(big.Int)
	key.D.SetBytes(msg.D)
	key.PublicKey.N = new(big.Int)
	key.PublicKey.N.SetBytes(msg.PublicKey.Modulus)
	key.PublicKey.E = 0x10001 // Fix
	// if msg.PublicKey.P != nil && msg.PublicKey.Q != nil {
	// 	msg.Primes[0] = new(big.Int)
	// 	msg.Primes[1] = new(big.Int)
	// 	msg.Primes[0].SetBytes(msg.PublicKey.P)
	// 	msg.Primes[1].SetBytes(msg.PublicKey.Q)
	// }
	return key, nil
}
