// Copyright (c) 2014, Google, Inc..  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// File: tpm2_attest_protocol_support.go

package tpm2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"time"

	// "github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util"
)

// TODO(jlm): Remove Printf's.

func CreateTemporaryChannelKey() (*rsa.PrivateKey, []byte, error) {
	requestingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Self sign the cert
	notBefore := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	us := "US"
	issuerName := "RequestDomainQuoteCert"
	localhost := "localhost"
	x509SubjectName := &pkix.Name{
		Organization:       []string{issuerName},
		OrganizationalUnit: []string{issuerName},
		CommonName:         localhost,
		Country:            []string{us},
	}
	var sn big.Int
	certificateTemplate := x509.Certificate{
		SerialNumber: &sn,
		Issuer:       *x509SubjectName,
		Subject:      *x509SubjectName,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
	}

	channelCert, err := x509.CreateCertificate(rand.Reader, &certificateTemplate,
		&certificateTemplate, requestingKey,
		requestingKey)
	if err != nil {
		return nil, nil, errors.New("RequestDomainQuoteCert: Can't self sign tls cert")
	}
	return requestingKey, channelCert, nil
}

func BuildAttestCertRequest(tpmDevice io.ReadWriter, quoteHandle Handle, endorsementHandle Handle, endorsementCert []byte,
	taoName string, ownerPw string) (*AttestCertRequest, error) {

	// Get Quote key.
	tpm2QuoteKeyBlob, tpm2QuoteKeyName, _, err := ReadPublic(tpmDevice, quoteHandle)
	if err != nil {
		return nil, err
	}
	rsaQuoteParams, err := DecodeRsaBuf(tpm2QuoteKeyBlob)
	if err != nil {
		return nil, err
	}

	quoteKey := new(rsa.PublicKey)
	quoteKey.N = new(big.Int)
	quoteKey.N.SetBytes(rsaQuoteParams.Modulus)
	quoteKey.E = int(rsaQuoteParams.Exp)

	request := new(AttestCertRequest)

	// DER encoded subject key
	derSubjectKey, err := x509.MarshalPKIXPublicKey(quoteKey)
	if err != nil {
		return nil, err
	}

	var hashedQuoteKey []byte
	if rsaQuoteParams.Hash_alg == AlgTPM_ALG_SHA1 {
		sha1Str := "sha1"
		request.HashType = &sha1Str
		sha1Hash := sha1.New()
		sha1Hash.Write([]byte(derSubjectKey))
		hashedQuoteKey = sha1Hash.Sum(nil)
	} else if rsaQuoteParams.Hash_alg == AlgTPM_ALG_SHA256 {
		sha256Str := "sha256"
		request.HashType = &sha256Str
		sha256Hash := sha256.New()
		sha256Hash.Write([]byte(derSubjectKey))
		hashedQuoteKey = sha256Hash.Sum(nil)
	} else {
		return nil, errors.New("RequestDomainQuoteCert: Quote key has unknown cert type")
	}

	sigAlg := uint16(AlgTPM_ALG_NULL)
	tpm2AttestBlob, tpm2SigBlob, err := Quote(tpmDevice, quoteHandle, ownerPw, ownerPw,
		hashedQuoteKey, []int{17, 18}, sigAlg)
	if err != nil {
		return nil, err
	}

	request.AttestBlob = tpm2AttestBlob
	request.SigBlob = tpm2SigBlob
	request.KeyName = &taoName
	request.SubjectPublicKey = derSubjectKey
	request.DerEndorsementCert = endorsementCert
	if rsaQuoteParams.Enc_alg == AlgTPM_ALG_RSA {
		rsaStr := "rsa"
		request.KeyType = &rsaStr

	} else {
		return nil, errors.New("RequestDomainQuoteCert: Bad quote key type")
	}
	request.Tpm2KeyName = tpm2QuoteKeyName
	// TODO: request.CertChain
	return request, nil
}

func GetCertFromAttestResponse(tpmDevice io.ReadWriter, quoteHandle Handle, endorsementHandle Handle,
	password string, response AttestCertResponse) ([]byte, error) {
	// Decrypt cert
	certBlob := append(response.IntegrityHmac, response.EncIdentity...)
	certInfo, err := ActivateCredential(tpmDevice, quoteHandle, endorsementHandle,
		password, "", certBlob, response.EncryptedSecret)
	if err != nil {
		return nil, err
	}
	fmt.Printf("certInfo: %x\n", certInfo)

	// Decrypt cert.
	_, decryptedCert, err := EncryptDataWithCredential(false, uint16(AlgTPM_ALG_SHA1),
		certInfo, response.EncryptedCert, response.EncryptedCertHmac)
	if err != nil {
		return nil, err
	}
	return decryptedCert, nil
}

// RequestDomainQuoteCert requests the Quote Cert
func RequestDomainQuoteCert(network, addr string, endorsementCert []byte, tpmDevice io.ReadWriter,
	quoteHandle Handle, endorsementHandle Handle, taoName string,
	ownerPw string) ([]byte, error) {

	requestingKey, derChannelCert, err := CreateTemporaryChannelKey()
	if err != nil || requestingKey == nil {
		return nil, err
	}
	channelCert, err := x509.ParseCertificate(derChannelCert)
	if err != nil || channelCert == nil {
		return nil, err
	}

	// Contact domain service.
	conn, err := tls.Dial(network, addr, &tls.Config{
		RootCAs: x509.NewCertPool(),
		// Certificates:       []tls.Certificate{tls.Certificate(*channelCert)},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Build request.
	request, err := BuildAttestCertRequest(tpmDevice, quoteHandle, endorsementHandle, endorsementCert, taoName, ownerPw)
	if err != nil {
		return nil, err
	}

	// Send request
	ms := util.NewMessageStream(conn)
	_, err = ms.WriteMessage(request)
	if err != nil {
		return nil, err
	}

	// Read the new cert
	var response AttestCertResponse
	err = ms.ReadMessage(&response)
	if err != nil {
		return nil, err
	}

	return GetCertFromAttestResponse(tpmDevice, quoteHandle, endorsementHandle, ownerPw, response)
}

// This is the operation of the server. It computes the AttestResponse.
func ProcessQuoteDomainRequest(request AttestCertRequest, policyKey *ecdsa.PrivateKey, derPolicyCert []byte) (*AttestCertResponse, error) {

	if *request.KeyType != "rsa" {
		return nil, errors.New("HandleQuoteDomainRequest: Unsuported key algorithm")
	}
	if *request.HashType != "sha1" && *request.HashType != "sha256" {
		return nil, errors.New("HandleQuoteDomainRequest: Unsuported hash algorithm")
	}

	// Get Key information from der
	attestKey, err := x509.ParsePKIXPublicKey(request.SubjectPublicKey)
	if err != nil {
		return nil, err
	}

	// Sign certificate.
	notBefore := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	us := "US"
	issuerName := "Google"
	localhost := "localhost"
	x509SubjectName := &pkix.Name{
		Organization:       []string{*request.KeyName},
		OrganizationalUnit: []string{*request.KeyName},
		CommonName:         localhost,
		Country:            []string{us},
	}
	x509IssuerName := &pkix.Name{
		Organization:       []string{issuerName},
		OrganizationalUnit: []string{issuerName},
		CommonName:         localhost,
		Country:            []string{us},
	}

	// issuerName := tao.NewX509Name(&details)
	var sn big.Int
	certificateTemplate := x509.Certificate{
		SerialNumber: &sn,
		Issuer:       *x509IssuerName,
		Subject:      *x509SubjectName,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
	}

	policyCert, err := x509.ParseCertificate(derPolicyCert)
	if err != nil {
		return nil, err
	}

	attestCert, err := x509.CreateCertificate(rand.Reader, &certificateTemplate,
		policyCert, attestKey, policyKey)
	if err != nil {
		fmt.Printf("Can't create attest certificate: ", err, "\n")
		return nil, err
	}

	response := new(AttestCertResponse)
	// response.CertChain= append(request.CertChain, policyKey.Cert.Raw)

	// hash  and verify quotekey.
	var hashAlgId uint16
	var hashedQuoteKey []byte
	if *request.HashType == "sha256" {
		hashAlgId = uint16(AlgTPM_ALG_SHA256)
		sha256Hash := sha256.New()
		sha256Hash.Write([]byte(request.SubjectPublicKey))
		hashedQuoteKey = sha256Hash.Sum(nil)
	} else if *request.HashType == "sha1" {
		hashAlgId = uint16(AlgTPM_ALG_SHA1)
		sha1Hash := sha1.New()
		sha1Hash.Write([]byte(request.SubjectPublicKey))
		hashedQuoteKey = sha1Hash.Sum(nil)
	} else {
		return nil, errors.New("Unsuported hash algorithm")
	}
	if len(hashedQuoteKey) < 10 {
	}

	subjectKey, err := x509.ParsePKIXPublicKey(request.SubjectPublicKey)
	if err != nil {
		return nil, err
	}
	rsaQuoteKey := subjectKey.(*rsa.PublicKey)
	if !VerifyRsaQuote(hashedQuoteKey, rsaQuoteKey,
		hashAlgId, request.AttestBlob, request.SigBlob, ValidPcr) {
		return nil, errors.New("Can't verify quote")
	}

	// Get Endorsement blob
	endorsement_cert, err := x509.ParseCertificate(request.DerEndorsementCert)
	if err != nil {
		return nil, err
	}

	// Verify Endorsement Cert
	ok, err := VerifyDerCert(request.DerEndorsementCert, derPolicyCert)
	if !ok {
		return nil, errors.New("Bad endorsement cert")
	}
	var protectorPublic *rsa.PublicKey
	switch k := endorsement_cert.PublicKey.(type) {
	case *rsa.PublicKey:
		protectorPublic = k
	case *rsa.PrivateKey:
		protectorPublic = &k.PublicKey
	default:
		return nil, errors.New("endorsement cert not an rsa key")
	}

	// Generate credential
	var credential [16]byte
	rand.Read(credential[0:16])
	fmt.Printf("Credential: %x, hashid: %x\n", credential, hashAlgId)
	encrypted_secret, encIdentity, integrityHmac, err := MakeCredential(
		protectorPublic, hashAlgId, credential[0:16], request.Tpm2KeyName)
	if err != nil {
		return nil, err
	}

	// Response
	response.IntegrityAlg = request.HashType
	response.IntegrityHmac = integrityHmac
	response.EncIdentity = encIdentity
	response.EncryptedSecret = encrypted_secret

	// Encrypt cert with credential
	cert_hmac, cert_out, err := EncryptDataWithCredential(true, hashAlgId,
		credential[0:16], attestCert, nil)
	if err != nil {
		return nil, err
	}
	response.EncryptedCert = cert_out
	response.EncryptedCertHmac = cert_hmac

	// Need to set required error field to 0.
	noError := int32(0)
	response.Error = &noError
	return response, nil
}

func HandleQuoteDomainRequest(conn net.Conn, policyKey *ecdsa.PrivateKey, derPolicyCert []byte) (bool, error) {
	log.Printf("HandleQuoteDomainRequest\n")

	// Expect a request with attestation from client.
	ms := util.NewMessageStream(conn)
	var request AttestCertRequest
	err := ms.ReadMessage(&request)
	if err != nil {
		log.Printf("HandleQuoteDomainRequest: Couldn't read attest request from channel")
		return false, err
	}

	resp, err := ProcessQuoteDomainRequest(request, policyKey, derPolicyCert)
	if err != nil {
		return false, err
	}

	_, err = ms.WriteMessage(resp)
	if err != nil {
		log.Printf("HandleQuoteDomainRequest: Couldn't return the attestation on the channel")
		log.Printf("\n")
		return false, err
	}
	return false, nil
}
