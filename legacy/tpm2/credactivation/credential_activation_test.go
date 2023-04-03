// Copyright (c) 2018, Google LLC All rights reserved.
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

package credactivation

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
)

var (
	eccEKPub = []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsIfixqsUp8cJBSeYDhJKCZ32eAHF
3rS7HdTMOnoFj1MrX+PutPTxa6SFdhWGLnhEQyfcwRni8veQX/dSP2on2w==
-----END PUBLIC KEY-----`)
	rsaEKPub = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArIqmuAvuIcakIEPd2hZl
avob21ehQ7zaHduJQNbNuKVSc1HTlvw9DkWN03b0SktcRIfsjw/omqPl60RhCx0j
qxsYnf5Gk4jhfCnUeQVicAqHnUGrKjMkLIGTZVOpyqBEXHsdhugw6M5HVIKyfwNO
KhvLZKRH8JkvtElVhLQ6E2+H83XoSpkt9oCnGPyN2Z5qRP+fhQiRylMCD8Rz8ABn
YVqGBBrG+2cBt/0uFLjxHx2mm/4sI/1scG5xrcrDLva9WZB40MehW5VlS6Fwqq05
dKtLGpk7ludjH38m2zhM5/UdKZ34skJaS/Aiyj+P5AT1BpJL2ZtjCbBdnMDUSbRF
1QIDAQAB
-----END PUBLIC KEY-----`)
)

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

func mustDecodeBase64(in string, t *testing.T) []byte {
	d, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestCredentialActivation(t *testing.T) {
	var activateTests = []struct {
		ekPub    []byte
		expected string
	}{
		{
			eccEKPub,
			"AEQAIE4SquOcMAzLi7f3ru6P8nuIpSmzr8OTACXpzLo3PTOe/oBazv+fZF2JiKDZqNPNeHISCsZMdEtEfvyYjqmzZ/CB7ABEACAeGDfvDRlRiDV1cbXlVFsSLo8JZ/2nJCA+slYczpcoXgAg+CstT57xB59sS1uDVuIyQulYttdJprVoGkEDVmvcWok=",
		},
		{
			rsaEKPub,
			"AEQAIFjKZAUo3Wmgxu+CqHFzsQZr7BqawtprBmpXpZa77nb5S+iN6IcSPQLCKPZMNuunv7BIb4/VJA/xjMrj8RnQbjspCwEAJcQogjACOfStYTVjmR4p61ZbTTRt7ZNG5nc6iifq+TfnyfoU+E3T6Kount4M8fSUdMWlKx5A24Ms4ndi1VYOA+s4inPusyn1X1ZCHe5tNwT1E9jpVxc0jaUAVad6Q5cOgUyAp4qvc8wmaYXcIa/PzVfa6teF4iXxNqVDAYqpdmbP68v0Hk5gRqCa/tHAdg5avE3C20DP1SSvPitumWROL6mHMooVxjsyjPnHEBLo7y/BKwezEO/15xnBvPOvWs7ARIu1KdER+zrCJX9SMCPbn4cVMfLdrX70xko7XjdhV7pXtAeUeKmmKSYE45m5ZN0h83YgHXGDjf+ynWse10okyA==",
		},
	}

	for _, test := range activateTests {
		p, _ := pem.Decode(test.ekPub)
		public, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			t.Fatal(err)
		}

		aikDigest := mustDecodeBase64("5snpf9qRfKD2Tb72eLAZqC/a/MyUhg+IvdwDZkTJK9w=", t)
		expected := mustDecodeBase64(test.expected, t)
		secret := mustDecodeBase64("AQIDBAUGBwgBAgMEBQYHCAECAwQFBgcIAQIDBAUGBwg=", t)

		aikName := &tpm2.HashValue{
			Alg:   tpm2.AlgSHA256,
			Value: aikDigest,
		}

		idObject, wrappedCredential, err := generate(aikName, public, 16, secret, zeroReader{})
		if err != nil {
			t.Fatal(err)
		}
		activationBlob := append(idObject, wrappedCredential...)

		if !bytes.Equal(expected, activationBlob) {
			t.Errorf("generate(%v, %v, %v) returned incorrect result", aikName, public, secret)
			t.Logf("  Got:  %v", base64.StdEncoding.EncodeToString(activationBlob))
			t.Logf("  Want: %v", base64.StdEncoding.EncodeToString(expected))
		}
	}
}
