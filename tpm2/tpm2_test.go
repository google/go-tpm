// Copyright (c) 2018, Google Inc. All rights reserved.
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

package tpm2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"flag"
	"math/big"
	"os"
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpmutil"
)

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

var (
	// PCR7 is for SecureBoot.
	pcrSelection     = PCRSelection{Hash: AlgSHA1, PCRs: []int{7}}
	defaultKeyParams = Public{
		Type:       AlgRSA,
		NameAlg:    AlgSHA1,
		Attributes: 0x00030072,
		RSAParameters: &RSAParams{
			Symmetric: &SymScheme{
				Alg:     AlgAES,
				KeyBits: 128,
				Mode:    AlgCFB,
			},
			KeyBits:  2048,
			Exponent: uint32(0x00010001),
			Modulus:  big.NewInt(0),
		},
	}
	defaultPassword = "\x01\x02\x03\x04"
	emptyPassword   = ""
)

func TestGetRandom(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	if _, err := GetRandom(rw, 16); err != nil {
		t.Fatalf("GetRandom failed: %v", err)
	}
}

func TestReadPCRs(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	pcrs, err := ReadPCRs(rw, pcrSelection)
	if err != nil {
		t.Errorf("ReadPCRs failed: %s", err)
	}
	for pcr, val := range pcrs {
		if empty := make([]byte, len(val)); reflect.DeepEqual(empty, val) {
			t.Errorf("Value of PCR %d is empty", pcr)
		}
	}
}

func TestReadClock(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	if _, _, err := ReadClock(rw); err != nil {
		t.Fatalf("ReadClock failed: %s", err)
	}

}

func TestGetCapability(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	if _, err := GetCapability(rw, CapabilityHandles, 1, 0x80000000); err != nil {
		t.Fatalf("GetCapability failed: %s", err)
	}
}

func TestCombinedKeyTest(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	parentHandle, _, err := CreatePrimary(rw, HandleOwner, pcrSelection, emptyPassword, defaultPassword, defaultKeyParams)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %s", err)
	}
	defer FlushContext(rw, parentHandle)

	privateBlob, publicBlob, err := CreateKey(rw, parentHandle, pcrSelection, defaultPassword, defaultPassword, defaultKeyParams)
	if err != nil {
		t.Fatalf("CreateKey failed: %s", err)
	}

	keyHandle, _, err := Load(rw, parentHandle, defaultPassword, publicBlob, privateBlob)
	if err != nil {
		t.Fatalf("Load failed: %s", err)
	}
	defer FlushContext(rw, keyHandle)

	if _, _, _, err := ReadPublic(rw, keyHandle); err != nil {
		t.Fatalf("ReadPublic failed: %s", err)
	}
}

func TestCombinedEndorsementTest(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	parentHandle, _, err := CreatePrimary(rw, HandleOwner, pcrSelection, emptyPassword, emptyPassword, defaultKeyParams)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %s", err)
	}
	defer FlushContext(rw, parentHandle)

	privateBlob, publicBlob, err := CreateKey(rw, parentHandle, pcrSelection, emptyPassword, defaultPassword, defaultKeyParams)
	if err != nil {
		t.Fatalf("CreateKey failed: %s", err)
	}

	keyHandle, _, err := Load(rw, parentHandle, emptyPassword, publicBlob, privateBlob)
	if err != nil {
		t.Fatalf("Load failed: %s", err)
	}
	defer FlushContext(rw, keyHandle)

	_, name, _, err := ReadPublic(rw, keyHandle)
	if err != nil {
		t.Fatalf("ReadPublic failed: %s", err)
	}

	// Generate Credential
	credential := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10}
	credBlob, encryptedSecret0, err := MakeCredential(rw, parentHandle, credential, name)
	if err != nil {
		t.Fatalf("MakeCredential failed: %s", err)
	}

	recoveredCredential1, err := ActivateCredential(rw, keyHandle, parentHandle, defaultPassword, emptyPassword, credBlob, encryptedSecret0)
	if err != nil {
		t.Fatalf("ActivateCredential failed: %s", err)
	}
	if bytes.Compare(credential, recoveredCredential1) != 0 {
		t.Fatalf("Credential and recovered credential differ: got %v, want %v", recoveredCredential1, credential)
	}
}

func TestCombinedContextTest(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	rootHandle, _, err := CreatePrimary(rw, HandleOwner, pcrSelection, emptyPassword, emptyPassword, defaultKeyParams)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer FlushContext(rw, rootHandle)

	// CreateKey (Quote Key)
	quotePrivate, quotePublic, err := CreateKey(rw, rootHandle, pcrSelection, emptyPassword, emptyPassword, defaultKeyParams)
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	quoteHandle, _, err := Load(rw, rootHandle, emptyPassword, quotePublic, quotePrivate)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer FlushContext(rw, quoteHandle)

	saveArea, err := ContextSave(rw, quoteHandle)
	if err != nil {
		t.Fatalf("ContextSave failed: %v", err)
	}
	FlushContext(rw, quoteHandle)

	quoteHandle, err = ContextLoad(rw, saveArea)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
}

func TestEvictControl(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	rootHandle, _, err := CreatePrimary(rw, HandleOwner, pcrSelection, emptyPassword, emptyPassword, defaultKeyParams)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer FlushContext(rw, rootHandle)

	// CreateKey (Quote Key)
	quotePrivate, quotePublic, err := CreateKey(rw, rootHandle, pcrSelection, emptyPassword, emptyPassword, defaultKeyParams)
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	quoteHandle, _, err := Load(rw, rootHandle, emptyPassword, quotePublic, quotePrivate)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer FlushContext(rw, quoteHandle)

	persistentHandle := tpmutil.Handle(0x817FFFFF)
	// Evict persistent key, if there is one already (e.g. last test run failed).
	if err := EvictControl(rw, emptyPassword, HandleOwner, persistentHandle, persistentHandle); err != nil {
		t.Logf("(expected) EvictControl failed: %v", err)
	}
	// Make key persistent.
	if err := EvictControl(rw, emptyPassword, HandleOwner, quoteHandle, persistentHandle); err != nil {
		t.Fatalf("EvictControl failed: %v", err)
	}
	// Evict persistent key.
	if err := EvictControl(rw, emptyPassword, HandleOwner, persistentHandle, persistentHandle); err != nil {
		t.Fatalf("EvictControl failed: %v", err)
	}
}

func TestHash(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	val := []byte("garmonbozia")
	got, err := Hash(rw, AlgSHA256, val)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}
	want := sha256.Sum256(val)

	if !bytes.Equal(got, want[:]) {
		t.Errorf("Hash(%q) returned %x, want %x", val, got, want)
	}
}

func TestLoadExternalPublicKey(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	run := func(t *testing.T, public Public, private Private) {
		t.Helper()

		h, _, err := LoadExternal(rw, public, private, HandleNull)
		if err != nil {
			t.Fatal(err)
		}
		defer FlushContext(rw, h)
	}

	t.Run("RSA", func(t *testing.T) {
		pk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		rp := Public{
			Type:       AlgRSA,
			NameAlg:    AlgSHA1,
			Attributes: FlagSign | FlagSensitiveDataOrigin | FlagUserWithAuth,
			RSAParameters: &RSAParams{
				Sign: &SigScheme{
					Alg:  AlgRSASSA,
					Hash: AlgSHA1,
				},
				KeyBits:  2048,
				Exponent: uint32(pk.PublicKey.E),
				Modulus:  pk.PublicKey.N,
			},
		}
		private := Private{
			Type:      AlgRSA,
			Sensitive: pk.Primes[0].Bytes(),
		}
		run(t, rp, private)
	})
	t.Run("ECC", func(t *testing.T) {
		pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		public := Public{
			Type:       AlgECC,
			NameAlg:    AlgSHA1,
			Attributes: FlagSign | FlagSensitiveDataOrigin | FlagUserWithAuth,
			ECCParameters: &ECCParams{
				Sign: &SigScheme{
					Alg:  AlgECDSA,
					Hash: AlgSHA1,
				},
				CurveID: CurveNISTP256,
				Point:   ECPoint{X: pk.PublicKey.X, Y: pk.PublicKey.Y},
			},
		}
		private := Private{
			Type:      AlgECC,
			Sensitive: pk.D.Bytes(),
		}
		run(t, public, private)
	})
}

func TestCertify(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	params := Public{
		Type:       AlgRSA,
		NameAlg:    AlgSHA256,
		Attributes: FlagSignerDefault,
		RSAParameters: &RSAParams{
			Sign: &SigScheme{
				Alg:  AlgRSASSA,
				Hash: AlgSHA256,
			},
			KeyBits: 2048,
			Modulus: big.NewInt(0),
		},
	}
	signerHandle, signerPub, err := CreatePrimary(rw, HandleOwner, pcrSelection, emptyPassword, defaultPassword, params)
	if err != nil {
		t.Fatalf("CreatePrimary(signer) failed: %s", err)
	}
	defer FlushContext(rw, signerHandle)

	subjectHandle, subjectPub, err := CreatePrimary(rw, HandlePlatform, pcrSelection, emptyPassword, defaultPassword, params)
	if err != nil {
		t.Fatalf("CreatePrimary(subject) failed: %s", err)
	}
	defer FlushContext(rw, subjectHandle)

	attest, sig, err := Certify(rw, defaultPassword, defaultPassword, subjectHandle, signerHandle, nil)
	if err != nil {
		t.Errorf("Certify failed: %s", err)
		return
	}

	attestHash := sha256.Sum256(attest)
	if err := rsa.VerifyPKCS1v15(signerPub.(*rsa.PublicKey), crypto.SHA256, attestHash[:], sig); err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}

	t.Run("DecodeAttestationData", func(t *testing.T) {
		ad, err := DecodeAttestationData(attest)
		if err != nil {
			t.Fatal("DecodeAttestationData:", err)
		}
		params := Public{
			Type:       AlgRSA,
			NameAlg:    AlgSHA256,
			Attributes: FlagSignerDefault,
			RSAParameters: &RSAParams{
				Sign: &SigScheme{
					Alg:  AlgRSASSA,
					Hash: AlgSHA256,
				},
				KeyBits: 2048,
				// Note: we don't include Exponent because CreatePrimary also
				// returns Public without it.
				Modulus: subjectPub.(*rsa.PublicKey).N,
			},
		}
		matches, err := ad.AttestedCertifyInfo.Name.MatchesPublic(params)
		if err != nil {
			t.Fatalf("AttestedCertifyInfo.Name.MatchesPublic error: %v", err)
		}
		if !matches {
			t.Error("Name in AttestationData doesn't match Public structure of subject")
		}
	})
}

func TestCertifyExternalKey(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	params := Public{
		Type:       AlgRSA,
		NameAlg:    AlgSHA256,
		Attributes: FlagSignerDefault,
		RSAParameters: &RSAParams{
			Sign: &SigScheme{
				Alg:  AlgRSASSA,
				Hash: AlgSHA256,
			},
			KeyBits: 2048,
			Modulus: big.NewInt(0),
		},
	}
	signerHandle, signerPub, err := CreatePrimary(rw, HandleOwner, pcrSelection, emptyPassword, defaultPassword, params)
	if err != nil {
		t.Fatalf("CreatePrimary(signer) failed: %s", err)
	}
	defer FlushContext(rw, signerHandle)

	run := func(t *testing.T, public Public, private Private) {
		t.Helper()
		subjectHandle, _, err := LoadExternal(rw, public, private, HandleNull)
		if err != nil {
			t.Fatalf("LoadExternal: %v", err)
		}
		defer FlushContext(rw, subjectHandle)

		attest, sig, err := Certify(rw, emptyPassword, defaultPassword, subjectHandle, signerHandle, nil)
		if err != nil {
			t.Errorf("Certify failed: %s", err)
			return
		}

		attestHash := sha256.Sum256(attest)
		if err := rsa.VerifyPKCS1v15(signerPub.(*rsa.PublicKey), crypto.SHA256, attestHash[:], sig); err != nil {
			t.Errorf("Signature verification failed: %v", err)
		}
	}
	t.Run("RSA", func(t *testing.T) {
		pk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		public := Public{
			Type:       AlgRSA,
			NameAlg:    AlgSHA1,
			Attributes: FlagSign | FlagSensitiveDataOrigin | FlagUserWithAuth,
			RSAParameters: &RSAParams{
				Sign: &SigScheme{
					Alg:  AlgRSASSA,
					Hash: AlgSHA1,
				},
				KeyBits:  2048,
				Exponent: uint32(pk.PublicKey.E),
				Modulus:  pk.PublicKey.N,
			},
		}
		private := Private{
			Type:      AlgRSA,
			Sensitive: pk.Primes[0].Bytes(),
		}
		run(t, public, private)
	})
	t.Run("ECC", func(t *testing.T) {
		pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		public := Public{
			Type:       AlgECC,
			NameAlg:    AlgSHA1,
			Attributes: FlagSign | FlagSensitiveDataOrigin | FlagUserWithAuth,
			ECCParameters: &ECCParams{
				Sign: &SigScheme{
					Alg:  AlgECDSA,
					Hash: AlgSHA1,
				},
				CurveID: CurveNISTP256,
				Point:   ECPoint{X: pk.PublicKey.X, Y: pk.PublicKey.Y},
			},
		}
		private := Private{
			Type:      AlgECC,
			Sensitive: pk.D.Bytes(),
		}
		run(t, public, private)
	})
}

func TestSign(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	run := func(t *testing.T, pub Public) {
		signerHandle, signerPub, err := CreatePrimary(rw, HandleOwner, pcrSelection, emptyPassword, defaultPassword, pub)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %s", err)
		}
		defer FlushContext(rw, signerHandle)

		digest := sha256.Sum256([]byte("heyo"))

		var scheme *SigScheme
		if pub.RSAParameters != nil {
			scheme = pub.RSAParameters.Sign
		}
		if pub.ECCParameters != nil {
			scheme = pub.ECCParameters.Sign
		}
		sig, err := Sign(rw, signerHandle, defaultPassword, digest[:], scheme)
		if err != nil {
			t.Fatalf("Sign failed: %s", err)
		}
		switch signerPub := signerPub.(type) {
		case *rsa.PublicKey:
			if err := rsa.VerifyPKCS1v15(signerPub, crypto.SHA256, digest[:], sig.RSA.Signature); err != nil {
				t.Errorf("Signature verification failed: %v", err)
			}
		case *ecdsa.PublicKey:
			if !ecdsa.Verify(signerPub, digest[:], sig.ECC.R, sig.ECC.S) {
				t.Error("Signature verification failed")
			}
		}
	}

	t.Run("RSA", func(t *testing.T) {
		run(t, Public{
			Type:       AlgRSA,
			NameAlg:    AlgSHA256,
			Attributes: FlagSign | FlagSensitiveDataOrigin | FlagUserWithAuth,
			RSAParameters: &RSAParams{
				Sign: &SigScheme{
					Alg:  AlgRSASSA,
					Hash: AlgSHA256,
				},
				KeyBits: 2048,
				Modulus: big.NewInt(0),
			},
		})
	})
	t.Run("ECC", func(t *testing.T) {
		run(t, Public{
			Type:       AlgECC,
			NameAlg:    AlgSHA256,
			Attributes: FlagSign | FlagSensitiveDataOrigin | FlagUserWithAuth,
			ECCParameters: &ECCParams{
				Sign: &SigScheme{
					Alg:  AlgECDSA,
					Hash: AlgSHA256,
				},
				CurveID: CurveNISTP256,
				Point:   ECPoint{X: big.NewInt(0), Y: big.NewInt(0)},
			},
		})
	})
}

func TestPCREvent(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()
	debugPCR := uint32(16)
	arbitraryBytes := []byte{1}
	if err := PCREvent(rw, tpmutil.Handle(debugPCR), arbitraryBytes); err != nil {
		t.Fatal(err)
	}
}

func TestReadPCR(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()
	pcrVal, err := ReadPCR(rw, 16 /*pcr*/, AlgSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if len(pcrVal) != 32 {
		t.Fatalf("Expected a 32 byte PCR value but got: %v", pcrVal)
	}
}

func TestEncodeDecodeAttestationData(t *testing.T) {
	signer := tpmutil.Handle(100)
	ciQualifiedName := tpmutil.Handle(101)
	ad := AttestationData{
		Magic: 1,
		Type:  TagAttestCertify,
		QualifiedSigner: Name{
			Handle: &signer,
		},
		ExtraData: []byte("foo"),
		ClockInfo: ClockInfo{
			Clock:        3,
			ResetCount:   4,
			RestartCount: 5,
			Safe:         6,
		},
		FirmwareVersion: 7,
		AttestedCertifyInfo: &CertifyInfo{
			Name: Name{
				Digest: &HashValue{
					Alg:   AlgSHA1,
					Value: make([]byte, hashConstructors[AlgSHA1]().Size()),
				},
			},
			QualifiedName: Name{
				Handle: &ciQualifiedName,
			},
		},
	}

	encoded, err := ad.Encode()
	if err != nil {
		t.Fatalf("error encoding AttestationData: %v", err)
	}
	decoded, err := DecodeAttestationData(encoded)
	if err != nil {
		t.Fatalf("error decoding AttestationData: %v", err)
	}

	if !reflect.DeepEqual(*decoded, ad) {
		t.Errorf("got decoded value:\n%v\nwant:\n%v", decoded, ad)
	}
}
