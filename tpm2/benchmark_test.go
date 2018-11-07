package tpm2

import (
	"crypto/sha256"
	"math/big"
	"testing"
)

func BenchmarkRSA2048Signing(b *testing.B) {
	b.StopTimer()
	rw := openTPM(b)
	defer rw.Close()

	pub := Public{
		Type:       AlgRSA,
		NameAlg:    AlgSHA256,
		Attributes: FlagSign | FlagSensitiveDataOrigin | FlagUserWithAuth,
		RSAParameters: &RSAParams{
			Sign: &SigScheme{
				Alg:  AlgRSASSA,
				Hash: AlgSHA256,
			},
			KeyBits: uint16(2048),
			Modulus: big.NewInt(0),
		},
	}

	signerHandle, _, err := CreatePrimary(rw, HandleOwner, pcrSelection, emptyPassword, defaultPassword, pub)
	if err != nil {
		b.Fatalf("CreatePrimary failed: %v", err)
	}
	defer FlushContext(rw, signerHandle)

	digest := sha256.Sum256([]byte("randomString"))

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := Sign(rw, signerHandle, defaultPassword, digest[:], pub.RSAParameters.Sign)
		if err != nil {
			b.Fatalf("Signing failed: %v", err)
		}
	}
}

func BenchmarkECCNISTP256Signing(b *testing.B) {
	b.StopTimer()
	rw := openTPM(b)
	defer rw.Close()

	pub := Public{
		Type:       AlgECC,
		NameAlg:    AlgSHA256,
		Attributes: FlagSign | FlagSensitiveDataOrigin | FlagUserWithAuth,
		ECCParameters: &ECCParams{
			Sign: &SigScheme{
				Alg:  AlgECDSA,
				Hash: AlgSHA256,
			},
			CurveID: CurveNISTP256,
		},
	}

	signerHandle, _, err := CreatePrimary(rw, HandleOwner, pcrSelection, emptyPassword, defaultPassword, pub)
	if err != nil {
		b.Fatalf("CreatePrimary failed: %v", err)
	}
	defer FlushContext(rw, signerHandle)

	digest := sha256.Sum256([]byte("randomString"))

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := Sign(rw, signerHandle, defaultPassword, digest[:], pub.ECCParameters.Sign)
		if err != nil {
			b.Fatalf("Signing failed: %v", err)
		}
	}
}
