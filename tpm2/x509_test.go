package tpm2_test

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestEKCertToTPMTPublic(t *testing.T) {
	testCases := []struct {
		name    string
		pemFile string
		expObj  tpm2.TPMTPublic
		expErr  error
	}{
		{
			name:    "RSA",
			pemFile: "./testdata/ek-rsa-crt.pem",
			expObj:  rsaEKWithPubKey(ekRSAPubKey),
		},
		{
			name:    "ECC",
			pemFile: "./testdata/ek-ecc-crt.pem",
			expObj:  eccEKWithPoint(ekECCPointX, ekECCPointY),
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			pemData, err := os.ReadFile(tc.pemFile)
			if err != nil {
				t.Fatalf("failed to read ek pem data")
			}
			pemBlock, _ := pem.Decode([]byte(pemData))
			if pemBlock == nil {
				t.Fatalf("failed to decode ek pem data")
			}
			cert, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				t.Fatalf("failed to load ek cert: %s", err)
			}
			actObj, actErr := tpm2.EKCertToTPMTPublic(*cert)
			if !assertExpectedError(t, true, actErr, tc.expErr) {
				return
			}
			assertEK(t, actObj, tc.expObj)
		})
	}
}

const (
	// the ECC point for ./testdata/ek-ecc*
	ekECCPointX = "3e3f4389f926eeb4d7be099dd0bf18e266330b4ad635db686bfc8c9b09882d68"
	ekECCPointY = "8cbddbc51fda8034a7cd27a32bfbcc52d1256525d1c8c8b7a19eb4b2aeb13a1c"

	// the RSA pub key for ./testdata/ek-rsa*
	ekRSAPubKey = "cf86edce5e02a204bd3d1892deb2d5ab0d75df8fde5cbef0596083a816708691aebabbecf6ddc5da3404991e7672c4c4dc81e0ab112f167ce1efdacb3ed1ef8c33c2335d3225844913bea74d7010a337a8205b398c98934c8d34260048ff471e349ca2065d895fc64d748db1a2e4a548c7110bfda1fbb814011471406c5dfde8a56afcf0a05a4c8768762112fef4120d3d03a882ba1de72c0b58f5876995a1d2be35392f85ffa1b9d54a42060301cf66f32ef355425567e90af14ba7fca14f0807d6b2a2235d12b0e33882da0715681e0dee957706018abd9e729ef060c77d6549cab2b78a9d1df14f8acc9649ba0db3ea3ac11e565e1f7a051e98361aca65ab"
)

func rsaEKWithPubKey(pubKey string) tpm2.TPMTPublic {
	pk := make([]byte, 256)
	if n, err := hex.Decode(pk, []byte(pubKey)); err != nil {
		panic(fmt.Sprintf("failed to decode rsa modulus: err=%s", err))
	} else if n != 256 {
		panic(fmt.Sprintf("failed to read entire rsa modulus: n=%d", n))
	}
	ek, err := tpm2.RSAEKTemplateWithPublicKey(tpm2.TPM2BPublicKeyRSA{
		Buffer: pk,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to get rsa ek with pub key: %s", err))
	}
	return ek
}

func eccEKWithPoint(x, y string) tpm2.TPMTPublic {
	xp := make([]byte, 32)
	yp := make([]byte, 32)
	if n, err := hex.Decode(xp, []byte(x)); err != nil {
		panic(fmt.Sprintf("failed to decode ecc point.X: err=%s", err))
	} else if n != 32 {
		panic(fmt.Sprintf("failed to read entire ecc point.X: n=%d", n))
	}
	if n, err := hex.Decode(yp, []byte(y)); err != nil {
		panic(fmt.Sprintf("failed to decode ecc point.Y: err=%s", err))
	} else if n != 32 {
		panic(fmt.Sprintf("failed to read entire ecc point.Y: n=%d", n))
	}
	ek, err := tpm2.ECCEKTemplateWithPoint(tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{
			Buffer: xp,
		},
		Y: tpm2.TPM2BECCParameter{
			Buffer: yp,
		},
	})
	if err != nil {
		panic(fmt.Sprintf("failed to get ecc ek with point: %s", err))
	}
	return ek
}

func assertEK(t *testing.T, ap, ep tpm2.TPMTPublic) {
	assertEKType(t, ap, ep)
	assertEKNameAlg(t, ap, ep)
	assertEKAuthPolicy(t, ap, ep)
	assertEKObjectAttributes(t, ap, ep)
	assertEKParameters(t, ap, ep)
	assertEKUnique(t, ap, ep)
}

func assertEKType(t *testing.T, ap, ep tpm2.TPMTPublic) {
	a, e := ap.Type, ep.Type
	switch {
	case a != tpm2.TPMAlgRSA && a != tpm2.TPMAlgECC:
		t.Errorf("unexpected pub key type: act=%v", a)
	case a != e:
		t.Errorf("unexpected pub key type: act=%v, exp=%v", a, e)
	}
}

func assertEKNameAlg(t *testing.T, ap, ep tpm2.TPMTPublic) {
	a, e := ap.NameAlg, ep.NameAlg
	switch {
	case a != tpm2.TPMAlgSHA256:
		t.Errorf("unexpected pub key alg: act=%v", a)
	case a != e:
		t.Errorf("unexpected pub key alg: act=%v, exp=%v", a, e)
	}
}

func assertEKAuthPolicy(t *testing.T, ap, ep tpm2.TPMTPublic) {
	a, e := ap.AuthPolicy.Buffer, ep.AuthPolicy.Buffer
	if !bytes.Equal(a, e) {
		t.Errorf("unexpected auth policy: act=%x, exp=%x", a, e)
	}
}

func assertEKObjectAttributes(t *testing.T, ap, ep tpm2.TPMTPublic) {
	a, e := ap.ObjectAttributes, ep.ObjectAttributes
	if a, e := a.AdminWithPolicy, e.AdminWithPolicy; a != e {
		t.Errorf("unexpected admin w policy: act=%v, exp=%v", a, e)
	}
	if a, e := a.Decrypt, e.Decrypt; a != e {
		t.Errorf("unexpected decrypt: act=%v, exp=%v", a, e)
	}
	if a, e := a.EncryptedDuplication, e.EncryptedDuplication; a != e {
		t.Errorf("unexpected encrypted dupe: act=%v, exp=%v", a, e)
	}
	if a, e := a.FixedParent, e.FixedParent; a != e {
		t.Errorf("unexpected fixed parent: act=%v, exp=%v", a, e)
	}
	if a, e := a.FixedTPM, e.FixedTPM; a != e {
		t.Errorf("unexpected fixed tpm: act=%v, exp=%v", a, e)
	}
	if a, e := a.NoDA, e.NoDA; a != e {
		t.Errorf("unexpected noda: act=%v, exp=%v", a, e)
	}
	if a, e := a.Restricted, e.Restricted; a != e {
		t.Errorf("unexpected restricted: act=%v, exp=%v", a, e)
	}
	if a, e := a.STClear, e.STClear; a != e {
		t.Errorf("unexpected stclear: act=%v, exp=%v", a, e)
	}
	if a, e := a.SensitiveDataOrigin, e.SensitiveDataOrigin; a != e {
		t.Errorf("unexpected sens data origin: act=%v, exp=%v", a, e)
	}
	if a, e := a.SignEncrypt, e.SignEncrypt; a != e {
		t.Errorf("unexpected sign encrypt: act=%v, exp=%v", a, e)
	}
	if a, e := a.UserWithAuth, e.UserWithAuth; a != e {
		t.Errorf("unexpected user w auth: act=%v, exp=%v", a, e)
	}
	if a, e := a.X509Sign, e.X509Sign; a != e {
		t.Errorf("unexpected x509 sign: act=%v, exp=%v", a, e)
	}
}

func assertEKParameters(t *testing.T, ap, ep tpm2.TPMTPublic) {
	apm, epm := ap.Parameters, ep.Parameters

	switch ap.Type {
	case tpm2.TPMAlgRSA:
		assertFnErr(t, "unexpected ecc detail", apm.ECCDetail)
		assertFnErr(t, "unexpected keyed hash detail", apm.KeyedHashDetail)
		assertFnErr(t, "unexpected sym detail", apm.SymDetail)

		a := assertFnObj(t, "missing act rsa detail", apm.RSADetail)
		e := assertFnObj(t, "missing exp rsa detail", epm.RSADetail)

		assertEKRSAParms(t, a, e)

	case tpm2.TPMAlgECC:
		assertFnErr(t, "unexpected keyed hash detail", apm.KeyedHashDetail)
		assertFnErr(t, "unexpected rsa detail", apm.RSADetail)
		assertFnErr(t, "unexpected sym detail", apm.SymDetail)

		a := assertFnObj(t, "missing act ecc detail", apm.ECCDetail)
		e := assertFnObj(t, "missing exp ecc detail", epm.ECCDetail)

		assertEKECCParms(t, a, e)
	}
}

func assertEKUnique(t *testing.T, ap, ep tpm2.TPMTPublic) {
	apu, epu := ap.Unique, ep.Unique

	switch ap.Type {
	case tpm2.TPMAlgRSA:
		assertFnErr(t, "unexpected ecc", apu.ECC)
		assertFnErr(t, "unexpected keyed hash", apu.KeyedHash)
		assertFnErr(t, "unexpected sym cipher", apu.SymCipher)

		a := assertFnObj(t, "missing act rsa key", apu.RSA)
		e := assertFnObj(t, "missing exp rsa key", epu.RSA)

		assertEKPublicKeyRSA(t, a, e)

	case tpm2.TPMAlgECC:
		assertFnErr(t, "unexpected keyed hash", apu.KeyedHash)
		assertFnErr(t, "unexpected rsa", apu.RSA)
		assertFnErr(t, "unexpected sym cipher", apu.SymCipher)

		a := assertFnObj(t, "missing act ecc point", apu.ECC)
		e := assertFnObj(t, "missing exp ecc point", epu.ECC)

		assertEKECCPoint(t, a, e)
	}
}

func assertEKPublicKeyRSA(t *testing.T, a, e tpm2.TPM2BPublicKeyRSA) {
	if a, e := a.Buffer, e.Buffer; !bytes.Equal(a, e) {
		t.Errorf("unexpected rsa pub key: act=%x, exp=%x", a, e)
	}
}

func assertEKECCPoint(t *testing.T, a, e tpm2.TPMSECCPoint) {
	if a, e := a.X.Buffer, e.X.Buffer; !bytes.Equal(a, e) {
		t.Errorf("unexpected ecc point.X: act=%x, exp=%x", a, e)
	}
	if a, e := a.Y.Buffer, e.Y.Buffer; !bytes.Equal(a, e) {
		t.Errorf("unexpected ecc point.Y: act=%x, exp=%x", a, e)
	}
}

func assertEKRSAParms(t *testing.T, a, e tpm2.TPMSRSAParms) {
	if a, e := a.Exponent, e.Exponent; a != e {
		t.Errorf("unexpected rsa exponent: act=%v, exp=%v", a, e)
	}
	if a, e := a.KeyBits, e.KeyBits; a != e {
		t.Errorf("unexpected rsa key bits: act=%d, exp=%d", a, e)
	}
	assertEKSymDef(t, a.Symmetric, e.Symmetric)
}

func assertEKECCParms(t *testing.T, a, e tpm2.TPMSECCParms) {
	if a, e := a.CurveID, e.CurveID; a != e {
		t.Errorf("unexpected ecc curve id: act=%v, exp=%v", a, e)
	}
	assertEKSymDef(t, a.Symmetric, e.Symmetric)
}

func assertEKSymDef(t *testing.T, a, e tpm2.TPMTSymDefObject) {
	if a, e := a.Algorithm, e.Algorithm; a != e {
		t.Errorf("unexpected sym def alg: act=%d, exp=%d", a, e)
	}
	assertFnErr(t, "unexpected sym def key bits xor", a.KeyBits.XOR)

	akb := assertFnObj(t, "missing act aes key bits", a.KeyBits.AES)
	ekb := assertFnObj(t, "missing exp aes key bits", e.KeyBits.AES)

	if a, e := akb, ekb; a != e {
		t.Errorf("unexpected sym def key bits: act=%d, exp=%d", a, e)
	}

	// The mode's contents reflect CFB, but it's not possible to retrieve that
	// information here.
	assertFnObj(t, "unexpected sym def mode", a.Mode.AES)
}

func assertFnErr[T any](t *testing.T, msg string, fn func() (T, error)) {
	if _, err := fn(); err == nil {
		t.Error(msg)
	}
}

type rsaEccDetailKeyPointTypes interface {
	tpm2.TPMSRSAParms | tpm2.TPMSECCParms |
		tpm2.TPM2BPublicKeyRSA | tpm2.TPMSECCPoint |
		tpm2.TPMKeyBits | tpm2.TPMAlgID
}

func assertFnObj[T rsaEccDetailKeyPointTypes](
	t *testing.T, msg string, fn func() (*T, error)) T {

	obj, err := fn()
	if err != nil {
		t.Errorf(msg+": %v", err)
	}
	if obj == nil {
		t.Fatalf(msg + ": nil details")
	}
	return *obj
}
