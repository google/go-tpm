package tpm2

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	insecureRand "math/rand"
	"testing"
)

func TestCredentialActivation(t *testing.T) {
	// These values were independently tested/derived-from from TCG 2.0.38-compliant hardware.
	n, ok := new(big.Int).SetString("21781359931719875035142348126986833104406251147281912291128410183893060751686286557235105177011038982931176491091366273712008774268043339103634631078508025847736699362996617038459342869130285665581223736549299195932345592253444537445668838861984376176364138265105552997914795970576284975601851753797509031880704132484924873723738272046545068767315124876824011679223652746414206246649323781826144832659865886735865286033208505363212876011411861316385696414905053502571926429826843117374014575605550176234010475825493066764152314323863950174296024693364113127191375694561947145403061250952175062770094723660429657392597", 10)
	if !ok {
		t.Fatalf("Failed to parse publicN string.")
	}
	public := rsa.PublicKey{
		N: n,
		E: defaultRSAExponent,
	}

	aikDigest, err := base64.StdEncoding.DecodeString("5snpf9qRfKD2Tb72eLAZqC/a/MyUhg+IvdwDZkTJK9w=")
	if err != nil {
		t.Fatalf("Failed to decode AIK digest base64: %v", err)
	}
	expected, err := base64.StdEncoding.DecodeString("AEQAIIQNQu1RkQagbyN+7JlCKUfwBJxIsONZ2/4BD7Q4A15+BcDylTlcvTDgl1CdTuiZk3JcechnrpbfdDXynZ9Sp0uOAwEApDH7zhzLAqsNMSiEdv0xoGrGf/sOCYzSccZ1pDIv7uHON3yMMrX8beOLtCZ9vEQ3vW4i6NdWUJEd/UeMYuc1+Ucu4IB5teUtExhNyvtOXEM7FNXnKooS2ltLA0L7jlkyqwGM7CE0MK4jeFvy13RFNek6S5Rd5MH3RpBuqpL5NjX/yr4g7xCyE2RmXrCSD2DiTm6wU/PtOxYXUVdXeuLaLD69g5pnEAWhARuYa9SomBI8Ewvcxm+slfJpTK/Unrg+FN/d/n0k0IajklNli/jRhuQh5nhrTZXg80kPsEGraSP8eJof49vR643EtoO88jzpTC+/9Tu3yiGCCxEMqR2szA==")
	if err != nil {
		t.Fatalf("Failed to decode expected output base64: %v", err)
	}
	secret, err := base64.StdEncoding.DecodeString("AQIDBAUGBwgBAgMEBQYHCAECAwQFBgcIAQIDBAUGBwg=")
	if err != nil {
		t.Fatalf("Failed to decode secret base64: %v", err)
	}

	aikName := &HashValue{
		Alg:   AlgSHA256,
		Value: aikDigest,
	}

	wrappedCredential, err := generateCredentialActivation(aikName, &public, 16, secret, insecureRand.New(insecureRand.NewSource(99)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, wrappedCredential) {
		t.Errorf("GenerateCredentialActivation(%v, %v, %v) returned incorrect result", aikName, public, secret)
		t.Logf("  Got:  %v", wrappedCredential)
		t.Logf("  Want: %v", expected)
	}
}
