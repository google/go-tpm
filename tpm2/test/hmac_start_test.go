package tpm2test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestHmacStart(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	run := func(t *testing.T, data []byte, password []byte, hierarchy TPMHandle, thetpm transport.TPM) []byte {
		maxInputBuffer := 1024

		sas, sasCloser, err := HMACSession(thetpm, TPMAlgSHA256, 16)
		if err != nil {
			t.Fatalf("could not create hmac key authorization session: %v", err)
		}
		defer func() {
			_ = sasCloser()
		}()

		createPrimary := CreatePrimary{
			PrimaryHandle: AuthHandle{
				Handle: hierarchy,
				Auth:   sas,
			},
			InPublic: New2B(TPMTPublic{
				Type:    TPMAlgKeyedHash,
				NameAlg: TPMAlgSHA256,
				ObjectAttributes: TPMAObject{
					SignEncrypt:         true,
					FixedTPM:            true,
					FixedParent:         true,
					SensitiveDataOrigin: true,
					UserWithAuth:        true,
				},
				Parameters: NewTPMUPublicParms(TPMAlgKeyedHash,
					&TPMSKeyedHashParms{
						Scheme: TPMTKeyedHashScheme{
							Scheme: TPMAlgHMAC,
							Details: NewTPMUSchemeKeyedHash(TPMAlgHMAC,
								&TPMSSchemeHMAC{
									HashAlg: TPMAlgSHA256,
								}),
						},
					}),
			}),
		}

		rspCP, err := createPrimary.Execute(thetpm)
		if err != nil {
			t.Fatalf("CreatePrimary HMAC key failed: %v", err)
		}

		flushContext := FlushContext{FlushHandle: rspCP.ObjectHandle}
		defer func() {
			_, _ = flushContext.Execute(thetpm)
		}()

		hmacStart := HmacStart{
			Handle: AuthHandle{
				Handle: rspCP.ObjectHandle,
				Name:   rspCP.Name,
				Auth:   sas,
			},
			Auth: TPM2BAuth{
				Buffer: password,
			},
			HashAlg: TPMAlgNull,
		}

		rspHS, err := hmacStart.Execute(thetpm)
		if err != nil {
			t.Fatalf("HmacStart failed: %v", err)
		}

		authHandle := AuthHandle{
			Handle: rspHS.SequenceHandle,
			Auth:   PasswordAuth(password),
		}

		for len(data) > maxInputBuffer {
			sequenceUpdate := SequenceUpdate{
				SequenceHandle: authHandle,
				Buffer: TPM2BMaxBuffer{
					Buffer: data[:maxInputBuffer],
				},
			}
			_, err = sequenceUpdate.Execute(thetpm)
			if err != nil {
				t.Fatalf("SequenceUpdate failed: %v", err)
			}

			data = data[maxInputBuffer:]
		}

		sequenceComplete := SequenceComplete{
			SequenceHandle: authHandle,
			Buffer: TPM2BMaxBuffer{
				Buffer: data,
			},
			Hierarchy: hierarchy,
		}

		rspSC, err := sequenceComplete.Execute(thetpm)
		if err != nil {
			t.Fatalf("SequenceComplete failed: %v", err)
		}
		return rspSC.Result.Buffer

	}

	bufferSizes := []int{512, 1024, 2048, 4096}
	password := make([]byte, 8)
	_, _ = rand.Read(password)

	hierarchies := map[string]TPMHandle{
		"Null":        TPMRHNull,
		"Owner":       TPMRHOwner,
		"Endorsement": TPMRHEndorsement}

	for _, bufferSize := range bufferSizes {
		data := make([]byte, bufferSize)
		for name, hierarchy := range hierarchies {
			t.Run(fmt.Sprintf("%s hierarchy [bufferSize=%d]", name, bufferSize), func(t *testing.T) {
				_, _ = rand.Read(data)
				// HMAC Key is not exported and can not be externally validated,
				// run HMAC twice with same data and confirm they are the same
				hmac1 := run(t, data, password, hierarchy, thetpm)
				hmac2 := run(t, data, password, hierarchy, thetpm)
				if !bytes.Equal(hmac1, hmac2) {
					t.Errorf("hmac %x is not expected %x", hmac1, hmac2)
				}
			})
		}
	}

	t.Run("Same key multiple sequences", func(t *testing.T) {
		sas, sasCloser, err := HMACSession(thetpm, TPMAlgSHA256, 16)
		if err != nil {
			t.Fatalf("could not create hmac key authorization session: %v", err)
		}
		defer func() {
			_ = sasCloser()
		}()

		createPrimary := CreatePrimary{
			PrimaryHandle: AuthHandle{
				Handle: TPMRHNull,
				Auth:   sas,
			},
			InPublic: New2B(TPMTPublic{
				Type:    TPMAlgKeyedHash,
				NameAlg: TPMAlgSHA256,
				ObjectAttributes: TPMAObject{
					SignEncrypt:         true,
					FixedTPM:            true,
					FixedParent:         true,
					SensitiveDataOrigin: true,
					UserWithAuth:        true,
				},
				Parameters: NewTPMUPublicParms(TPMAlgKeyedHash,
					&TPMSKeyedHashParms{
						Scheme: TPMTKeyedHashScheme{
							Scheme: TPMAlgHMAC,
							Details: NewTPMUSchemeKeyedHash(TPMAlgHMAC,
								&TPMSSchemeHMAC{
									HashAlg: TPMAlgSHA256,
								}),
						},
					}),
			}),
		}

		rspCP, err := createPrimary.Execute(thetpm)
		if err != nil {
			t.Fatalf("CreatePrimary HMAC key failed: %v", err)
		}

		flushContext := FlushContext{FlushHandle: rspCP.ObjectHandle}
		defer func() {
			_, _ = flushContext.Execute(thetpm)
		}()

		hmacStart := HmacStart{
			Handle: AuthHandle{
				Handle: rspCP.ObjectHandle,
				Name:   rspCP.Name,
				Auth:   sas,
			},
			Auth: TPM2BAuth{
				Buffer: password,
			},
			HashAlg: TPMAlgNull,
		}

		rspHS1, err := hmacStart.Execute(thetpm)
		if err != nil {
			t.Fatalf("HmacStart failed: %v", err)
		}

		authHandle1 := AuthHandle{
			Handle: rspHS1.SequenceHandle,
			Auth:   PasswordAuth(password),
		}

		rspHS2, err := hmacStart.Execute(thetpm)
		if err != nil {
			t.Fatalf("HmacStart failed: %v", err)
		}

		authHandle2 := AuthHandle{
			Handle: rspHS2.SequenceHandle,
			Auth:   PasswordAuth(password),
		}

		if rspHS1.SequenceHandle.HandleValue() == rspHS2.SequenceHandle.HandleValue() {
			t.Error("sequence handles are not unique")
		}

		sequenceComplete1 := SequenceComplete{
			SequenceHandle: authHandle1,
		}

		_, err = sequenceComplete1.Execute(thetpm)
		if err != nil {
			t.Fatalf("SequenceComplete failed: %v", err)
		}

		sequenceComplete2 := SequenceComplete{
			SequenceHandle: authHandle2,
		}

		_, err = sequenceComplete2.Execute(thetpm)
		if err != nil {
			t.Fatalf("SequenceComplete failed: %v", err)
		}

	})

}

func TestHmacStartNoKeyAuth(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	run := func(t *testing.T, data []byte, password []byte, hierarchy TPMHandle, thetpm transport.TPM) []byte {
		maxInputBuffer := 1024

		createPrimary := CreatePrimary{
			PrimaryHandle: hierarchy,
			InPublic: New2B(TPMTPublic{
				Type:    TPMAlgKeyedHash,
				NameAlg: TPMAlgSHA256,
				ObjectAttributes: TPMAObject{
					SignEncrypt:         true,
					FixedTPM:            true,
					FixedParent:         true,
					SensitiveDataOrigin: true,
					UserWithAuth:        true,
				},
				Parameters: NewTPMUPublicParms(TPMAlgKeyedHash,
					&TPMSKeyedHashParms{
						Scheme: TPMTKeyedHashScheme{
							Scheme: TPMAlgHMAC,
							Details: NewTPMUSchemeKeyedHash(TPMAlgHMAC,
								&TPMSSchemeHMAC{
									HashAlg: TPMAlgSHA256,
								}),
						},
					}),
			}),
		}

		rspCP, err := createPrimary.Execute(thetpm)
		if err != nil {
			t.Fatalf("CreatePrimary HMAC key failed: %v", err)
		}

		flushContext := FlushContext{FlushHandle: rspCP.ObjectHandle}
		defer func() {
			_, _ = flushContext.Execute(thetpm)
		}()

		hmacStart := HmacStart{
			Handle: NamedHandle{
				Handle: rspCP.ObjectHandle,
				Name:   rspCP.Name,
			},
			Auth: TPM2BAuth{
				Buffer: password,
			},
			HashAlg: TPMAlgNull,
		}

		rspHS, err := hmacStart.Execute(thetpm)
		if err != nil {
			t.Fatalf("HmacStart failed: %v", err)
		}

		authHandle := AuthHandle{
			Handle: rspHS.SequenceHandle,
			Auth:   PasswordAuth(password),
		}

		for len(data) > maxInputBuffer {
			sequenceUpdate := SequenceUpdate{
				SequenceHandle: authHandle,
				Buffer: TPM2BMaxBuffer{
					Buffer: data[:maxInputBuffer],
				},
			}
			_, err = sequenceUpdate.Execute(thetpm)
			if err != nil {
				t.Fatalf("SequenceUpdate failed: %v", err)
			}

			data = data[maxInputBuffer:]
		}

		sequenceComplete := SequenceComplete{
			SequenceHandle: authHandle,
			Buffer: TPM2BMaxBuffer{
				Buffer: data,
			},
			Hierarchy: hierarchy,
		}

		rspSC, err := sequenceComplete.Execute(thetpm)
		if err != nil {
			t.Fatalf("SequenceComplete failed: %v", err)
		}
		return rspSC.Result.Buffer

	}

	password := make([]byte, 8)
	_, _ = rand.Read(password)

	hierarchies := map[string]TPMHandle{
		"Null":        TPMRHNull,
		"Owner":       TPMRHOwner,
		"Endorsement": TPMRHEndorsement}

	data := make([]byte, 1024)
	for name, hierarchy := range hierarchies {
		t.Run(fmt.Sprintf("%s hierarchy [bufferSize=1024]", name), func(t *testing.T) {
			_, _ = rand.Read(data)
			// HMAC Key is not exported and can not be externally validated,
			// run HMAC twice with same data and confirm they are the same
			hmac1 := run(t, data, password, hierarchy, thetpm)
			hmac2 := run(t, data, password, hierarchy, thetpm)
			if !bytes.Equal(hmac1, hmac2) {
				t.Errorf("hmac %x is not expected %x", hmac1, hmac2)
			}
		})
	}

}
