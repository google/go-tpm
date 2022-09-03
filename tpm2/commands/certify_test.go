package tpm2

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm/tpm2/helpers"
	"github.com/google/go-tpm/tpm2/structures/tpm"
	"github.com/google/go-tpm/tpm2/structures/tpm2b"
	"github.com/google/go-tpm/tpm2/structures/tpma"
	"github.com/google/go-tpm/tpm2/structures/tpml"
	"github.com/google/go-tpm/tpm2/structures/tpms"
	"github.com/google/go-tpm/tpm2/structures/tpmt"
	"github.com/google/go-tpm/tpm2/structures/tpmu"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestCertify(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	Auth := []byte("password")

	PCR7, err := CreatePCRSelection([]int{7})
	if err != nil {
		t.Fatalf("Failed to create PCRSelection")
	}
	public := tpm2b.Public{
		PublicArea: tpmt.Public{
			Type:    tpm.AlgRSA,
			NameAlg: tpm.AlgSHA256,
			ObjectAttributes: tpma.Object{
				SignEncrypt:         true,
				Restricted:          true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			Parameters: tpmu.PublicParms{
				RSADetail: &tpms.RSAParms{
					Scheme: tpmt.RSAScheme{
						Scheme: tpm.AlgRSASSA,
						Details: tpmu.AsymScheme{
							RSASSA: &tpms.SigSchemeRSASSA{
								HashAlg: tpm.AlgSHA256,
							},
						},
					},
					KeyBits: 2048,
				},
			},
		},
	}

	pcrSelection := tpml.PCRSelection{
		PCRSelections: []tpms.PCRSelection{
			{
				Hash:      tpm.AlgSHA256,
				PCRSelect: PCR7,
			},
		},
	}

	createPrimarySigner := CreatePrimary{
		PrimaryHandle: tpm.RHOwner,
		InSensitive: tpm2b.SensitiveCreate{
			Sensitive: tpms.SensitiveCreate{
				UserAuth: tpm2b.Auth{
					Buffer: Auth,
				},
			},
		},
		InPublic:    public,
		CreationPCR: pcrSelection,
	}
	rspSigner, err := createPrimarySigner.Execute(thetpm)
	if err != nil {
		t.Fatalf("Failed to create primary: %v", err)
	}
	flushContextSigner := FlushContext{FlushHandle: rspSigner.ObjectHandle}
	defer flushContextSigner.Execute(thetpm)

	createPrimarySubject := CreatePrimary{
		PrimaryHandle: tpm.RHOwner,
		InSensitive: tpm2b.SensitiveCreate{
			Sensitive: tpms.SensitiveCreate{
				UserAuth: tpm2b.Auth{
					Buffer: Auth,
				},
			},
		},
		InPublic:    public,
		CreationPCR: pcrSelection,
	}
	unique := tpmu.PublicID{
		RSA: &tpm2b.PublicKeyRSA{
			Buffer: []byte("subject key"),
		},
	}
	createPrimarySubject.InPublic.PublicArea.Unique = unique

	rspSubject, err := createPrimarySubject.Execute(thetpm)
	if err != nil {
		t.Fatalf("Failed to create primary: %v", err)
	}
	flushContextSubject := FlushContext{FlushHandle: rspSubject.ObjectHandle}
	defer flushContextSubject.Execute(thetpm)

	originalBuffer := []byte("test nonce")

	certify := Certify{
		ObjectHandle: AuthHandle{
			Handle: rspSubject.ObjectHandle,
			Name:   rspSubject.Name,
			Auth:   PasswordAuth(Auth),
		},
		SignHandle: AuthHandle{
			Handle: rspSigner.ObjectHandle,
			Name:   rspSigner.Name,
			Auth:   PasswordAuth(Auth),
		},
		QualifyingData: tpm2b.Data{
			Buffer: originalBuffer,
		},
		InScheme: tpmt.SigScheme{
			Scheme: tpm.AlgNull,
		},
	}

	rspCert, err := certify.Execute(thetpm)
	if err != nil {
		t.Fatalf("Failed to certify: %v", err)
	}

	info, err := Marshal(rspCert.CertifyInfo.AttestationData)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	attestHash := sha256.Sum256(info)
	pub := rspSigner.OutPublic.PublicArea
	rsaPub, err := helpers.RSAPub(pub.Parameters.RSADetail, pub.Unique.RSA)
	if err != nil {
		t.Fatalf("Failed to retrieve Public Key: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, attestHash[:], rspCert.Signature.Signature.RSASSA.Sig.Buffer); err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}

	if !cmp.Equal(originalBuffer, rspCert.CertifyInfo.AttestationData.ExtraData.Buffer) {
		t.Errorf("Attested buffer is different from original buffer")
	}
}

func TestCreateAndCertifyCreation(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	public := tpm2b.Public{
		PublicArea: tpmt.Public{
			Type:    tpm.AlgRSA,
			NameAlg: tpm.AlgSHA256,
			ObjectAttributes: tpma.Object{
				SignEncrypt:         true,
				Restricted:          true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				NoDA:                true,
			},
			Parameters: tpmu.PublicParms{
				RSADetail: &tpms.RSAParms{
					Scheme: tpmt.RSAScheme{
						Scheme: tpm.AlgRSASSA,
						Details: tpmu.AsymScheme{
							RSASSA: &tpms.SigSchemeRSASSA{
								HashAlg: tpm.AlgSHA256,
							},
						},
					},
					KeyBits: 2048,
				},
			},
		},
	}

	PCR7, err := CreatePCRSelection([]int{7})
	if err != nil {
		t.Fatalf("Failed to create PCRSelection")
	}
	pcrSelection := tpml.PCRSelection{
		PCRSelections: []tpms.PCRSelection{
			{
				Hash:      tpm.AlgSHA1,
				PCRSelect: PCR7,
			},
		},
	}

	createPrimary := CreatePrimary{
		PrimaryHandle: tpm.RHEndorsement,
		InPublic:      public,
		CreationPCR:   pcrSelection,
	}
	rspCP, err := createPrimary.Execute(thetpm)
	if err != nil {
		t.Fatalf("Failed to create primary: %v", err)
	}
	flushContext := FlushContext{FlushHandle: rspCP.ObjectHandle}
	defer flushContext.Execute(thetpm)

	inScheme := tpmt.SigScheme{
		Scheme: tpm.AlgRSASSA,
		Details: tpmu.SigScheme{
			RSASSA: &tpms.SchemeHash{
				HashAlg: tpm.AlgSHA256,
			},
		},
	}

	certifyCreation := CertifyCreation{
		SignHandle: AuthHandle{
			Handle: rspCP.ObjectHandle,
			Name:   rspCP.Name,
			Auth:   PasswordAuth(nil),
		},
		ObjectHandle: NamedHandle{
			Handle: rspCP.ObjectHandle,
			Name:   rspCP.Name,
		},
		CreationHash:   rspCP.CreationHash,
		InScheme:       inScheme,
		CreationTicket: rspCP.CreationTicket,
	}

	rspCC, err := certifyCreation.Execute(thetpm)
	if err != nil {
		t.Fatalf("Failed to certify creation: %v", err)
	}

	attName := rspCC.CertifyInfo.AttestationData.Attested.Creation.ObjectName.Buffer
	pubName := rspCP.Name.Buffer
	if !bytes.Equal(attName, pubName) {
		t.Fatalf("Attested name: %v does not match returned public key: %v.", attName, pubName)
	}

	info, err := Marshal(rspCC.CertifyInfo.AttestationData)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	attestHash := sha256.Sum256(info)

	pub := rspCP.OutPublic.PublicArea
	rsaPub, err := helpers.RSAPub(pub.Parameters.RSADetail, pub.Unique.RSA)
	if err != nil {
		t.Fatalf("Failed to retrieve Public Key: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, attestHash[:], rspCC.Signature.Signature.RSASSA.Sig.Buffer); err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
}

func TestNVCertify(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	Auth := []byte("password")

	public := tpm2b.Public{
		PublicArea: tpmt.Public{
			Type:    tpm.AlgRSA,
			NameAlg: tpm.AlgSHA256,
			ObjectAttributes: tpma.Object{
				SignEncrypt:         true,
				Restricted:          true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			Parameters: tpmu.PublicParms{
				RSADetail: &tpms.RSAParms{
					Scheme: tpmt.RSAScheme{
						Scheme: tpm.AlgRSASSA,
						Details: tpmu.AsymScheme{
							RSASSA: &tpms.SigSchemeRSASSA{
								HashAlg: tpm.AlgSHA256,
							},
						},
					},
					KeyBits: 2048,
				},
			},
		},
	}

	createPrimarySigner := CreatePrimary{
		PrimaryHandle: tpm.RHOwner,
		InSensitive: tpm2b.SensitiveCreate{
			Sensitive: tpms.SensitiveCreate{
				UserAuth: tpm2b.Auth{
					Buffer: Auth,
				},
			},
		},
		InPublic: public,
	}
	rspSigner, err := createPrimarySigner.Execute(thetpm)
	if err != nil {
		t.Fatalf("Failed to create primary: %v", err)
	}
	flushContextSigner := FlushContext{FlushHandle: rspSigner.ObjectHandle}
	defer flushContextSigner.Execute(thetpm)

	def := NVDefineSpace{
		AuthHandle: tpm.RHOwner,
		PublicInfo: tpm2b.NVPublic{
			NVPublic: tpms.NVPublic{
				NVIndex: tpm.Handle(0x0180000F),
				NameAlg: tpm.AlgSHA256,
				Attributes: tpma.NV{
					OwnerWrite: true,
					OwnerRead:  true,
					AuthWrite:  true,
					AuthRead:   true,
					NT:         tpm.NTOrdinary,
					NoDA:       true,
				},
				DataSize: 4,
			},
		},
	}
	if err := def.Execute(thetpm); err != nil {
		t.Fatalf("Calling TPM2_NV_DefineSpace: %v", err)
	}

	readPub := NVReadPublic{
		NVIndex: tpm.Handle(0x0180000F),
	}
	nvPub, err := readPub.Execute(thetpm)
	if err != nil {
		t.Fatalf("Calling TPM2_NV_ReadPublic: %v", err)
	}

	prewrite := NVWrite{
		AuthHandle: AuthHandle{
			Handle: def.PublicInfo.NVPublic.NVIndex,
			Name:   nvPub.NVName,
			Auth:   PasswordAuth(nil),
		},
		NVIndex: NamedHandle{
			Handle: def.PublicInfo.NVPublic.NVIndex,
			Name:   nvPub.NVName,
		},
		Data: tpm2b.MaxNVBuffer{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		},
		Offset: 0,
	}
	if err := prewrite.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_Write: %v", err)
	}

	nvPub, err = readPub.Execute(thetpm)
	if err != nil {
		t.Fatalf("Calling TPM2_NV_ReadPublic: %v", err)
	}

	nvCertify := NVCertify{
		AuthHandle: AuthHandle{
			Handle: tpm.Handle(0x0180000F),
			Name:   nvPub.NVName,
			Auth:   PasswordAuth(nil),
		},
		SignHandle: AuthHandle{
			Handle: rspSigner.ObjectHandle,
			Name:   rspSigner.Name,
			Auth:   PasswordAuth(Auth),
		},
		NVIndex: NamedHandle{
			Handle: tpm.Handle(0x0180000F),
			Name:   nvPub.NVName,
		},
		QualifyingData: tpm2b.Data{
			Buffer: []byte("nonce"),
		},
	}
	rspCert, err := nvCertify.Execute(thetpm)
	if err != nil {
		t.Fatalf("Failed to certify: %v", err)
	}

	info, err := Marshal(rspCert.CertifyInfo.AttestationData)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	attestHash := sha256.Sum256(info)
	pub := rspSigner.OutPublic.PublicArea
	rsaPub, err := helpers.RSAPub(pub.Parameters.RSADetail, pub.Unique.RSA)
	if err != nil {
		t.Fatalf("Failed to retrieve Public Key: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, attestHash[:], rspCert.Signature.Signature.RSASSA.Sig.Buffer); err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}

	if !cmp.Equal([]byte("nonce"), rspCert.CertifyInfo.AttestationData.ExtraData.Buffer) {
		t.Errorf("Attested buffer is different from original buffer")
	}
}
