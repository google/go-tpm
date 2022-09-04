package tpm2test

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/google/go-cmp/cmp"
	. "github.com/google/go-tpm/tpm2"
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
	public := TPM2BPublic{
		PublicArea: TPMTPublic{
			Type:    TPMAlgRSA,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				SignEncrypt:         true,
				Restricted:          true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			Parameters: TPMUPublicParms{
				RSADetail: &TPMSRSAParms{
					Scheme: TPMTRSAScheme{
						Scheme: TPMAlgRSASSA,
						Details: TPMUAsymScheme{
							RSASSA: &TPMSSigSchemeRSASSA{
								HashAlg: TPMAlgSHA256,
							},
						},
					},
					KeyBits: 2048,
				},
			},
		},
	}

	pcrSelection := TPMLPCRSelection{
		PCRSelections: []TPMSPCRSelection{
			{
				Hash:      TPMAlgSHA256,
				PCRSelect: PCR7,
			},
		},
	}

	createPrimarySigner := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InSensitive: TPM2BSensitiveCreate{
			Sensitive: TPMSSensitiveCreate{
				UserAuth: TPM2BAuth{
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
		PrimaryHandle: TPMRHOwner,
		InSensitive: TPM2BSensitiveCreate{
			Sensitive: TPMSSensitiveCreate{
				UserAuth: TPM2BAuth{
					Buffer: Auth,
				},
			},
		},
		InPublic:    public,
		CreationPCR: pcrSelection,
	}
	unique := TPMUPublicID{
		RSA: &TPM2BPublicKeyRSA{
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
		QualifyingData: TPM2BData{
			Buffer: originalBuffer,
		},
		InScheme: TPMTSigScheme{
			Scheme: TPMAlgNull,
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
	rsaPub, err := RSAPub(pub.Parameters.RSADetail, pub.Unique.RSA)
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

	public := TPM2BPublic{
		PublicArea: TPMTPublic{
			Type:    TPMAlgRSA,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				SignEncrypt:         true,
				Restricted:          true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				NoDA:                true,
			},
			Parameters: TPMUPublicParms{
				RSADetail: &TPMSRSAParms{
					Scheme: TPMTRSAScheme{
						Scheme: TPMAlgRSASSA,
						Details: TPMUAsymScheme{
							RSASSA: &TPMSSigSchemeRSASSA{
								HashAlg: TPMAlgSHA256,
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
	pcrSelection := TPMLPCRSelection{
		PCRSelections: []TPMSPCRSelection{
			{
				Hash:      TPMAlgSHA1,
				PCRSelect: PCR7,
			},
		},
	}

	createPrimary := CreatePrimary{
		PrimaryHandle: TPMRHEndorsement,
		InPublic:      public,
		CreationPCR:   pcrSelection,
	}
	rspCP, err := createPrimary.Execute(thetpm)
	if err != nil {
		t.Fatalf("Failed to create primary: %v", err)
	}
	flushContext := FlushContext{FlushHandle: rspCP.ObjectHandle}
	defer flushContext.Execute(thetpm)

	inScheme := TPMTSigScheme{
		Scheme: TPMAlgRSASSA,
		Details: TPMUSigScheme{
			RSASSA: &TPMSSchemeHash{
				HashAlg: TPMAlgSHA256,
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
	rsaPub, err := RSAPub(pub.Parameters.RSADetail, pub.Unique.RSA)
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

	public := TPM2BPublic{
		PublicArea: TPMTPublic{
			Type:    TPMAlgRSA,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				SignEncrypt:         true,
				Restricted:          true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			Parameters: TPMUPublicParms{
				RSADetail: &TPMSRSAParms{
					Scheme: TPMTRSAScheme{
						Scheme: TPMAlgRSASSA,
						Details: TPMUAsymScheme{
							RSASSA: &TPMSSigSchemeRSASSA{
								HashAlg: TPMAlgSHA256,
							},
						},
					},
					KeyBits: 2048,
				},
			},
		},
	}

	createPrimarySigner := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InSensitive: TPM2BSensitiveCreate{
			Sensitive: TPMSSensitiveCreate{
				UserAuth: TPM2BAuth{
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
		AuthHandle: TPMRHOwner,
		PublicInfo: TPM2BNVPublic{
			NVPublic: TPMSNVPublic{
				NVIndex: TPMHandle(0x0180000F),
				NameAlg: TPMAlgSHA256,
				Attributes: TPMANV{
					OwnerWrite: true,
					OwnerRead:  true,
					AuthWrite:  true,
					AuthRead:   true,
					NT:         TPMNTOrdinary,
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
		NVIndex: TPMHandle(0x0180000F),
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
		Data: TPM2BMaxNVBuffer{
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
			Handle: TPMHandle(0x0180000F),
			Name:   nvPub.NVName,
			Auth:   PasswordAuth(nil),
		},
		SignHandle: AuthHandle{
			Handle: rspSigner.ObjectHandle,
			Name:   rspSigner.Name,
			Auth:   PasswordAuth(Auth),
		},
		NVIndex: NamedHandle{
			Handle: TPMHandle(0x0180000F),
			Name:   nvPub.NVName,
		},
		QualifyingData: TPM2BData{
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
	rsaPub, err := RSAPub(pub.Parameters.RSADetail, pub.Unique.RSA)
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
