package tpm2

import (
	"encoding/binary"

	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/structures/tpms"
	"github.com/google/go-tpm/direct/structures/tpmt"
)

// HandleName returns the TPM Name of a PCR, session, or permanent value
// (e.g., hierarchy) handle.
func HandleName(h tpm.Handle) tpm2b.Name {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, uint32(h))
	return tpm2b.Name{
		Buffer: result,
	}
}

// objectOrNVName calculates the Name of an NV index or object.
// pub is a pointer to either a tpmt.Public or tpms.NVPublic.
func objectOrNVName(alg tpm.AlgID, pub interface{}) (*tpm2b.Name, error) {
	h, err := alg.Hash()
	if err != nil {
		return nil, err
	}

	// Create a byte slice with the correct reserved size and marshal the
	// NameAlg to it.
	result := make([]byte, 2, 2+h.Size())
	binary.BigEndian.PutUint16(result, uint16(alg))

	// Calculate the hash of the entire Public contents and append it to the
	// result.
	ha := h.New()
	marshalledPub, err := Marshal(pub)
	if err != nil {
		return nil, err
	}
	ha.Write(marshalledPub)
	result = ha.Sum(result)

	return &tpm2b.Name{
		Buffer: result,
	}, nil
}

// ObjectName returns the TPM Name of an object.
func ObjectName(p *tpmt.Public) (*tpm2b.Name, error) {
	return objectOrNVName(p.NameAlg, p)
}

// NVName returns the TPM Name of an NV index.
func NVName(p *tpms.NVPublic) (*tpm2b.Name, error) {
	return objectOrNVName(p.NameAlg, p)
}
