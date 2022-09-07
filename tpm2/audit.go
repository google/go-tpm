package tpm2

import (
	"bytes"
	"fmt"
	"reflect"
)

// CommandAudit represents an audit session for attesting the execution of a
// series of commands in the TPM. It is useful for both command and session
// auditing.
type CommandAudit struct {
	hash   TPMIAlgHash
	digest []byte
}

// NewAudit initializes a new CommandAudit with the specified hash algorithm.
func NewAudit(hash TPMIAlgHash) (*CommandAudit, error) {
	h, err := hash.Hash()
	if err != nil {
		return nil, err
	}
	return &CommandAudit{
		hash:   hash,
		digest: make([]byte, h.Size()),
	}, nil
}

// Extend extends the audit digest with the given command and response.
func (a *CommandAudit) Extend(cmd Command, rsp Response) error {
	cpHash, err := auditCPHash(a.hash, cmd)
	if err != nil {
		return err
	}
	rpHash, err := auditRPHash(a.hash, rsp)
	if err != nil {
		return err
	}
	ha, err := a.hash.Hash()
	if err != nil {
		return err
	}
	h := ha.New()
	h.Write(a.digest)
	h.Write(cpHash)
	h.Write(rpHash)
	a.digest = h.Sum(nil)
	return nil
}

// Digest returns the current digest of the audit.
func (a *CommandAudit) Digest() []byte {
	return a.digest
}

// auditCPHash calculates the command parameter hash for a given command with
// the given hash algorithm. The command is assumed to not have any decrypt
// sessions.
func auditCPHash(h TPMIAlgHash, c Command) ([]byte, error) {
	cc := c.Command()
	names, err := cmdNames(c)
	if err != nil {
		return nil, err
	}
	parms, err := cmdParameters(c, nil)
	if err != nil {
		return nil, err
	}
	return cpHash(h, cc, names, parms)
}

// auditRPHash calculates the response parameter hash for a given response with
// the given hash algorithm. The command is assumed to be successful and to not
// have any encrypt sessions.
func auditRPHash(h TPMIAlgHash, r Response) ([]byte, error) {
	cc := r.Response()
	var parms bytes.Buffer
	parameters := taggedMembers(reflect.ValueOf(r).Elem(), "handle", true)
	for i, parameter := range parameters {
		if err := marshal(&parms, parameter); err != nil {
			return nil, fmt.Errorf("marshalling parameter %v: %w", i+1, err)
		}
	}
	return rpHash(h, TPMRCSuccess, cc, parms.Bytes())
}
