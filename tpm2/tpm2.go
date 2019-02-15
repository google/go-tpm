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

// Package tpm2 supports direct communication with a TPM 2.0 device under Linux.
package tpm2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpmutil"
)

// OpenTPM opens a channel to the TPM at the given path. If the file is a
// device, then it treats it like a normal TPM device, and if the file is a
// Unix domain socket, then it opens a connection to the socket.
var OpenTPM = tpmutil.OpenTPM

// GetRandom gets random bytes from the TPM.
func GetRandom(rw io.ReadWriter, size uint16) ([]byte, error) {
	resp, err := runCommand(rw, TagNoSessions, cmdGetRandom, size)
	if err != nil {
		return nil, err
	}

	var randBytes []byte
	if _, err := tpmutil.Unpack(resp, &randBytes); err != nil {
		return nil, err
	}
	return randBytes, nil
}

// FlushContext removes an object or session under handle to be removed from
// the TPM. This must be called for any loaded handle to avoid out-of-memory
// errors in TPM.
func FlushContext(rw io.ReadWriter, handle tpmutil.Handle) error {
	_, err := runCommand(rw, TagNoSessions, cmdFlushContext, handle)
	return err
}

func encodeTPMLPCRSelection(sel PCRSelection) ([]byte, error) {
	if len(sel.PCRs) == 0 {
		return tpmutil.Pack(uint32(0))
	}

	// PCR selection is a variable-size bitmask, where position of a set bit is
	// the selected PCR index.
	// Size of the bitmask in bytes is pre-pended. It should be at least
	// sizeOfPCRSelect.
	//
	// For example, selecting PCRs 3 and 9 looks like:
	// size(3)  mask     mask     mask
	// 00000011 00000000 00000001 00000100
	ts := tpmsPCRSelection{
		Hash: sel.Hash,
		Size: sizeOfPCRSelect,
		PCRs: make([]byte, sizeOfPCRSelect),
	}
	// sel.PCRs parameter is indexes of PCRs, convert that to set bits.
	for _, n := range sel.PCRs {
		byteNum := n / 8
		bytePos := byte(1 << byte(n%8))
		ts.PCRs[byteNum] |= bytePos
	}
	// Only encode 1 TPMS_PCR_SELECT value.
	return tpmutil.Pack(uint32(1), ts)
}

func decodeTPMLPCRSelection(buf *bytes.Buffer) (PCRSelection, error) {
	var count uint32
	var sel PCRSelection
	if err := tpmutil.UnpackBuf(buf, &count); err != nil {
		return sel, err
	}
	switch count {
	case 0:
		sel.Hash = AlgUnknown
		return sel, nil
	case 1: // We only support decoding of a single PCRSelection.
	default:
		return sel, fmt.Errorf("decoding TPML_PCR_SELECTION list longer than 1 is not supported (got length %d)", count)
	}

	// See comment in encodeTPMLPCRSelection for details on this format.
	var ts tpmsPCRSelection
	if err := tpmutil.UnpackBuf(buf, &ts.Hash, &ts.Size); err != nil {
		return sel, err
	}
	ts.PCRs = make([]byte, ts.Size)
	if _, err := buf.Read(ts.PCRs); err != nil {
		return sel, err
	}

	sel.Hash = ts.Hash
	for i := 0; i < int(ts.Size); i++ {
		for j := 0; j < 8; j++ {
			set := ts.PCRs[i] & byte(1<<byte(j))
			if set == 0 {
				continue
			}
			sel.PCRs = append(sel.PCRs, 8*i+j)
		}
	}
	return sel, nil
}

func decodeReadPCRs(in []byte) (map[int][]byte, error) {
	buf := bytes.NewBuffer(in)
	var updateCounter uint32
	if err := tpmutil.UnpackBuf(buf, &updateCounter); err != nil {
		return nil, err
	}

	sel, err := decodeTPMLPCRSelection(buf)
	if err != nil {
		return nil, fmt.Errorf("decoding TPML_PCR_SELECTION: %v", err)
	}

	var digestCount uint32
	if err = tpmutil.UnpackBuf(buf, &digestCount); err != nil {
		return nil, fmt.Errorf("decoding TPML_DIGEST length: %v", err)
	}
	if int(digestCount) != len(sel.PCRs) {
		return nil, fmt.Errorf("received %d PCRs but %d digests", len(sel.PCRs), digestCount)
	}

	vals := make(map[int][]byte)
	for _, pcr := range sel.PCRs {
		var val []byte
		if err = tpmutil.UnpackBuf(buf, &val); err != nil {
			return nil, fmt.Errorf("decoding TPML_DIGEST item: %v", err)
		}
		vals[pcr] = val
	}
	return vals, nil
}

// ReadPCRs reads PCR values from the TPM.
func ReadPCRs(rw io.ReadWriter, sel PCRSelection) (map[int][]byte, error) {
	cmd, err := encodeTPMLPCRSelection(sel)
	if err != nil {
		return nil, err
	}
	resp, err := runCommand(rw, TagNoSessions, cmdPCRRead, tpmutil.RawBytes(cmd))
	if err != nil {
		return nil, err
	}

	return decodeReadPCRs(resp)
}

func decodeReadClock(in []byte) (uint64, uint64, error) {
	var curTime, curClock uint64

	if _, err := tpmutil.Unpack(in, &curTime, &curClock); err != nil {
		return 0, 0, err
	}
	return curTime, curClock, nil
}

// ReadClock returns current clock values from the TPM.
//
// First return value is time in milliseconds since TPM was initialized (since
// system startup).
//
// Second return value is time in milliseconds since TPM reset (since Storage
// Primary Seed is changed).
func ReadClock(rw io.ReadWriter) (uint64, uint64, error) {
	resp, err := runCommand(rw, TagNoSessions, cmdReadClock)
	if err != nil {
		return 0, 0, err
	}
	return decodeReadClock(resp)
}

func decodeGetCapability(in []byte) ([]interface{}, bool, error) {
	var moreData byte
	var capReported Capability

	buf := bytes.NewBuffer(in)
	if err := tpmutil.UnpackBuf(buf, &moreData, &capReported); err != nil {
		return nil, false, err
	}

	switch capReported {
	case CapabilityHandles:
		var numHandles uint32
		if err := tpmutil.UnpackBuf(buf, &numHandles); err != nil {
			return nil, false, fmt.Errorf("could not unpack handle count: %v", err)
		}

		var handles []interface{}
		for i := 0; i < int(numHandles); i++ {
			var handle tpmutil.Handle
			if err := tpmutil.UnpackBuf(buf, &handle); err != nil {
				return nil, false, fmt.Errorf("could not unpack handle: %v", err)
			}
			handles = append(handles, handle)
		}
		return handles, moreData > 0, nil
	case CapabilityAlgs:
		var numAlgs uint32
		if err := tpmutil.UnpackBuf(buf, &numAlgs); err != nil {
			return nil, false, fmt.Errorf("could not unpack algorithm count: %v", err)
		}

		var algs []interface{}
		for i := 0; i < int(numAlgs); i++ {
			var alg AlgorithmDescription
			if err := tpmutil.UnpackBuf(buf, &alg); err != nil {
				return nil, false, fmt.Errorf("could not unpack algorithm description: %v", err)
			}
			algs = append(algs, alg)
		}
		return algs, moreData > 0, nil
	case CapabilityTPMProperties:
		var numProps uint32
		if err := tpmutil.UnpackBuf(buf, &numProps); err != nil {
			return nil, false, fmt.Errorf("could not unpack fixed properties count: %v", err)
		}

		var props []interface{}
		for i := 0; i < int(numProps); i++ {
			var prop TaggedProperty
			if err := tpmutil.UnpackBuf(buf, &prop); err != nil {
				return nil, false, fmt.Errorf("could not unpack tagged property: %v", err)
			}
			props = append(props, prop)
		}
		return props, moreData > 0, nil

	default:
		return nil, false, fmt.Errorf("unsupported capability %v", capReported)
	}
}

// GetCapability returns various information about the TPM state.
//
// Currently only CapabilityHandles (list active handles) and CapabilityAlgs
// (list supported algorithms) are supported. CapabilityHandles will return
// a []tpmutil.Handle for vals, CapabilityAlgs will return
// []AlgorithmDescription.
//
// moreData is true if the TPM indicated that more data is available. Follow
// the spec for the capability in question on how to query for more data.
func GetCapability(rw io.ReadWriter, capa Capability, count, property uint32) (vals []interface{}, moreData bool, err error) {
	resp, err := runCommand(rw, TagNoSessions, cmdGetCapability, capa, property, count)
	if err != nil {
		return nil, false, err
	}
	return decodeGetCapability(resp)
}

func encodeAuthArea(sections ...AuthCommand) ([]byte, error) {
	var res []byte
	for _, s := range sections {
		buf, err := tpmutil.Pack(s)
		if err != nil {
			return nil, err
		}
		res = append(res, buf...)
	}

	size, err := tpmutil.Pack(uint32(len(res)))
	if err != nil {
		return nil, err
	}

	return concat(size, res)
}

func encodePCREvent(pcr tpmutil.Handle, eventData []byte) ([]byte, error) {
	ha, err := tpmutil.Pack(pcr)
	if err != nil {
		return nil, err
	}
	auth, err := encodeAuthArea(AuthCommand{Session: HandlePasswordSession, Attributes: AttrContinueSession, Auth: EmptyAuth})
	if err != nil {
		return nil, err
	}
	event, err := tpmutil.Pack(eventData)
	if err != nil {
		return nil, err
	}
	return concat(ha, auth, event)
}

// PCREvent writes an update to the specified PCR.
func PCREvent(rw io.ReadWriter, pcr tpmutil.Handle, eventData []byte) error {
	cmd, err := encodePCREvent(pcr, eventData)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, TagSessions, cmdPCREvent, tpmutil.RawBytes(cmd))
	return err
}

func encodeSensitiveArea(s tpmsSensitiveCreate) ([]byte, error) {
	// TPMS_SENSITIVE_CREATE
	buf, err := tpmutil.Pack(s)
	if err != nil {
		return nil, err
	}
	// TPM2B_SENSITIVE_CREATE
	return tpmutil.Pack(buf)
}

// encodeCreate works for both TPM2_Create and TPM2_CreatePrimary.
func encodeCreate(owner tpmutil.Handle, sel PCRSelection, parentPassword, ownerPassword string, sensitiveData []byte, pub Public) ([]byte, error) {
	inPublic, err := pub.Encode()
	if err != nil {
		return nil, err
	}
	return encodeCreateRawTemplate(owner, sel, parentPassword, ownerPassword, sensitiveData, inPublic)
}

func encodeCreateRawTemplate(owner tpmutil.Handle, sel PCRSelection, parentPassword, ownerPassword string, sensitiveData, inPublic []byte) ([]byte, error) {
	parent, err := tpmutil.Pack(owner)
	if err != nil {
		return nil, err
	}
	auth, err := encodeAuthArea(AuthCommand{Session: HandlePasswordSession, Attributes: AttrContinueSession, Auth: []byte(parentPassword)})
	if err != nil {
		return nil, err
	}
	inSensitive, err := encodeSensitiveArea(tpmsSensitiveCreate{
		UserAuth: []byte(ownerPassword),
		Data:     sensitiveData,
	})
	if err != nil {
		return nil, err
	}
	publicBlob, err := tpmutil.Pack(inPublic)
	if err != nil {
		return nil, err
	}
	outsideInfo, err := tpmutil.Pack([]byte(nil))
	if err != nil {
		return nil, err
	}
	creationPCR, err := encodeTPMLPCRSelection(sel)
	if err != nil {
		return nil, err
	}
	return concat(
		parent,
		auth,
		inSensitive,
		publicBlob,
		outsideInfo,
		creationPCR,
	)
}

func decodeCreatePrimary(in []byte) (handle tpmutil.Handle, public, creationData, creationHash []byte, ticket *Ticket, creationName []byte, err error) {
	var paramSize uint32

	buf := bytes.NewBuffer(in)
	// Handle and auth data.
	if err := tpmutil.UnpackBuf(buf, &handle, &paramSize); err != nil {
		return 0, nil, nil, nil, nil, nil, fmt.Errorf("decoding handle, paramSize: %v", err)
	}

	if err := tpmutil.UnpackBuf(buf, &public, &creationData, &creationHash); err != nil {
		return 0, nil, nil, nil, nil, nil, fmt.Errorf("decoding public, creationData, creationHash: %v", err)
	}

	ticket, err = decodeTicket(buf)
	if err != nil {
		return 0, nil, nil, nil, nil, nil, fmt.Errorf("decoding ticket: %v", err)
	}

	if err := tpmutil.UnpackBuf(buf, &creationName); err != nil {
		return 0, nil, nil, nil, nil, nil, fmt.Errorf("decoding creationName: %v", err)
	}

	if _, err := DecodeCreationData(creationData); err != nil {
		return 0, nil, nil, nil, nil, nil, fmt.Errorf("parsing CreationData: %v", err)
	}
	return handle, public, creationData, creationHash, ticket, creationName, err
}

// CreatePrimary initializes the primary key in a given hierarchy.
// The second return value is the public part of the generated key.
func CreatePrimary(rw io.ReadWriter, owner tpmutil.Handle, sel PCRSelection, parentPassword, ownerPassword string, p Public) (tpmutil.Handle, crypto.PublicKey, error) {
	hnd, public, _, _, _, _, err := CreatePrimaryEx(rw, owner, sel, parentPassword, ownerPassword, p)
	if err != nil {
		return 0, nil, err
	}

	pub, err := DecodePublic(public)
	if err != nil {
		return 0, nil, fmt.Errorf("parsing public: %v", err)
	}

	var pubKey crypto.PublicKey
	switch pub.Type {
	case AlgRSA:
		// Endianness of big.Int.Bytes/SetBytes and modulus in the TPM is the same
		// (big-endian).
		pubKey = &rsa.PublicKey{N: pub.RSAParameters.Modulus, E: int(pub.RSAParameters.Exponent)}
	case AlgECC:
		curve, ok := toGoCurve[pub.ECCParameters.CurveID]
		if !ok {
			return 0, nil, fmt.Errorf("can't map TPM EC curve ID 0x%x to Go elliptic.Curve value", pub.ECCParameters.CurveID)
		}
		pubKey = &ecdsa.PublicKey{
			X:     pub.ECCParameters.Point.X,
			Y:     pub.ECCParameters.Point.Y,
			Curve: curve,
		}
	default:
		return 0, nil, fmt.Errorf("unsupported primary key type 0x%x", pub.Type)
	}

	return hnd, pubKey, err
}

// CreatePrimaryEx initializes the primary key in a given hierarchy.
// This function differs from CreatePrimary in that all response elements
// are returned, and they are returned in relatively raw form.
func CreatePrimaryEx(rw io.ReadWriter, owner tpmutil.Handle, sel PCRSelection, parentPassword, ownerPassword string, pub Public) (keyHandle tpmutil.Handle, public, creationData, creationHash []byte, ticket *Ticket, creationName []byte, err error) {
	cmd, err := encodeCreate(owner, sel, parentPassword, ownerPassword, nil /*inSensitive*/, pub)
	if err != nil {
		return 0, nil, nil, nil, nil, nil, err
	}
	resp, err := runCommand(rw, TagSessions, cmdCreatePrimary, tpmutil.RawBytes(cmd))
	if err != nil {
		return 0, nil, nil, nil, nil, nil, err
	}

	return decodeCreatePrimary(resp)
}

// CreatePrimaryRawTemplate is CreatePrimary, but with the public template
// (TPMT_PUBLIC) provided pre-encoded. This is commonly used with key templates
// stored in NV RAM.
func CreatePrimaryRawTemplate(rw io.ReadWriter, owner tpmutil.Handle, sel PCRSelection, parentPassword, ownerPassword string, public []byte) (tpmutil.Handle, crypto.PublicKey, error) {
	cmd, err := encodeCreateRawTemplate(owner, sel, parentPassword, ownerPassword, nil /*inSensitive*/, public)
	if err != nil {
		return 0, nil, err
	}
	resp, err := runCommand(rw, TagSessions, cmdCreatePrimary, tpmutil.RawBytes(cmd))
	if err != nil {
		return 0, nil, err
	}

	hnd, pub, _, _, _, _, err := decodeCreatePrimary(resp)
	return hnd, pub, err
}

func decodeReadPublic(in []byte) (Public, []byte, []byte, error) {
	var resp struct {
		Public        []byte
		Name          []byte
		QualifiedName []byte
	}
	if _, err := tpmutil.Unpack(in, &resp); err != nil {
		return Public{}, nil, nil, err
	}
	pub, err := DecodePublic(resp.Public)
	if err != nil {
		return Public{}, nil, nil, err
	}
	return pub, resp.Name, resp.QualifiedName, nil
}

// ReadPublic reads the public part of the object under handle.
// Returns the public data, name and qualified name.
func ReadPublic(rw io.ReadWriter, handle tpmutil.Handle) (Public, []byte, []byte, error) {
	resp, err := runCommand(rw, TagNoSessions, cmdReadPublic, handle)
	if err != nil {
		return Public{}, nil, nil, err
	}

	return decodeReadPublic(resp)
}

func decodeCreate(in []byte) (handle tpmutil.Handle, private, public, creationData, creationHash []byte, creationTicket Ticket, err error) {
	buf := bytes.NewBuffer(in)

	if err := tpmutil.UnpackBuf(buf, &handle, &private, &public, &creationData, &creationHash); err != nil {
		return 0, nil, nil, nil, nil, Ticket{}, fmt.Errorf("decoding Handle, Private, Public, CreationData, CreationHash: %v", err)
	}
	cr, err := decodeTicket(buf)
	if err != nil {
		return 0, nil, nil, nil, nil, Ticket{}, fmt.Errorf("decoding CreationTicket: %v", err)
	}
	creationTicket = *cr
	if _, err := DecodeCreationData(creationData); err != nil {
		return 0, nil, nil, nil, nil, Ticket{}, fmt.Errorf("decoding CreationData: %v", err)
	}
	return handle, private, public, creationData, creationHash, creationTicket, nil
}

func create(rw io.ReadWriter, parentHandle tpmutil.Handle, parentPassword, objectPassword string, sensitiveData []byte, pub Public, pcrSelection PCRSelection) (handle tpmutil.Handle, private, public, creationData, creationHash []byte, creationTicket Ticket, err error) {
	cmd, err := encodeCreate(parentHandle, pcrSelection, parentPassword, objectPassword, sensitiveData, pub)
	if err != nil {
		return 0, nil, nil, nil, nil, Ticket{}, err
	}
	resp, err := runCommand(rw, TagSessions, cmdCreate, tpmutil.RawBytes(cmd))
	if err != nil {
		return 0, nil, nil, nil, nil, Ticket{}, err
	}
	return decodeCreate(resp)
}

// CreateKey creates a new key pair under the owner handle.
// Returns private key and public key blobs.
func CreateKey(rw io.ReadWriter, owner tpmutil.Handle, sel PCRSelection, parentPassword, ownerPassword string, pub Public) ([]byte, []byte, error) {
	_, private, public, _, _, _, err := create(rw, owner, parentPassword, ownerPassword, nil /*inSensitive*/, pub, sel)
	if err != nil {
		return nil, nil, err
	}
	return private, public, nil
}

// Seal creates a data blob object that seals the sensitive data under a parent and with a
// password and auth policy. Access to the parent must be available with a simple password.
// Returns private and public portions of the created object.
func Seal(rw io.ReadWriter, parentHandle tpmutil.Handle, parentPassword, objectPassword string, objectAuthPolicy []byte, sensitiveData []byte) ([]byte, []byte, error) {
	inPublic := Public{
		Type:       AlgKeyedHash,
		NameAlg:    AlgSHA256,
		Attributes: FlagFixedTPM | FlagFixedParent,
		AuthPolicy: objectAuthPolicy,
	}
	_, private, public, _, _, _, err := create(rw, parentHandle, parentPassword, objectPassword, sensitiveData, inPublic, PCRSelection{})
	if err != nil {
		return nil, nil, err
	}
	return private, public, nil
}

func encodeLoad(parentHandle tpmutil.Handle, parentAuth string, publicBlob, privateBlob []byte) ([]byte, error) {
	ah, err := tpmutil.Pack(parentHandle)
	if err != nil {
		return nil, err
	}
	auth, err := encodeAuthArea(AuthCommand{Session: HandlePasswordSession, Attributes: AttrContinueSession, Auth: []byte(parentAuth)})
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(privateBlob, publicBlob)
	if err != nil {
		return nil, err
	}
	return concat(ah, auth, params)
}

func decodeLoad(in []byte) (tpmutil.Handle, []byte, error) {
	var handle tpmutil.Handle
	var paramSize uint32
	var name []byte

	if _, err := tpmutil.Unpack(in, &handle, &paramSize, &name); err != nil {
		return 0, nil, err
	}
	return handle, name, nil
}

// Load loads public/private blobs into an object in the TPM.
// Returns loaded object handle and its name.
func Load(rw io.ReadWriter, parentHandle tpmutil.Handle, parentAuth string, publicBlob, privateBlob []byte) (tpmutil.Handle, []byte, error) {
	cmd, err := encodeLoad(parentHandle, parentAuth, publicBlob, privateBlob)
	if err != nil {
		return 0, nil, err
	}
	resp, err := runCommand(rw, TagSessions, cmdLoad, tpmutil.RawBytes(cmd))
	if err != nil {
		return 0, nil, err
	}
	return decodeLoad(resp)
}

func encodeLoadExternal(pub Public, private Private, hierarchy tpmutil.Handle) ([]byte, error) {
	privateBlob, err := private.Encode()
	if err != nil {
		return nil, err
	}
	publicBlob, err := pub.Encode()
	if err != nil {
		return nil, err
	}

	return tpmutil.Pack(privateBlob, publicBlob, hierarchy)
}

func decodeLoadExternal(in []byte) (tpmutil.Handle, []byte, error) {
	var handle tpmutil.Handle
	var name []byte

	if _, err := tpmutil.Unpack(in, &handle, &name); err != nil {
		return 0, nil, err
	}
	return handle, name, nil
}

// LoadExternal loads a public (and optionally a private) key into an object in
// the TPM. Returns loaded object handle and its name.
func LoadExternal(rw io.ReadWriter, pub Public, private Private, hierarchy tpmutil.Handle) (tpmutil.Handle, []byte, error) {
	cmd, err := encodeLoadExternal(pub, private, hierarchy)
	if err != nil {
		return 0, nil, err
	}
	resp, err := runCommand(rw, TagNoSessions, cmdLoadExternal, tpmutil.RawBytes(cmd))
	if err != nil {
		return 0, nil, err
	}
	handle, name, err := decodeLoadExternal(resp)
	if err != nil {
		return 0, nil, err
	}
	return handle, name, nil
}

// PolicyPassword sets password authorization requirement on the object.
func PolicyPassword(rw io.ReadWriter, handle tpmutil.Handle) error {
	_, err := runCommand(rw, TagNoSessions, cmdPolicyPassword, handle)
	return err
}

func encodePolicySecret(entityHandle tpmutil.Handle, entityAuth AuthCommand, policyHandle tpmutil.Handle, policyNonce, cpHash, policyRef []byte, expiry int32) ([]byte, error) {
	auth, err := encodeAuthArea(entityAuth)
	if err != nil {
		return nil, err
	}
	handles, err := tpmutil.Pack(entityHandle, policyHandle)
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(policyNonce, cpHash, policyRef, expiry)
	if err != nil {
		return nil, err
	}
	return concat(handles, auth, params)
}

// PolicySecret sets a secret authorization requirement on the provided entity.
// If expiry is non-zero, the authorization is valid for expiry seconds.
func PolicySecret(rw io.ReadWriter, entityHandle tpmutil.Handle, entityAuth AuthCommand, policyHandle tpmutil.Handle, policyNonce, cpHash, policyRef []byte, expiry int32) (*Ticket, error) {
	cmd, err := encodePolicySecret(entityHandle, entityAuth, policyHandle, policyNonce, cpHash, policyRef, expiry)
	if err != nil {
		return nil, err
	}
	resp, err := runCommand(rw, TagSessions, CmdPolicySecret, tpmutil.RawBytes(cmd))
	if err != nil {
		return nil, err
	}

	// Tickets are only provided if expiry is set.
	if expiry != 0 {
		tk, err := decodeTicket(bytes.NewBuffer(resp))
		if err != nil {
			return nil, fmt.Errorf("decoding ticket: %v", err)
		}
		return tk, nil
	}
	return nil, nil
}

func encodePolicyPCR(session tpmutil.Handle, expectedDigest []byte, sel PCRSelection) ([]byte, error) {
	params, err := tpmutil.Pack(session, expectedDigest)
	if err != nil {
		return nil, err
	}
	pcrs, err := encodeTPMLPCRSelection(sel)
	if err != nil {
		return nil, err
	}
	return concat(params, pcrs)
}

// PolicyPCR sets PCR state binding for authorization on a session.
func PolicyPCR(rw io.ReadWriter, session tpmutil.Handle, expectedDigest []byte, sel PCRSelection) error {
	cmd, err := encodePolicyPCR(session, expectedDigest, sel)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, TagNoSessions, CmdPolicyPCR, tpmutil.RawBytes(cmd))
	return err
}

// PolicyGetDigest returns the current policyDigest of the session.
func PolicyGetDigest(rw io.ReadWriter, handle tpmutil.Handle) ([]byte, error) {
	resp, err := runCommand(rw, TagNoSessions, cmdPolicyGetDigest, handle)
	if err != nil {
		return nil, err
	}

	var digest []byte
	_, err = tpmutil.Unpack(resp, &digest)
	return digest, err
}

func encodeStartAuthSession(tpmKey, bindKey tpmutil.Handle, nonceCaller, secret []byte, se SessionType, sym, hashAlg Algorithm) ([]byte, error) {
	ha, err := tpmutil.Pack(tpmKey, bindKey)
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(nonceCaller, secret, se, sym, hashAlg)
	if err != nil {
		return nil, err
	}
	return concat(ha, params)
}

func decodeStartAuthSession(in []byte) (tpmutil.Handle, []byte, error) {
	var handle tpmutil.Handle
	var nonce []byte
	if _, err := tpmutil.Unpack(in, &handle, &nonce); err != nil {
		return 0, nil, err
	}
	return handle, nonce, nil
}

// StartAuthSession initializes a session object.
// Returns session handle and the initial nonce from the TPM.
func StartAuthSession(rw io.ReadWriter, tpmKey, bindKey tpmutil.Handle, nonceCaller, secret []byte, se SessionType, sym, hashAlg Algorithm) (tpmutil.Handle, []byte, error) {
	cmd, err := encodeStartAuthSession(tpmKey, bindKey, nonceCaller, secret, se, sym, hashAlg)
	if err != nil {
		return 0, nil, err
	}
	resp, err := runCommand(rw, TagNoSessions, cmdStartAuthSession, tpmutil.RawBytes(cmd))
	if err != nil {
		return 0, nil, err
	}
	return decodeStartAuthSession(resp)
}

func encodeUnseal(sessionHandle, itemHandle tpmutil.Handle, password string) ([]byte, error) {
	ha, err := tpmutil.Pack(itemHandle)
	if err != nil {
		return nil, err
	}
	auth, err := encodeAuthArea(AuthCommand{Session: sessionHandle, Attributes: AttrContinueSession, Auth: []byte(password)})
	if err != nil {
		return nil, err
	}
	return concat(ha, auth)
}

func decodeUnseal(in []byte) ([]byte, error) {
	var paramSize uint32
	var unsealed []byte

	if _, err := tpmutil.Unpack(in, &paramSize, &unsealed); err != nil {
		return nil, err
	}
	return unsealed, nil
}

// Unseal returns the data for a loaded sealed object.
func Unseal(rw io.ReadWriter, itemHandle tpmutil.Handle, password string) ([]byte, error) {
	return UnsealWithSession(rw, HandlePasswordSession, itemHandle, password)
}

// UnsealWithSession returns the data for a loaded sealed object.
func UnsealWithSession(rw io.ReadWriter, sessionHandle, itemHandle tpmutil.Handle, password string) ([]byte, error) {
	cmd, err := encodeUnseal(sessionHandle, itemHandle, password)
	if err != nil {
		return nil, err
	}
	resp, err := runCommand(rw, TagSessions, cmdUnseal, tpmutil.RawBytes(cmd))
	if err != nil {
		return nil, err
	}
	return decodeUnseal(resp)
}

func encodeQuote(signingHandle tpmutil.Handle, parentPassword, ownerPassword string, toQuote []byte, sel PCRSelection, sigAlg Algorithm) ([]byte, error) {
	ha, err := tpmutil.Pack(signingHandle)
	if err != nil {
		return nil, err
	}
	auth, err := encodeAuthArea(AuthCommand{Session: HandlePasswordSession, Attributes: AttrContinueSession, Auth: []byte(parentPassword)})
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(toQuote, sigAlg)
	if err != nil {
		return nil, err
	}
	pcrs, err := encodeTPMLPCRSelection(sel)
	if err != nil {
		return nil, err
	}
	return concat(ha, auth, params, pcrs)
}

func decodeQuote(in []byte) ([]byte, *Signature, error) {
	buf := bytes.NewBuffer(in)
	var paramSize uint32
	var attest []byte
	if err := tpmutil.UnpackBuf(buf, &paramSize, &attest); err != nil {
		return nil, nil, err
	}
	sig, err := decodeSignature(buf)
	return attest, sig, err
}

// Quote returns a quote of PCR values. A quote is a signature of the PCR
// values, created using a signing TPM key.
//
// Returns attestation data and the signature.
//
// Note: currently only RSA signatures are supported.
func Quote(rw io.ReadWriter, signingHandle tpmutil.Handle, parentPassword, ownerPassword string, toQuote []byte, sel PCRSelection, sigAlg Algorithm) ([]byte, *Signature, error) {
	cmd, err := encodeQuote(signingHandle, parentPassword, ownerPassword, toQuote, sel, sigAlg)
	if err != nil {
		return nil, nil, err
	}
	resp, err := runCommand(rw, TagSessions, cmdQuote, tpmutil.RawBytes(cmd))
	if err != nil {
		return nil, nil, err
	}
	return decodeQuote(resp)
}

func encodeActivateCredential(auth []AuthCommand, activeHandle tpmutil.Handle, keyHandle tpmutil.Handle, credBlob, secret []byte) ([]byte, error) {
	ha, err := tpmutil.Pack(activeHandle, keyHandle)
	if err != nil {
		return nil, err
	}
	a, err := encodeAuthArea(auth...)
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(credBlob, secret)
	if err != nil {
		return nil, err
	}
	return concat(ha, a, params)
}

func decodeActivateCredential(in []byte) ([]byte, error) {
	var paramSize uint32
	var certInfo []byte

	if _, err := tpmutil.Unpack(in, &paramSize, &certInfo); err != nil {
		return nil, err
	}
	return certInfo, nil
}

// ActivateCredential associates an object with a credential.
// Returns decrypted certificate information.
func ActivateCredential(rw io.ReadWriter, activeHandle, keyHandle tpmutil.Handle, activePassword, protectorPassword string, credBlob, secret []byte) ([]byte, error) {
	return ActivateCredentialUsingAuth(rw, []AuthCommand{
		{Session: HandlePasswordSession, Attributes: AttrContinueSession, Auth: []byte(activePassword)},
		{Session: HandlePasswordSession, Attributes: AttrContinueSession, Auth: []byte(protectorPassword)},
	}, activeHandle, keyHandle, credBlob, secret)
}

// ActivateCredentialUsingAuth associates an object with a credential, using the
// given set of authorizations. Two authorization must be provided.
// Returns decrypted certificate information.
func ActivateCredentialUsingAuth(rw io.ReadWriter, auth []AuthCommand, activeHandle, keyHandle tpmutil.Handle, credBlob, secret []byte) ([]byte, error) {
	if len(auth) != 2 {
		return nil, fmt.Errorf("len(auth) = %d, want 2", len(auth))
	}

	cmd, err := encodeActivateCredential(auth, activeHandle, keyHandle, credBlob, secret)
	if err != nil {
		return nil, err
	}
	resp, err := runCommand(rw, TagSessions, cmdActivateCredential, tpmutil.RawBytes(cmd))
	if err != nil {
		return nil, err
	}
	return decodeActivateCredential(resp)
}

func encodeMakeCredential(protectorHandle tpmutil.Handle, credential, activeName []byte) ([]byte, error) {
	ha, err := tpmutil.Pack(protectorHandle)
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(credential, activeName)
	if err != nil {
		return nil, err
	}
	return concat(ha, params)
}

func decodeMakeCredential(in []byte) ([]byte, []byte, error) {
	var credBlob []byte
	var encryptedSecret []byte

	if _, err := tpmutil.Unpack(in, &credBlob, &encryptedSecret); err != nil {
		return nil, nil, err
	}
	return credBlob, encryptedSecret, nil
}

// MakeCredential creates an encrypted credential for use in MakeCredential.
// Returns encrypted credential and wrapped secret used to encrypt it.
func MakeCredential(rw io.ReadWriter, protectorHandle tpmutil.Handle, credential, activeName []byte) ([]byte, []byte, error) {
	cmd, err := encodeMakeCredential(protectorHandle, credential, activeName)
	if err != nil {
		return nil, nil, err
	}
	resp, err := runCommand(rw, TagNoSessions, cmdMakeCredential, tpmutil.RawBytes(cmd))
	if err != nil {
		return nil, nil, err
	}
	return decodeMakeCredential(resp)
}

func encodeEvictControl(ownerAuth string, owner, objectHandle, persistentHandle tpmutil.Handle) ([]byte, error) {
	ha, err := tpmutil.Pack(owner, objectHandle)
	if err != nil {
		return nil, err
	}
	auth, err := encodeAuthArea(AuthCommand{Session: HandlePasswordSession, Attributes: AttrContinueSession, Auth: []byte(ownerAuth)})
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(persistentHandle)
	if err != nil {
		return nil, err
	}
	return concat(ha, auth, params)
}

// EvictControl toggles persistence of an object within the TPM.
func EvictControl(rw io.ReadWriter, ownerAuth string, owner, objectHandle, persistentHandle tpmutil.Handle) error {
	cmd, err := encodeEvictControl(ownerAuth, owner, objectHandle, persistentHandle)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, TagSessions, cmdEvictControl, tpmutil.RawBytes(cmd))
	return err
}

// ContextSave returns an encrypted version of the session, object or sequence
// context for storage outside of the TPM. The handle references context to
// store.
func ContextSave(rw io.ReadWriter, handle tpmutil.Handle) ([]byte, error) {
	return runCommand(rw, TagNoSessions, cmdContextSave, handle)
}

// ContextLoad reloads context data created by ContextSave.
func ContextLoad(rw io.ReadWriter, saveArea []byte) (tpmutil.Handle, error) {
	resp, err := runCommand(rw, TagNoSessions, cmdContextLoad, tpmutil.RawBytes(saveArea))
	if err != nil {
		return 0, err
	}
	var handle tpmutil.Handle
	_, err = tpmutil.Unpack(resp, &handle)
	return handle, err
}

func encodeIncrementNV(handle tpmutil.Handle, authString string) ([]byte, error) {
	auth, err := encodeAuthArea(AuthCommand{Session: HandlePasswordSession, Attributes: AttrContinueSession, Auth: []byte(authString)})
	if err != nil {
		return nil, err
	}
	out, err := tpmutil.Pack(handle, handle)
	if err != nil {
		return nil, err
	}
	return concat(out, auth)
}

// NVIncrement increments a counter in NVRAM.
func NVIncrement(rw io.ReadWriter, handle tpmutil.Handle, authString string) error {
	cmd, err := encodeIncrementNV(handle, authString)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, TagSessions, cmdIncrementNVCounter, tpmutil.RawBytes(cmd))
	return err
}

func encodeUndefineSpace(ownerAuth string, owner, index tpmutil.Handle) ([]byte, error) {
	auth, err := encodeAuthArea(AuthCommand{Session: HandlePasswordSession, Attributes: AttrContinueSession, Auth: []byte(ownerAuth)})
	if err != nil {
		return nil, err
	}
	out, err := tpmutil.Pack(owner, index)
	if err != nil {
		return nil, err
	}
	return concat(out, auth)
}

// NVUndefineSpace removes an index from TPM's NV storage.
func NVUndefineSpace(rw io.ReadWriter, ownerAuth string, owner, index tpmutil.Handle) error {
	cmd, err := encodeUndefineSpace(ownerAuth, owner, index)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, TagSessions, cmdUndefineSpace, tpmutil.RawBytes(cmd))
	return err
}

func encodeDefineSpace(owner, handle tpmutil.Handle, ownerAuth, authVal string, attributes NVAttr, policy []byte, dataSize uint16) ([]byte, error) {
	ha, err := tpmutil.Pack(owner)
	if err != nil {
		return nil, err
	}
	auth, err := encodeAuthArea(AuthCommand{Session: HandlePasswordSession, Attributes: AttrContinueSession, Auth: []byte(ownerAuth)})
	if err != nil {
		return nil, err
	}
	publicInfo, err := tpmutil.Pack(handle, AlgSHA1, attributes, policy, dataSize)
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack([]byte(authVal), publicInfo)
	if err != nil {
		return nil, err
	}
	return concat(ha, auth, params)
}

// NVDefineSpace creates an index in TPM's NV storage.
func NVDefineSpace(rw io.ReadWriter, owner, handle tpmutil.Handle, ownerAuth, authString string, policy []byte, attributes NVAttr, dataSize uint16) error {
	cmd, err := encodeDefineSpace(owner, handle, ownerAuth, authString, attributes, policy, dataSize)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, TagSessions, cmdDefineSpace, tpmutil.RawBytes(cmd))
	return err
}

func encodeWriteNV(owner, handle tpmutil.Handle, authString string, data []byte, offset uint16) ([]byte, error) {
	auth, err := encodeAuthArea(AuthCommand{Session: HandlePasswordSession, Attributes: AttrContinueSession, Auth: []byte(authString)})
	if err != nil {
		return nil, err
	}
	out, err := tpmutil.Pack(owner, handle)
	if err != nil {
		return nil, err
	}
	buf, err := tpmutil.Pack(data, offset)
	if err != nil {
		return nil, err
	}
	return concat(out, auth, buf)
}

// NVWrite writes data into the TPM's NV storage.
func NVWrite(rw io.ReadWriter, owner, handle tpmutil.Handle, authString string, data []byte, offset uint16) error {
	cmd, err := encodeWriteNV(owner, handle, authString, data, offset)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, TagSessions, cmdWriteNV, tpmutil.RawBytes(cmd))
	return err
}

func decodeNVReadPublic(in []byte) (NVPublic, error) {
	var pub NVPublic
	var buf []byte
	if _, err := tpmutil.Unpack(in, &buf); err != nil {
		return pub, err
	}
	_, err := tpmutil.Unpack(buf, &pub)
	return pub, err
}

// NVReadPublic reads the public data of an NV index.
func NVReadPublic(rw io.ReadWriter, index tpmutil.Handle) (NVPublic, error) {
	// Read public area to determine data size.
	resp, err := runCommand(rw, TagNoSessions, cmdReadPublicNV, index)
	if err != nil {
		return NVPublic{}, err
	}
	return decodeNVReadPublic(resp)
}

func decodeNVRead(in []byte) ([]byte, error) {
	var sessionAttributes uint32
	var data []byte
	if _, err := tpmutil.Unpack(in, &sessionAttributes, &data); err != nil {
		return nil, err
	}
	return data, nil
}

func encodeNVRead(nvIndex, authHandle tpmutil.Handle, password string, offset, dataSize uint16) ([]byte, error) {
	handles, err := tpmutil.Pack(authHandle, nvIndex)
	if err != nil {
		return nil, err
	}
	auth, err := encodeAuthArea(AuthCommand{Session: HandlePasswordSession, Attributes: AttrContinueSession, Auth: []byte(password)})
	if err != nil {
		return nil, err
	}

	params, err := tpmutil.Pack(dataSize, offset)
	if err != nil {
		return nil, err
	}

	return concat(handles, auth, params)
}

// NVRead reads a full data blob from an NV index. This function is
// deprecated; use NVReadEx instead.
func NVRead(rw io.ReadWriter, index tpmutil.Handle) ([]byte, error) {
	return NVReadEx(rw, index, index, "", 0)
}

// NVReadEx reads a full data blob from an NV index, using the given
// authorization handle. NVRead commands are done in blocks of blockSize.
// If blockSize is 0, the TPM is queried for TPM_PT_NV_BUFFER_MAX, and that
// value is used.
func NVReadEx(rw io.ReadWriter, index, authHandle tpmutil.Handle, password string, blockSize int) ([]byte, error) {
	if blockSize == 0 {
		readBuff, _, err := GetCapability(rw, CapabilityTPMProperties, 1, uint32(NVMaxBufferSize))
		if err != nil {
			return nil, fmt.Errorf("GetCapability for TPM_PT_NV_BUFFER_MAX failed: %v", err)
		}
		if len(readBuff) != 1 {
			return nil, fmt.Errorf("could not determine NVRAM read/write buffer size")
		}
		rb, ok := readBuff[0].(TaggedProperty)
		if !ok {
			return nil, fmt.Errorf("GetCapability returned unexpected type: %T, expected TaggedProperty", readBuff[0])
		}
		blockSize = int(rb.Value)
	}

	// Read public area to determine data size.
	pub, err := NVReadPublic(rw, index)
	if err != nil {
		return nil, fmt.Errorf("decoding NV_ReadPublic response: %v", err)
	}

	// Read the NVRAM area in blocks.
	outBuff := make([]byte, 0, int(pub.DataSize))
	for len(outBuff) < int(pub.DataSize) {
		readSize := blockSize
		if readSize > (int(pub.DataSize) - len(outBuff)) {
			readSize = int(pub.DataSize) - len(outBuff)
		}

		cmd, err := encodeNVRead(index, authHandle, password, uint16(len(outBuff)), uint16(readSize))
		if err != nil {
			return nil, fmt.Errorf("building NV_Read command: %v", err)
		}
		resp, err := runCommand(rw, TagSessions, cmdReadNV, tpmutil.RawBytes(cmd))
		if err != nil {
			return nil, fmt.Errorf("running NV_Read command (cursor=%d,size=%d): %v", len(outBuff), readSize, err)
		}
		data, err := decodeNVRead(resp)
		if err != nil {
			return nil, fmt.Errorf("decoding NV_Read command: %v", err)
		}
		outBuff = append(outBuff, data...)
	}
	return outBuff, nil
}

// Hash computes a hash of data in buf using the TPM.
func Hash(rw io.ReadWriter, alg Algorithm, buf []byte) ([]byte, error) {
	resp, err := runCommand(rw, TagNoSessions, cmdHash, buf, alg, HandleNull)
	if err != nil {
		return nil, err
	}

	var digest []byte
	if _, err = tpmutil.Unpack(resp, &digest); err != nil {
		return nil, err
	}
	return digest, nil
}

// Startup initializes a TPM (usually done by the OS).
func Startup(rw io.ReadWriter, typ StartupType) error {
	_, err := runCommand(rw, TagNoSessions, cmdStartup, typ)
	return err
}

// Shutdown shuts down a TPM (usually done by the OS).
func Shutdown(rw io.ReadWriter, typ StartupType) error {
	_, err := runCommand(rw, TagNoSessions, cmdShutdown, typ)
	return err
}

func encodeSign(key tpmutil.Handle, password string, digest []byte, sigScheme *SigScheme) ([]byte, error) {
	ha, err := tpmutil.Pack(key)
	if err != nil {
		return nil, err
	}
	auth, err := encodeAuthArea(AuthCommand{Session: HandlePasswordSession, Attributes: AttrContinueSession, Auth: []byte(password)})
	if err != nil {
		return nil, err
	}
	d, err := tpmutil.Pack(digest)
	if err != nil {
		return nil, err
	}
	s, err := sigScheme.encode()
	if err != nil {
		return nil, err
	}
	hc, err := tpmutil.Pack(TagHashCheck)
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(HandleNull, []byte(nil))
	if err != nil {
		return nil, err
	}

	return concat(ha, auth, d, s, hc, params)
}

func decodeSign(buf []byte) (*Signature, error) {
	in := bytes.NewBuffer(buf)
	var paramSize uint32
	if err := tpmutil.UnpackBuf(in, &paramSize); err != nil {
		return nil, err
	}
	return decodeSignature(in)
}

// Sign computes a signature for digest using a given loaded key. Signature
// algorithm depends on the key type.
func Sign(rw io.ReadWriter, key tpmutil.Handle, password string, digest []byte, sigScheme *SigScheme) (*Signature, error) {
	cmd, err := encodeSign(key, password, digest, sigScheme)
	if err != nil {
		return nil, err
	}
	resp, err := runCommand(rw, TagSessions, cmdSign, tpmutil.RawBytes(cmd))
	if err != nil {
		return nil, err
	}
	return decodeSign(resp)
}

func encodeCertify(parentAuth, ownerAuth string, object, signer tpmutil.Handle, qualifyingData []byte) ([]byte, error) {
	ha, err := tpmutil.Pack(object, signer)
	if err != nil {
		return nil, err
	}

	auth, err := encodeAuthArea(AuthCommand{Session: HandlePasswordSession, Attributes: AttrContinueSession, Auth: []byte(parentAuth)}, AuthCommand{Session: HandlePasswordSession, Attributes: AttrContinueSession, Auth: []byte(ownerAuth)})
	if err != nil {
		return nil, err
	}

	scheme := tpmtSigScheme{AlgRSASSA, AlgSHA256}
	// Use signing key's scheme.
	params, err := tpmutil.Pack(qualifyingData, scheme)
	if err != nil {
		return nil, err
	}
	return concat(ha, auth, params)
}

func decodeCertify(resp []byte) ([]byte, []byte, error) {
	var paramSize uint32
	var attest, signature []byte
	var sigAlg, hashAlg Algorithm
	if _, err := tpmutil.Unpack(resp, &paramSize, &attest, &sigAlg, &hashAlg, &signature); err != nil {
		return nil, nil, err
	}
	return attest, signature, nil
}

// Certify generates a signature of a loaded TPM object with a signing key
// signer. Returned values are: attestation data (TPMS_ATTEST), signature and
// error, if any.
func Certify(rw io.ReadWriter, parentAuth, ownerAuth string, object, signer tpmutil.Handle, qualifyingData []byte) ([]byte, []byte, error) {
	cmd, err := encodeCertify(parentAuth, ownerAuth, object, signer, qualifyingData)
	if err != nil {
		return nil, nil, err
	}
	resp, err := runCommand(rw, TagSessions, cmdCertify, tpmutil.RawBytes(cmd))
	if err != nil {
		return nil, nil, err
	}
	return decodeCertify(resp)
}

func encodeCertifyCreation(objectAuth string, object, signer tpmutil.Handle, qualifyingData, creationHash []byte, scheme SigScheme, ticket *Ticket) ([]byte, error) {
	handles, err := tpmutil.Pack(signer, object)
	if err != nil {
		return nil, err
	}
	auth, err := encodeAuthArea(AuthCommand{Session: HandlePasswordSession, Attributes: AttrContinueSession, Auth: []byte(objectAuth)})
	if err != nil {
		return nil, err
	}
	s, err := scheme.encode()
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(qualifyingData, creationHash, tpmutil.RawBytes(s), ticket)
	if err != nil {
		return nil, err
	}
	return concat(handles, auth, params)
}

// CertifyCreation generates a signature of a newly-created &
// loaded TPM object, using signer as the signing key.
func CertifyCreation(rw io.ReadWriter, objectAuth string, object, signer tpmutil.Handle, qualifyingData, creationHash []byte, sigScheme SigScheme, creationTicket *Ticket) (attestation, signature []byte, err error) {
	cmd, err := encodeCertifyCreation(objectAuth, object, signer, qualifyingData, creationHash, sigScheme, creationTicket)
	if err != nil {
		return nil, nil, err
	}
	resp, err := runCommand(rw, TagSessions, cmdCertifyCreation, tpmutil.RawBytes(cmd))
	if err != nil {
		return nil, nil, err
	}
	return decodeCertify(resp)
}

func runCommand(rw io.ReadWriter, tag tpmutil.Tag, cmd tpmutil.Command, in ...interface{}) ([]byte, error) {
	resp, code, err := tpmutil.RunCommand(rw, tag, cmd, in...)
	if err != nil {
		return nil, err
	}
	return resp, decodeResponse(code)
}

// concat is a helper for encoding functions that separately encode handle,
// auth and param areas. A nil error is always returned, so that callers can
// simply return concat(a, b, c).
func concat(chunks ...[]byte) ([]byte, error) {
	return bytes.Join(chunks, nil), nil
}

func encodePCRExtend(pcr tpmutil.Handle, hashAlg Algorithm, hash tpmutil.RawBytes, password string) ([]byte, error) {
	ha, err := tpmutil.Pack(pcr)
	if err != nil {
		return nil, err
	}
	auth, err := encodeAuthArea(AuthCommand{Session: HandlePasswordSession, Attributes: AttrContinueSession, Auth: []byte(password)})
	if err != nil {
		return nil, err
	}
	pcrCount := uint32(1)
	extend, err := tpmutil.Pack(pcrCount, hashAlg, hash)
	if err != nil {
		return nil, err
	}
	return concat(ha, auth, extend)
}

// PCRExtend extends a value into the selected PCR
func PCRExtend(rw io.ReadWriter, pcr tpmutil.Handle, hashAlg Algorithm, hash []byte, password string) error {
	cmd, err := encodePCRExtend(pcr, hashAlg, hash, password)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, TagSessions, cmdPCRExtend, tpmutil.RawBytes(cmd))
	return err
}

// ReadPCR reads the value of the given PCR.
func ReadPCR(rw io.ReadWriter, pcr int, hashAlg Algorithm) ([]byte, error) {
	pcrSelection := PCRSelection{
		Hash: hashAlg,
		PCRs: []int{pcr},
	}
	pcrVals, err := ReadPCRs(rw, pcrSelection)
	if err != nil {
		return nil, fmt.Errorf("unable to read PCRs from TPM: %v", err)
	}
	pcrVal, present := pcrVals[pcr]
	if !present {
		return nil, fmt.Errorf("PCR %d value missing from response", pcr)
	}
	return pcrVal, nil
}
