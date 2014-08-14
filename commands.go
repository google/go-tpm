// Copyright (c) 2014, Google Inc. All rights reserved.
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

package tpm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/golang/glog"
)

// Supported TPM commands.
const (
	tagPCRInfoLong     uint16 = 0x06
	tagRQUCommand      uint16 = 0x00C1
	tagRQUAuth1Command uint16 = 0x00C2
	tagRQUAuth2Command uint16 = 0x00C3
	tagRSPCommand      uint16 = 0x00C4
	tagRSPAuth1Command uint16 = 0x00C5
	tagRSPAuth2Command uint16 = 0x00C6
)

// Supported TPM operations.
const (
	ordOIAP          uint32 = 0x0000000A
	ordOSAP          uint32 = 0x0000000B
	ordPCRRead       uint32 = 0x00000015
	ordSeal          uint32 = 0x00000017
	ordUnseal        uint32 = 0x00000018
	ordGetPubKey     uint32 = 0x00000021
	ordQuote2        uint32 = 0x0000003E
	ordLoadKey2      uint32 = 0x00000041
	ordGetRandom     uint32 = 0x00000046
	ordFlushSpecific uint32 = 0x000000BA
)

// Entity types
const (
	etKeyHandle uint16 = 0x0001
	etSRK       uint16 = 0x0004
	etKey       uint16 = 0x0005
)

// Resource types
const (
	rtKey   uint32 = 0x00000001
	rtAuth  uint32 = 0x00000002
	rtHash  uint32 = 0x00000003
	rtTrans uint32 = 0x00000004
)

// A Handle is a 32-bit unsigned integer.
type Handle uint32

// Entity values
const (
	khSRK Handle = 0x40000000
)

// A commandHeader is the header for a TPM command.
type commandHeader struct {
	Tag  uint16
	Size uint32
	Cmd  uint32
}

// String returns a string version of a commandHeader
func (ch commandHeader) String() string {
	return fmt.Sprintf("commandHeader{Tag: %x, Size: %x, Cmd: %x}", ch.Tag, ch.Size, ch.Cmd)
}

// A responseHeader is a header for TPM responses.
type responseHeader struct {
	Tag  uint16
	Size uint32
	Res  uint32
}

// String returns a string representation of a responseHeader.
func (rh responseHeader) String() string {
	return fmt.Sprintf("responseHeader{Tag: %x, Size: %x, Res: %x", rh.Tag, rh.Size, rh.Res)
}

// maxTPMResponse is the largest possible response from the TPM. We need to know
// this because we don't always know the length of the TPM response, and
// /dev/tpm insists on giving it all back in a single value rather than
// returning a header and a body in separate responses.
const maxTPMResponse = 4096

// submitTPMRequest sends a structure to the TPM device file and gets results
// back, interpreting them as a new provided structure.
func submitTPMRequest(f *os.File, tag uint16, ord uint32, in []interface{}, out []interface{}) (uint32, error) {
	ch := commandHeader{tag, 0, ord}
	inb, err := packWithHeader(ch, in)
	if err != nil {
		return 0, err
	}

	if glog.V(2) {
		glog.Infof("TPM request:\n%x\n", inb)
	}
	if _, err := f.Write(inb); err != nil {
		return 0, err
	}

	// Try to read the whole thing, but handle the case where it's just a
	// ResponseHeader and not the body, since that's what happens in the error
	// case.
	var rh responseHeader
	rhSize := binary.Size(rh)
	outb := make([]byte, maxTPMResponse)
	outlen, err := f.Read(outb)
	if err != nil {
		return 0, err
	}

	// Resize the buffer to match the amount read from the TPM.
	outb = outb[:outlen]
	if glog.V(2) {
		glog.Infof("TPM response:\n%x\n", outb)
	}

	if err := unpack(outb[:rhSize], []interface{}{&rh}); err != nil {
		return 0, err
	}

	// Check success before trying to read the rest of the result.
	// Note that the command tag and its associated response tag differ by 3,
	// e.g., tagRQUCommand == 0x00C1, and tagRSPCommand == 0x00C4.
	if rh.Res != 0 {
		return rh.Res, tpmError(rh.Res)
	}

	if rh.Tag != ch.Tag+3 {
		return 0, errors.New("inconsistent tag returned by TPM. Expected " + strconv.Itoa(int(ch.Tag+3)) + " but got " + strconv.Itoa(int(rh.Tag)))
	}

	if rh.Size > uint32(rhSize) {
		if err := unpack(outb[rhSize:], out); err != nil {
			return 0, err
		}
	}

	return rh.Res, nil
}

// A nonce is a 20-byte value.
type nonce [20]byte

const nonceSize uint32 = 20

// An oiapResponse is a response to an OIAP command.
type oiapResponse struct {
	AuthHandle Handle
	NonceEven  nonce
}

// String returns a string representation of an oiapResponse.
func (opr oiapResponse) String() string {
	return fmt.Sprintf("oiapResponse{AuthHandle: %x, NonceEven: % x}", opr.AuthHandle, opr.NonceEven)
}

// Close flushes the auth handle associated with an OIAP session.
func (opr *oiapResponse) Close(f *os.File) error {
	return flushSpecific(f, opr.AuthHandle, rtAuth)
}

// oiap sends an OIAP command to the TPM and gets back an auth value and a
// nonce.
func oiap(f *os.File) (*oiapResponse, error) {
	var resp oiapResponse
	out := []interface{}{&resp}
	// In this case, we don't need to check ret, since all the information is
	// contained in err.
	if _, err := submitTPMRequest(f, tagRQUCommand, ordOIAP, nil, out); err != nil {
		return nil, err
	}

	return &resp, nil
}

// An osapCommand is a command sent for OSAP authentication.
type osapCommand struct {
	EntityType  uint16
	EntityValue Handle
	OddOSAP     nonce
}

// String returns a string representation of an osapCommand.
func (opc osapCommand) String() string {
	return fmt.Sprintf("osapCommand{EntityType: %x, EntityValue: %x, OddOSAP: % x}", opc.EntityType, opc.EntityValue, opc.OddOSAP)
}

// An osapResponse is a TPM reply to an osapCommand.
type osapResponse struct {
	AuthHandle Handle
	NonceEven  nonce
	EvenOSAP   nonce
}

// String returns a string representation of an osapResponse.
func (opr osapResponse) String() string {
	return fmt.Sprintf("osapResponse{AuthHandle: %x, NonceEven: % x, EvenOSAP: % x}", opr.AuthHandle, opr.NonceEven, opr.EvenOSAP)
}

// Close flushes the AuthHandle associated with an OSAP session.
func (opr *osapResponse) Close(f *os.File) error {
	return flushSpecific(f, opr.AuthHandle, rtAuth)
}

// osap sends an OSAPCommand to the TPM and gets back authentication
// information in an OSAPResponse.
func osap(f *os.File, osap *osapCommand) (*osapResponse, error) {
	in := []interface{}{osap}
	var resp osapResponse
	out := []interface{}{&resp}
	// In this case, we don't need to check the ret value, since all the
	// information is contained in err.
	if _, err := submitTPMRequest(f, tagRQUCommand, ordOSAP, in, out); err != nil {
		return nil, err
	}

	return &resp, nil
}

// A Digest is a 20-byte SHA1 value.
type digest [20]byte

const digestSize uint32 = 20

// An AuthValue is a 20-byte value used for authentication.
type authValue [20]byte

const authSize uint32 = 20

// A sealCommand is the command sent to the TPM to seal data.
type sealCommand struct {
	KeyHandle Handle
	EncAuth   authValue
}

// String returns a string representation of a sealCommand.
func (sc sealCommand) String() string {
	return fmt.Sprintf("sealCommand{KeyHandle: %x, EncAuth: % x}", sc.KeyHandle, sc.EncAuth)
}

// commandAuth stores the auth information sent with a command. Commands with
// tagRQUAuth1Command tags use one of these auth structures, and commands with
// tagRQUAuth2Command use two.
type commandAuth struct {
	AuthHandle  Handle
	NonceOdd    nonce
	ContSession byte
	Auth        authValue
}

// String returns a string representation of a sealCommandAuth.
func (ca commandAuth) String() string {
	return fmt.Sprintf("commandAuth{AuthHandle: %x, NonceOdd: % x, ContSession: %x, Auth: % x}", ca.AuthHandle, ca.NonceOdd, ca.ContSession, ca.Auth)
}

// responseAuth contains the auth information returned from a command.
type responseAuth struct {
	NonceEven   nonce
	ContSession byte
	Auth        authValue
}

// String returns a string representation of a responseAuth.
func (ra responseAuth) String() string {
	return fmt.Sprintf("responseAuth{NonceEven: % x, ContSession: %x, Auth: % x}", ra.NonceEven, ra.ContSession, ra.Auth)
}

// A tpmStoredData holds sealed data from the TPM.
type tpmStoredData struct {
	Version uint32
	Info    []byte
	Enc     []byte
}

// String returns a string representation of a tpmStoredData.
func (tsd tpmStoredData) String() string {
	return fmt.Sprintf("tpmStoreddata{Version: %x, Info: % x, Enc: % x\n", tsd.Version, tsd.Info, tsd.Enc)
}

// seal performs a seal operation on the TPM.
func seal(f *os.File, sc *sealCommand, pcrs *pcrInfoLong, data []byte, ca *commandAuth) (*tpmStoredData, *responseAuth, uint32, error) {
	pcrsize := binary.Size(pcrs)
	if pcrsize < 0 {
		return nil, nil, 0, errors.New("couldn't compute the size of a pcrInfoLong")
	}

	// TODO(tmroeder): special-case pcrInfoLong in pack/unpack so we don't have
	// to write out the length explicitly here.
	in := []interface{}{sc, uint32(pcrsize), pcrs, data, ca}

	var tsd tpmStoredData
	var ra responseAuth
	out := []interface{}{&tsd, &ra}
	ret, err := submitTPMRequest(f, tagRQUAuth1Command, ordSeal, in, out)
	if err != nil {
		return nil, nil, 0, err
	}

	return &tsd, &ra, ret, nil
}

// unseal data sealed by the TPM.
func unseal(f *os.File, keyHandle Handle, sealed *tpmStoredData, ca1 *commandAuth, ca2 *commandAuth) ([]byte, *responseAuth, *responseAuth, uint32, error) {
	in := []interface{}{keyHandle, sealed, ca1, ca2}
	var outb []byte
	var ra1 responseAuth
	var ra2 responseAuth
	out := []interface{}{&outb, &ra1, &ra2}
	ret, err := submitTPMRequest(f, tagRQUAuth2Command, ordUnseal, in, out)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	return outb, &ra1, &ra2, ret, nil
}

// flushSpecific removes a handle from the TPM. Note that removing a handle
// doesn't require any authentication.
func flushSpecific(f *os.File, handle Handle, resourceType uint32) error {
	// In this case, all the information is in err, so we don't check the
	// specific return-value details.
	_, err := submitTPMRequest(f, tagRQUCommand, ordFlushSpecific, []interface{}{handle, resourceType}, nil)
	return err
}

// These are the parameters of a TPM key.
type keyParms struct {
	AlgID     uint32
	EncScheme uint16
	SigScheme uint16
	Parms     []byte // Serialized rsaKeyParms or symmetricKeyParms.
}

// An rsaKeyParms encodes the length of the RSA prime in bits, the number of
// primes in its factored form, and the exponent used for public-key
// encryption.
type rsaKeyParms struct {
	KeyLength uint32
	NumPrimes uint32
	Exponent  []byte
}

type symmetricKeyParms struct {
	KeyLength uint32
	BlockSize uint32
	IV        []byte
}

// A key is a TPM representation of a key.
type key struct {
	Version        uint32
	KeyUsage       uint16
	KeyFlags       uint32
	AuthDataUsage  byte
	AlgorithmParms keyParms
	PCRInfo        []byte
	PubKey         []byte
	EncData        []byte
}

// A key12 is a newer TPM representation of a key.
type key12 struct {
	Tag            uint16
	Zero           uint16 // Always all 0.
	KeyUsage       uint16
	KeyFlags       uint32
	AuthDataUsage  byte
	AlgorithmParms keyParms
	PCRInfo        []byte // This must be a serialization of a pcrInfoLong.
	PubKey         []byte
	EncData        []byte
}

// A pubKey represents a public key known to the TPM.
type pubKey struct {
	AlgorithmParms keyParms
	Key            []byte
}

// loadKey2 loads a key into the TPM. It's a tagRQUAuth1Command, so it only
// needs one auth parameter.
func loadKey2(f *os.File, k *key, ca *commandAuth) (Handle, *responseAuth, uint32, error) {
	// We always load our keys with the SRK as the parent key.
	in := []interface{}{khSRK, k, ca}
	var keyHandle Handle
	var ra responseAuth
	out := []interface{}{&keyHandle, &ra}
	if glog.V(2) {
		glog.Info("About to submit the TPM request for loadKey2")
	}

	ret, err := submitTPMRequest(f, tagRQUAuth1Command, ordLoadKey2, in, out)
	if err != nil {
		return 0, nil, 0, err
	}

	if glog.V(2) {
		glog.Info("Received a good response for loadKey2")
	}

	return keyHandle, &ra, ret, nil
}

// getPubKey gets a public key from the TPM
func getPubKey(f *os.File, keyHandle Handle, ca *commandAuth) (*pubKey, *responseAuth, uint32, error) {
	in := []interface{}{keyHandle, ca}
	var pk pubKey
	var ra responseAuth
	out := []interface{}{&pk, &ra}
	ret, err := submitTPMRequest(f, tagRQUAuth1Command, ordGetPubKey, in, out)
	if err != nil {
		return nil, nil, 0, err
	}

	return &pk, &ra, ret, nil
}

// quote2 signs arbitrary data under a given set of PCRs and using a key
// specified by keyHandle. It returns information about the PCRs it signed
// under, the signature, auth information, and optionally information about the
// TPM itself. Note that the input to quote2 must be exactly 20 bytes, so it is
// normally the SHA1 hash of the data.
func quote2(f *os.File, keyHandle Handle, hash [20]byte, pcrs *pcrSelection, addVersion byte, ca *commandAuth) (*pcrInfoShort, *capVersionInfo, []byte, []byte, *responseAuth, uint32, error) {
	in := []interface{}{keyHandle, hash, pcrs, addVersion, ca}
	var pcrShort pcrInfoShort
	var capInfo capVersionInfo
	var capBytes []byte
	var sig []byte
	var ra responseAuth
	out := []interface{}{&pcrShort, &capBytes, &sig, &ra}
	ret, err := submitTPMRequest(f, tagRQUAuth1Command, ordQuote2, in, out)
	if err != nil {
		return nil, nil, nil, nil, nil, 0, err
	}

	// Deserialize the capInfo, if any.
	if len(capBytes) == 0 {
		return &pcrShort, nil, capBytes, sig, &ra, ret, nil
	}

	fmt.Println("Successfully got the data. Sig has len", len(sig))

	size := binary.Size(capInfo.CapVersionFixed)
	fmt.Println("fixed size is", size)
	fmt.Println("capbytes size is", len(capBytes))
	capInfo.VendorSpecific = make([]byte, len(capBytes)-size)
	if err := unpack(capBytes[:size], []interface{}{&capInfo.CapVersionFixed}); err != nil {
		return nil, nil, nil, nil, nil, 0, err
	}

	copy(capInfo.VendorSpecific, capBytes[size:])

	return &pcrShort, &capInfo, capBytes, sig, &ra, ret, nil
}
