package tpm2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"

	"github.com/google/go-tpm/direct/helpers"
	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/structures/tpma"
	"github.com/google/go-tpm/direct/structures/tpmi"
	"github.com/google/go-tpm/direct/structures/tpms"
	"github.com/google/go-tpm/direct/structures/tpmt"
	"github.com/google/go-tpm/direct/structures/tpmu"
	legacy "github.com/google/go-tpm/tpm2"
)

// Session represents a session in the TPM.
type Session interface {
	// Initializes the session, if needed. Has no effect if not needed or
	// already done. Some types of sessions may need to be initialized
	// just-in-time, e.g., to support calling patterns that help the user
	// securely authorize their actions without writing a lot of code.
	Init(tpm *TPM) error
	// Cleans up the session, if needed.
	// Some types of session need to be cleaned up if the command failed,
	// again to support calling patterns that help the user securely
	// authorize their actions without writing a lot of code.
	CleanupFailure(tpm *TPM) error
	// The last nonceTPM for this session.
	NonceTPM() tpm2b.Nonce
	// Updates nonceCaller to a new random value.
	NewNonceCaller() error
	// Computes the authorization HMAC for the session.
	// If this is the first authorization session for a command, and
	// there is another session (or sessions) for parameter
	// decryption and/or encryption, then addNonces contains the
	// nonceTPMs from each of them, respectively (see Part 1, 19.6.5)
	Authorize(cc tpm.CC, parms, addNonces []byte, names []tpm2b.Name, authIndex int) (*tpms.AuthCommand, error)
	// Validates the response for the session.
	// Updates NonceTPM for the session.
	Validate(rc tpm.RC, cc tpm.CC, parms []byte, names []tpm2b.Name, authIndex int, auth *tpms.AuthResponse) error
	// Returns true if this is an encryption session.
	IsEncryption() bool
	// Returns true if this is a decryption session.
	IsDecryption() bool
	// If this session is used for parameter decryption, encrypts the
	// parameter. Otherwise, does not modify the parameter.
	Encrypt(parameter []byte) error
	// If this session is used for parameter encryption, encrypts the
	// parameter. Otherwise, does not modify the parameter.
	Decrypt(parameter []byte) error
	// Returns the handle value of this session.
	Handle() tpm.Handle
}

// CPHash calculates the TPM command parameter hash for a given Command.
// N.B. Authorization sessions on handles are ignored, but names aren't.
func CPHash(alg tpmi.AlgHash, cmd Command) (*tpm2b.Digest, error) {
	cc := cmd.Command()
	names, err := cmdNames(cmd)
	if err != nil {
		return nil, err
	}
	parms, err := cmdParameters(cmd, nil)
	if err != nil {
		return nil, err
	}
	digest, err := cpHash(alg, cc, names, parms)
	if err != nil {
		return nil, err
	}
	return &tpm2b.Digest{
		Buffer: digest,
	}, nil
}

// cpHash calculates the TPM command parameter hash.
// cpHash = hash(CC || names || parms)
func cpHash(alg tpmi.AlgHash, cc tpm.CC, names []tpm2b.Name, parms []byte) ([]byte, error) {
	ha, err := alg.Hash()
	if err != nil {
		return nil, err
	}
	h := ha.New()
	binary.Write(h, binary.BigEndian, cc)
	for _, name := range names {
		h.Write(name.Buffer)
	}
	h.Write(parms)
	return h.Sum(nil), nil
}

// rpHash calculates the TPM response parameter hash.
// rpHash = hash(RC || CC || parms)
func rpHash(alg tpmi.AlgHash, rc tpm.RC, cc tpm.CC, parms []byte) ([]byte, error) {
	ha, err := alg.Hash()
	if err != nil {
		return nil, err
	}
	h := ha.New()
	binary.Write(h, binary.BigEndian, rc)
	binary.Write(h, binary.BigEndian, cc)
	h.Write(parms)
	return h.Sum(nil), nil
}

// pwSession represents a password-pseudo-session.
type pwSession struct {
	auth []byte
}

// PasswordAuth assembles a password pseudo-session with the given auth value.
func PasswordAuth(auth []byte) Session {
	return &pwSession{
		auth: auth,
	}
}

// Init is not required and has no effect for a password session.
func (s *pwSession) Init(tpm *TPM) error { return nil }

// Cleanup is not required and has no effect for a password session.
func (s *pwSession) CleanupFailure(tpm *TPM) error { return nil }

// NonceTPM normally returns the last nonceTPM value from the session.
// Since a password session is a pseudo-session with the auth value stuffed
// in where the HMAC should go, this is not used.
func (s *pwSession) NonceTPM() tpm2b.Nonce { return tpm2b.Nonce{} }

// NewNonceCaller updates the nonceCaller for this session.
// Password sessions don't have nonces.
func (s *pwSession) NewNonceCaller() error { return nil }

// Computes the authorization structure for the session.
func (s *pwSession) Authorize(cc tpm.CC, parms, addNonces []byte, _ []tpm2b.Name, _ int) (*tpms.AuthCommand, error) {
	return &tpms.AuthCommand{
		Handle:     tpm.RSPW,
		Nonce:      tpm2b.Nonce{},
		Attributes: tpma.Session{},
		Authorization: tpm2b.Data{
			Buffer: s.auth,
		},
	}, nil
}

// Validates the response session structure for the session.
func (s *pwSession) Validate(rc tpm.RC, cc tpm.CC, parms []byte, _ []tpm2b.Name, _ int, auth *tpms.AuthResponse) error {
	if len(auth.Nonce.Buffer) != 0 {
		return fmt.Errorf("expected empty nonce in response auth to PW session, got %x", auth.Nonce)
	}
	expectedAttrs := tpma.Session{
		ContinueSession: true,
	}
	if auth.Attributes != expectedAttrs {
		return fmt.Errorf("expected only ContinueSession in response auth to PW session, got %v", auth.Attributes)
	}
	if len(auth.Authorization.Buffer) != 0 {
		return fmt.Errorf("expected empty HMAC in response auth to PW session, got %x", auth.Authorization)
	}
	return nil
}

// IsEncryption returns true if this is an encryption session.
// Password sessions can't be used for encryption.
func (s *pwSession) IsEncryption() bool { return false }

// IsDecryption returns true if this is a decryption session.
// Password sessions can't be used for decryption.
func (s *pwSession) IsDecryption() bool { return false }

// If this session is used for parameter decryption, encrypts the
// parameter. Otherwise, does not modify the parameter.
// Password sessions can't be used for decryption.
func (s *pwSession) Encrypt(parameter []byte) error { return nil }

// If this session is used for parameter encryption, encrypts the
// parameter. Otherwise, does not modify the parameter.
// Password sessions can't be used for encryption.
func (s *pwSession) Decrypt(parameter []byte) error { return nil }

// Handle returns the handle value associated with this session.
// In the case of a password session, this is always TPM_RS_PW.
func (s *pwSession) Handle() tpm.Handle { return tpm.RSPW }

// sessionOptions represents extra options used when setting up an HMAC or policy session.
type sessionOptions struct {
	auth       []byte
	password   bool
	bindHandle tpmi.DHEntity
	bindName   tpm2b.Name
	bindAuth   []byte
	saltHandle tpmi.DHObject
	saltPub    tpmt.Public
	attrs      tpma.Session
	symmetric  tpmt.SymDef
}

// defaultOptions represents the default options used when none are provided.
func defaultOptions() sessionOptions {
	return sessionOptions{
		symmetric: tpmt.SymDef{
			Algorithm: tpm.AlgNull,
		},
		bindHandle: tpm.RHNull,
		saltHandle: tpm.RHNull,
	}
}

// AuthOption is an option for setting up an auth session variadically.
type AuthOption func(*sessionOptions)

// Auth uses the session to prove knowledge of the object's auth value.
func Auth(auth []byte) AuthOption {
	return func(o *sessionOptions) {
		o.auth = auth
	}
}

// Password is a policy-session-only option that specifies to provide the
// object's auth value in place of the authorization HMAC when authorizing.
// For HMAC sessions, has the same effect as using Auth.
// Deprecated: This is not recommended and is only provided for completeness;
// use Auth instead.
func Password(auth []byte) AuthOption {
	return func(o *sessionOptions) {
		o.auth = auth
		o.password = true
	}
}

// Bound specifies that this session's session key should depend on the auth
// value of the given object.
func Bound(handle tpmi.DHEntity, name tpm2b.Name, auth []byte) AuthOption {
	return func(o *sessionOptions) {
		o.bindHandle = handle
		o.bindName = name
		o.bindAuth = auth
	}
}

// Salted specifies that this session's session key should depend on an
// encrypted seed value using the given public key.
// 'handle' must refer to a loaded RSA or ECC key.
func Salted(handle tpmi.DHObject, pub tpmt.Public) AuthOption {
	return func(o *sessionOptions) {
		o.saltHandle = handle
		o.saltPub = pub
	}
}

// parameterEncryptionDirection specifies whether the session-encrypted
// parameters are encrypted on the way into the TPM, out of the TPM, or both.
type parameterEncryptionDirection int

const (
	// EncryptIn specifies a decrypt session.
	EncryptIn parameterEncryptionDirection = 1 + iota
	// EncryptOut specifies an encrypt session.
	EncryptOut
	// EncryptInOut specifies a decrypt+encrypt session.
	EncryptInOut
)

// AESEncryption uses the session to encrypt the first parameter sent to/from
// the TPM.
// Note that only commands whose first command/response parameter is a 2B can
// support session encryption.
func AESEncryption(keySize tpm.KeyBits, dir parameterEncryptionDirection) AuthOption {
	return func(o *sessionOptions) {
		o.attrs.Decrypt = (dir == EncryptIn || dir == EncryptInOut)
		o.attrs.Encrypt = (dir == EncryptOut || dir == EncryptInOut)
		o.symmetric = tpmt.SymDef{
			Algorithm: tpm.AlgAES,
			KeyBits: tpmu.SymKeyBits{
				AES: helpers.NewKeyBits(keySize),
			},
			Mode: tpmu.SymMode{
				AES: helpers.NewAlgID(tpm.AlgCFB),
			},
		}
	}
}

// Audit uses the session to compute extra HMACs.
// An Audit session can be used with GetSessionAuditDigest to obtain attestation
// over a sequence of commands.
func Audit() AuthOption {
	return func(o *sessionOptions) {
		o.attrs.Audit = true
	}
}

// AuditExclusive is like an audit session, but even more powerful.
// This allows an audit session to additionally indicate that no other auditable
// commands were executed other than the ones described by the audit hash.
func AuditExclusive() AuthOption {
	return func(o *sessionOptions) {
		o.attrs.Audit = true
		o.attrs.AuditExclusive = true
	}
}

// hmacSession generally implements the HMAC session.
type hmacSession struct {
	sessionOptions
	hash       tpmi.AlgHash
	nonceSize  int
	handle     tpm.Handle
	sessionKey []byte
	// last nonceCaller
	nonceCaller tpm2b.Nonce
	// last nonceTPM
	nonceTPM tpm2b.Nonce
}

// HMAC sets up a just-in-time HMAC session that is used only once.
// A real session is created, but just in time and it is flushed when used.
func HMAC(hash tpmi.AlgHash, nonceSize int, opts ...AuthOption) Session {
	// Set up a one-off session that knows the auth value.
	sess := hmacSession{
		sessionOptions: defaultOptions(),
		hash:           hash,
		nonceSize:      nonceSize,
		handle:         tpm.RHNull,
	}
	for _, opt := range opts {
		opt(&sess.sessionOptions)
	}
	return &sess
}

// HMACSession sets up a reusable HMAC session that needs to be closed.
func HMACSession(t *TPM, hash tpmi.AlgHash, nonceSize int, opts ...AuthOption) (s Session, close func() error, err error) {
	// Set up a not-one-off session that knows the auth value.
	sess := hmacSession{
		sessionOptions: defaultOptions(),
		hash:           hash,
		nonceSize:      nonceSize,
		handle:         tpm.RHNull,
	}
	for _, opt := range opts {
		opt(&sess.sessionOptions)
	}
	// This session is reusable and is closed with the function we'll
	// return.
	sess.sessionOptions.attrs.ContinueSession = true

	// Initialize the session.
	if err := sess.Init(t); err != nil {
		return nil, nil, err
	}

	closer := func() error {
		fc := FlushContext{FlushHandle: sess.handle}
		_, err := fc.Execute(t)
		return err
	}

	return &sess, closer, nil
}

// Part 1, B.10.2
func getEncryptedSaltRSA(nameAlg tpmi.AlgHash, parms *tpms.RSAParms, pub *tpm2b.PublicKeyRSA) (*tpm2b.EncryptedSecret, []byte, error) {
	rsaPub, err := helpers.RSAPub(parms, pub)
	if err != nil {
		return nil, nil, fmt.Errorf("could not encrypt salt to RSA key: %w", err)
	}
	// Odd special case: the size of the salt depends on the RSA scheme's
	// hash alg.
	var hAlg tpmi.AlgHash
	switch parms.Scheme.Scheme {
	case tpm.AlgRSASSA:
		hAlg = parms.Scheme.Details.RSASSA.HashAlg
	case tpm.AlgRSAES:
		hAlg = nameAlg
	case tpm.AlgRSAPSS:
		hAlg = parms.Scheme.Details.RSAPSS.HashAlg
	case tpm.AlgOAEP:
		hAlg = parms.Scheme.Details.OAEP.HashAlg
	case tpm.AlgNull:
		hAlg = nameAlg
	default:
		return nil, nil, fmt.Errorf("unsupported RSA salt key scheme: %v", parms.Scheme.Scheme)
	}
	ha, err := hAlg.Hash()
	if err != nil {
		return nil, nil, err
	}
	salt := make([]byte, ha.Size())
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("generating random salt: %w", err)
	}
	// Part 1, section 4.6 specifies the trailing NULL byte for the label.
	encSalt, err := rsa.EncryptOAEP(ha.New(), rand.Reader, rsaPub, salt, []byte("SECRET\x00"))
	if err != nil {
		return nil, nil, fmt.Errorf("encrypting salt: %w", err)
	}
	return &tpm2b.EncryptedSecret{
		Buffer: encSalt,
	}, salt, nil
}

// Part 1, 19.6.13
func getEncryptedSaltECC(nameAlg tpmi.AlgHash, parms *tpms.ECCParms, pub *tpms.ECCPoint) (*tpm2b.EncryptedSecret, []byte, error) {
	curve, err := parms.CurveID.Curve()
	if err != nil {
		return nil, nil, fmt.Errorf("could not encrypt salt to ECC key: %w", err)
	}
	eccPub, err := helpers.ECCPub(parms, pub)
	if err != nil {
		return nil, nil, fmt.Errorf("could not encrypt salt to ECC key: %w", err)
	}
	ephPriv, ephPubX, ephPubY, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("could not encrypt salt to ECC key: %w", err)
	}
	zx, _ := curve.Params().ScalarMult(eccPub.X, eccPub.Y, ephPriv)
	// ScalarMult returns a big.Int, whose Bytes() function may return the
	// compacted form. In our case, we want to left-pad zx to the size of
	// the curve.
	z := make([]byte, (curve.Params().BitSize+7)/8)
	zx.FillBytes(z)
	ha, err := nameAlg.Hash()
	if err != nil {
		return nil, nil, err
	}
	salt := legacy.KDFeHash(ha, z, "SECRET", ephPubX.Bytes(), pub.X.Buffer, ha.Size()*8)

	var encSalt bytes.Buffer
	binary.Write(&encSalt, binary.BigEndian, uint16(len(ephPubX.Bytes())))
	encSalt.Write(ephPubX.Bytes())
	binary.Write(&encSalt, binary.BigEndian, uint16(len(ephPubY.Bytes())))
	encSalt.Write(ephPubY.Bytes())
	return &tpm2b.EncryptedSecret{
		Buffer: encSalt.Bytes(),
	}, salt, nil
}

// getEncryptedSalt creates a salt value for salted sessions.
// Returns the encrypted salt and plaintext salt, or an error value.
func getEncryptedSalt(pub tpmt.Public) (*tpm2b.EncryptedSecret, []byte, error) {
	switch pub.Type {
	case tpm.AlgRSA:
		return getEncryptedSaltRSA(pub.NameAlg, pub.Parameters.RSADetail, pub.Unique.RSA)
	case tpm.AlgECC:
		return getEncryptedSaltECC(pub.NameAlg, pub.Parameters.ECCDetail, pub.Unique.ECC)
	default:
		return nil, nil, fmt.Errorf("salt encryption alg '%v' not supported", pub.Type)
	}
}

// Init initializes the session, just in time, if needed.
func (s *hmacSession) Init(t *TPM) error {
	if s.handle != tpm.RHNull {
		// Session is already initialized.
		return nil
	}

	// Get a high-quality nonceCaller for our use.
	// Store it with the session object for later reference.
	s.nonceCaller = tpm2b.Nonce{
		Buffer: make([]byte, s.nonceSize),
	}
	if _, err := rand.Read(s.nonceCaller.Buffer); err != nil {
		return err
	}

	// Start up the actual auth session.
	sasCmd := StartAuthSession{
		TPMKey:      s.saltHandle,
		Bind:        s.bindHandle,
		NonceCaller: s.nonceCaller,
		SessionType: tpm.SEHMAC,
		Symmetric:   s.symmetric,
		AuthHash:    s.hash,
	}
	var salt []byte
	if s.saltHandle != tpm.RHNull {
		var err error
		var encSalt *tpm2b.EncryptedSecret
		encSalt, salt, err = getEncryptedSalt(s.saltPub)
		if err != nil {
			return err
		}
		sasCmd.EncryptedSalt = *encSalt
	}
	sasRsp, err := sasCmd.Execute(t)
	if err != nil {
		return err
	}
	s.handle = sasRsp.SessionHandle
	s.nonceTPM = sasRsp.NonceTPM
	// Part 1, 19.6
	ha, err := s.hash.Hash()
	if err != nil {
		return err
	}
	if s.bindHandle != tpm.RHNull || len(salt) != 0 {
		var authSalt []byte
		authSalt = append(authSalt, s.bindAuth...)
		authSalt = append(authSalt, salt...)
		s.sessionKey = legacy.KDFaHash(ha, authSalt, "ATH", s.nonceTPM.Buffer, s.nonceCaller.Buffer, ha.Size()*8)
	}
	return nil
}

// Cleanup cleans up the session, if needed.
func (s *hmacSession) CleanupFailure(t *TPM) error {
	// The user is already responsible to clean up this session.
	if s.attrs.ContinueSession {
		return nil
	}
	fc := FlushContext{FlushHandle: s.handle}
	if _, err := fc.Execute(t); err != nil {
		return err
	}
	s.handle = tpm.RHNull
	return nil
}

// NonceTPM returns the last nonceTPM value from the session.
// May be nil, if the session hasn't been initialized yet.
func (s *hmacSession) NonceTPM() tpm2b.Nonce { return s.nonceTPM }

// To avoid a circular dependency on gotpm by tpm2, implement a
// tiny serialization by hand for tpma.Session here
func attrsToBytes(attrs tpma.Session) []byte {
	var res byte
	if attrs.ContinueSession {
		res |= (1 << 0)
	}
	if attrs.AuditExclusive {
		res |= (1 << 1)
	}
	if attrs.AuditReset {
		res |= (1 << 2)
	}
	if attrs.Reserved1 {
		res |= (1 << 3)
	}
	if attrs.Reserved2 {
		res |= (1 << 4)
	}
	if attrs.Decrypt {
		res |= (1 << 5)
	}
	if attrs.Encrypt {
		res |= (1 << 6)
	}
	if attrs.Audit {
		res |= (1 << 7)
	}
	return []byte{res}
}

// computeHMAC computes an authorization HMAC according to various equations in
// Part 1.
// This applies to both commands and responses.
// The value of key depends on whether the session is bound and/or salted.
// pHash cpHash for a command, or an rpHash for a response.
// nonceNewer in a command is the new nonceCaller sent in the command session
//   packet.
// nonceNewer in a response is the new nonceTPM sent in the response session
//   packet.
// nonceOlder in a command is the last nonceTPM sent by the TPM for this
//   session. This may be when the session was created, or the last time it was
//   used.
// nonceOlder in a response is the corresponding nonceCaller sent in the
//   command.
func computeHMAC(alg tpmi.AlgHash, key, pHash, nonceNewer, nonceOlder, addNonces []byte, attrs tpma.Session) ([]byte, error) {
	ha, err := alg.Hash()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(ha.New, key)
	mac.Write(pHash)
	mac.Write(nonceNewer)
	mac.Write(nonceOlder)
	mac.Write(addNonces)
	mac.Write(attrsToBytes(attrs))
	return mac.Sum(nil), nil
}

// Trim trailing zeros from the auth value. Part 1, 19.6.5, Note 2
// Does not allocate a new underlying byte array.
func hmacKeyFromAuthValue(auth []byte) []byte {
	key := auth
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == 0 {
			key = key[:i]
		}
	}
	return key
}

// NewNonceCaller updates the nonceCaller for this session.
func (s *hmacSession) NewNonceCaller() error {
	_, err := rand.Read(s.nonceCaller.Buffer)
	return err
}

// Authorize computes the authorization structure for the session.
// Unlike the TPM spec, authIndex is zero-based.
func (s *hmacSession) Authorize(cc tpm.CC, parms, addNonces []byte, names []tpm2b.Name, authIndex int) (*tpms.AuthCommand, error) {
	if s.handle == tpm.RHNull {
		// Session is not initialized.
		return nil, fmt.Errorf("session not initialized")
	}

	// Part 1, 19.6
	// HMAC key is (sessionKey || auth) unless this session is authorizing
	// its bind target
	var hmacKey []byte
	hmacKey = append(hmacKey, s.sessionKey...)
	if len(s.bindName.Buffer) == 0 || authIndex >= len(names) || !bytes.Equal(names[authIndex].Buffer, s.bindName.Buffer) {
		hmacKey = append(hmacKey, hmacKeyFromAuthValue(s.auth)...)
	}

	// Compute the authorization HMAC.
	cph, err := cpHash(s.hash, cc, names, parms)
	if err != nil {
		return nil, err
	}
	hmac, err := computeHMAC(s.hash, hmacKey, cph, s.nonceCaller.Buffer, s.nonceTPM.Buffer, addNonces, s.attrs)
	if err != nil {
		return nil, err
	}
	result := tpms.AuthCommand{
		Handle:     s.handle,
		Nonce:      s.nonceCaller,
		Attributes: s.attrs,
		Authorization: tpm2b.Data{
			Buffer: hmac,
		},
	}
	return &result, nil
}

// Validate validates the response session structure for the session.
// It updates nonceTPM from the TPM's response.
func (s *hmacSession) Validate(rc tpm.RC, cc tpm.CC, parms []byte, names []tpm2b.Name, authIndex int, auth *tpms.AuthResponse) error {
	// Track the new nonceTPM for the session.
	s.nonceTPM = auth.Nonce
	// Track the session being automatically flushed.
	if !auth.Attributes.ContinueSession {
		s.handle = tpm.RHNull
	}

	// Part 1, 19.6
	// HMAC key is (sessionKey || auth) unless this session is authorizing
	// its bind target
	var hmacKey []byte
	hmacKey = append(hmacKey, s.sessionKey...)
	if len(s.bindName.Buffer) == 0 || authIndex >= len(names) || !bytes.Equal(names[authIndex].Buffer, s.bindName.Buffer) {
		hmacKey = append(hmacKey, hmacKeyFromAuthValue(s.auth)...)
	}

	// Compute the authorization HMAC.
	rph, err := rpHash(s.hash, rc, cc, parms)
	if err != nil {
		return err
	}
	mac, err := computeHMAC(s.hash, hmacKey, rph, s.nonceTPM.Buffer, s.nonceCaller.Buffer, nil, auth.Attributes)
	if err != nil {
		return err
	}
	// Compare the HMAC (constant time)
	if !hmac.Equal(mac, auth.Authorization.Buffer) {
		return fmt.Errorf("incorrect authorization HMAC")
	}
	return nil
}

// IsEncryption returns true if this is an encryption session.
func (s *hmacSession) IsEncryption() bool {
	return s.attrs.Encrypt
}

// IsDecryption returns true if this is a decryption session.
func (s *hmacSession) IsDecryption() bool {
	return s.attrs.Decrypt
}

// Encrypt decrypts the parameter in place, if this session is used for
// parameter decryption. Otherwise, it does not modify the parameter.
func (s *hmacSession) Encrypt(parameter []byte) error {
	if !s.IsDecryption() {
		return nil
	}
	// Only AES-CFB is supported.
	keyBytes := *s.symmetric.KeyBits.AES / 8
	keyIVBytes := int(keyBytes) + 16
	var sessionValue []byte
	sessionValue = append(sessionValue, s.sessionKey...)
	sessionValue = append(sessionValue, s.auth...)
	ha, err := s.hash.Hash()
	if err != nil {
		return err
	}
	keyIV := legacy.KDFaHash(ha, sessionValue, "CFB", s.nonceCaller.Buffer, s.nonceTPM.Buffer, keyIVBytes*8)
	key, err := aes.NewCipher(keyIV[:keyBytes])
	if err != nil {
		return err
	}
	stream := cipher.NewCFBEncrypter(key, keyIV[keyBytes:])
	stream.XORKeyStream(parameter, parameter)
	return nil
}

// Decrypt encrypts the parameter in place, if this session is used for
// parameter encryption. Otherwise, it does not modify the parameter.
func (s *hmacSession) Decrypt(parameter []byte) error {
	if !s.IsEncryption() {
		return nil
	}
	// Only AES-CFB is supported.
	keyBytes := *s.symmetric.KeyBits.AES / 8
	keyIVBytes := int(keyBytes) + 16
	// Part 1, 21.1
	var sessionValue []byte
	sessionValue = append(sessionValue, s.sessionKey...)
	sessionValue = append(sessionValue, s.auth...)
	ha, err := s.hash.Hash()
	if err != nil {
		return err
	}
	keyIV := legacy.KDFaHash(ha, sessionValue, "CFB", s.nonceTPM.Buffer, s.nonceCaller.Buffer, keyIVBytes*8)
	key, err := aes.NewCipher(keyIV[:keyBytes])
	if err != nil {
		return err
	}
	stream := cipher.NewCFBDecrypter(key, keyIV[keyBytes:])
	stream.XORKeyStream(parameter, parameter)
	return nil
}

// Handle returns the handle value of the session.
// If the session is created with HMAC (instead of HMACSession) this will be
// TPM_RH_NULL.
func (s *hmacSession) Handle() tpm.Handle {
	return s.handle
}

// PolicyCallback represents an object's policy in the form of a function.
// This function makes zero or more TPM policy commands and returns error.
type PolicyCallback = func(tpm *TPM, handle tpmi.SHPolicy, nonceTPM tpm2b.Nonce) error

// policySession generally implements the policy session.
type policySession struct {
	sessionOptions
	hash       tpmi.AlgHash
	nonceSize  int
	handle     tpm.Handle
	sessionKey []byte
	// last nonceCaller
	nonceCaller tpm2b.Nonce
	// last nonceTPM
	nonceTPM tpm2b.Nonce
	callback *PolicyCallback
}

// Policy sets up a just-in-time policy session that created each time it's
// needed.
// Each time the policy is created, the callback is invoked to authorize the
// session.
// A real session is created, but just in time, and it is flushed when used.
func Policy(hash tpmi.AlgHash, nonceSize int, callback PolicyCallback, opts ...AuthOption) Session {
	// Set up a one-off session that knows the auth value.
	sess := policySession{
		sessionOptions: defaultOptions(),
		hash:           hash,
		nonceSize:      nonceSize,
		handle:         tpm.RHNull,
		callback:       &callback,
	}
	for _, opt := range opts {
		opt(&sess.sessionOptions)
	}
	return &sess
}

// PolicySession opens a policy session that needs to be closed.
// The caller is responsible to call whichever policy commands they want in the
// session.
// Note that the TPM resets a policy session after it is successfully used.
func PolicySession(t *TPM, hash tpmi.AlgHash, nonceSize int, opts ...AuthOption) (s Session, close func() error, err error) {
	// Set up a not-one-off session that knows the auth value.
	sess := policySession{
		sessionOptions: defaultOptions(),
		hash:           hash,
		nonceSize:      nonceSize,
		handle:         tpm.RHNull,
	}
	for _, opt := range opts {
		opt(&sess.sessionOptions)
	}

	// This session is reusable and is closed with the function we'll
	// return.
	sess.sessionOptions.attrs.ContinueSession = true

	// Initialize the session.
	if err := sess.Init(t); err != nil {
		return nil, nil, err
	}

	closer := func() error {
		fc := FlushContext{sess.handle}
		_, err := fc.Execute(t)
		return err
	}

	return &sess, closer, nil
}

// Init initializes the session, just in time, if needed.
func (s *policySession) Init(t *TPM) error {
	if s.handle != tpm.RHNull {
		// Session is already initialized.
		return nil
	}

	// Get a high-quality nonceCaller for our use.
	// Store it with the session object for later reference.
	s.nonceCaller = tpm2b.Nonce{
		Buffer: make([]byte, s.nonceSize),
	}
	if _, err := rand.Read(s.nonceCaller.Buffer); err != nil {
		return err
	}

	// Start up the actual auth session.
	sasCmd := StartAuthSession{
		TPMKey:      s.saltHandle,
		Bind:        s.bindHandle,
		NonceCaller: s.nonceCaller,
		SessionType: tpm.SEPolicy,
		Symmetric:   s.symmetric,
		AuthHash:    s.hash,
	}
	var salt []byte
	if s.saltHandle != tpm.RHNull {
		var err error
		var encSalt *tpm2b.EncryptedSecret
		encSalt, salt, err = getEncryptedSalt(s.saltPub)
		if err != nil {
			return err
		}
		sasCmd.EncryptedSalt = *encSalt
	}
	sasRsp, err := sasCmd.Execute(t)
	if err != nil {
		return err
	}
	s.handle = sasRsp.SessionHandle
	s.nonceTPM = sasRsp.NonceTPM
	// Part 1, 19.6
	if s.bindHandle != tpm.RHNull || len(salt) != 0 {
		var authSalt []byte
		authSalt = append(authSalt, s.bindAuth...)
		authSalt = append(authSalt, salt...)
		ha, err := s.hash.Hash()
		if err != nil {
			return err
		}
		s.sessionKey = legacy.KDFaHash(ha, authSalt, "ATH", s.nonceTPM.Buffer, s.nonceCaller.Buffer, ha.Size()*8)
	}

	// Call the callback to execute the policy, if needed
	if s.callback != nil {
		if err := (*s.callback)(t, s.handle, s.nonceTPM); err != nil {
			return fmt.Errorf("executing policy: %w", err)
		}
	}

	return nil
}

// CleanupFailure cleans up the session, if needed.
func (s *policySession) CleanupFailure(t *TPM) error {
	// The user is already responsible to clean up this session.
	if s.attrs.ContinueSession {
		return nil
	}
	fc := FlushContext{FlushHandle: s.handle}
	if _, err := fc.Execute(t); err != nil {
		return err
	}
	s.handle = tpm.RHNull
	return nil
}

// NonceTPM returns the last nonceTPM value from the session.
// May be nil, if the session hasn't been initialized yet.
func (s *policySession) NonceTPM() tpm2b.Nonce { return s.nonceTPM }

// NewNonceCaller updates the nonceCaller for this session.
func (s *policySession) NewNonceCaller() error {
	_, err := rand.Read(s.nonceCaller.Buffer)
	return err
}

// Authorize computes the authorization structure for the session.
func (s *policySession) Authorize(cc tpm.CC, parms, addNonces []byte, names []tpm2b.Name, _ int) (*tpms.AuthCommand, error) {
	if s.handle == tpm.RHNull {
		// Session is not initialized.
		return nil, fmt.Errorf("session not initialized")
	}

	var hmac []byte
	if s.password {
		hmac = s.auth
	} else {
		// Part 1, 19.6
		// HMAC key is (sessionKey || auth).
		var hmacKey []byte
		hmacKey = append(hmacKey, s.sessionKey...)
		hmacKey = append(hmacKey, hmacKeyFromAuthValue(s.auth)...)

		// Compute the authorization HMAC.
		cph, err := cpHash(s.hash, cc, names, parms)
		if err != nil {
			return nil, err
		}
		hmac, err = computeHMAC(s.hash, hmacKey, cph, s.nonceCaller.Buffer, s.nonceTPM.Buffer, addNonces, s.attrs)
		if err != nil {
			return nil, err
		}
	}

	result := tpms.AuthCommand{
		Handle:     s.handle,
		Nonce:      s.nonceCaller,
		Attributes: s.attrs,
		Authorization: tpm2b.Data{
			Buffer: hmac,
		},
	}
	return &result, nil
}

// Validate valitades the response session structure for the session.
// Updates nonceTPM from the TPM's response.
func (s *policySession) Validate(rc tpm.RC, cc tpm.CC, parms []byte, _ []tpm2b.Name, _ int, auth *tpms.AuthResponse) error {
	// Track the new nonceTPM for the session.
	s.nonceTPM = auth.Nonce
	// Track the session being automatically flushed.
	if !auth.Attributes.ContinueSession {
		s.handle = tpm.RHNull
	}

	if s.password {
		// If we used a password, expect no nonce and no response HMAC.
		if len(auth.Nonce.Buffer) != 0 {
			return fmt.Errorf("expected empty nonce in response auth to PW policy, got %x", auth.Nonce)
		}
		if len(auth.Authorization.Buffer) != 0 {
			return fmt.Errorf("expected empty HMAC in response auth to PW policy, got %x", auth.Authorization)
		}
	} else {
		// Part 1, 19.6
		// HMAC key is (sessionKey || auth).
		var hmacKey []byte
		hmacKey = append(hmacKey, s.sessionKey...)
		hmacKey = append(hmacKey, hmacKeyFromAuthValue(s.auth)...)
		// Compute the authorization HMAC.
		rph, err := rpHash(s.hash, rc, cc, parms)
		if err != nil {
			return err
		}
		mac, err := computeHMAC(s.hash, hmacKey, rph, s.nonceTPM.Buffer, s.nonceCaller.Buffer, nil, auth.Attributes)
		if err != nil {
			return err
		}
		// Compare the HMAC (constant time)
		if !hmac.Equal(mac, auth.Authorization.Buffer) {
			return fmt.Errorf("incorrect authorization HMAC")
		}
	}
	return nil
}

// IsEncryption returns true if this is an encryption session.
func (s *policySession) IsEncryption() bool {
	return s.attrs.Encrypt
}

// IsDecryption returns true if this is a decryption session.
func (s *policySession) IsDecryption() bool {
	return s.attrs.Decrypt
}

// Encrypt encrypts the parameter in place, if this session is used for
// parameter decryption. Otherwise, it does not modify the parameter.
func (s *policySession) Encrypt(parameter []byte) error {
	if !s.IsDecryption() {
		return nil
	}
	// Only AES-CFB is supported.
	keyBytes := *s.symmetric.KeyBits.AES / 8
	keyIVBytes := int(keyBytes) + 16
	var sessionValue []byte
	sessionValue = append(sessionValue, s.sessionKey...)
	sessionValue = append(sessionValue, s.auth...)
	ha, err := s.hash.Hash()
	if err != nil {
		return err
	}
	keyIV := legacy.KDFaHash(ha, sessionValue, "CFB", s.nonceCaller.Buffer, s.nonceTPM.Buffer, keyIVBytes*8)
	key, err := aes.NewCipher(keyIV[:keyBytes])
	if err != nil {
		return err
	}
	stream := cipher.NewCFBEncrypter(key, keyIV[keyBytes:])
	stream.XORKeyStream(parameter, parameter)
	return nil
}

// Decrypt decrypts the parameter in place, if this session is used for
// parameter encryption. Otherwise, it does not modify the parameter.
func (s *policySession) Decrypt(parameter []byte) error {
	if !s.IsEncryption() {
		return nil
	}
	// Only AES-CFB is supported.
	keyBytes := *s.symmetric.KeyBits.AES / 8
	keyIVBytes := int(keyBytes) + 16
	// Part 1, 21.1
	var sessionValue []byte
	sessionValue = append(sessionValue, s.sessionKey...)
	sessionValue = append(sessionValue, s.auth...)
	ha, err := s.hash.Hash()
	if err != nil {
		return err
	}
	keyIV := legacy.KDFaHash(ha, sessionValue, "CFB", s.nonceTPM.Buffer, s.nonceCaller.Buffer, keyIVBytes*8)
	key, err := aes.NewCipher(keyIV[:keyBytes])
	if err != nil {
		return err
	}
	stream := cipher.NewCFBDecrypter(key, keyIV[keyBytes:])
	stream.XORKeyStream(parameter, parameter)
	return nil
}

// Handle returns the handle value of the session.
// If the session is created with Policy (instead of PolicySession) this will be
// TPM_RH_NULL.
func (s *policySession) Handle() tpm.Handle {
	return s.handle
}
