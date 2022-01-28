package tpm

import (
	"crypto"
	"crypto/elliptic"

	// Register the relevant hash implementations.
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
)

// Generated values come from Part 2: Structures, section 6.2.
const (
	GeneratedValue Generated = 0xff544347
)

// AlgID values come from Part 2: Structures, section 6.3.
const (
	AlgRSA          AlgID = 0x0001
	AlgTDES         AlgID = 0x0003
	AlgSHA          AlgID = 0x0004
	AlgSHA1                  = AlgSHA
	AlgHMAC         AlgID = 0x0005
	AlgAES          AlgID = 0x0006
	AlgMGF1         AlgID = 0x0007
	AlgKeyedHash    AlgID = 0x0008
	AlgXOR          AlgID = 0x000A
	AlgSHA256       AlgID = 0x000B
	AlgSHA384       AlgID = 0x000C
	AlgSHA512       AlgID = 0x000D
	AlgNull         AlgID = 0x0010
	AlgSM3256       AlgID = 0x0012
	AlgSM4          AlgID = 0x0013
	AlgRSASSA       AlgID = 0x0014
	AlgRSAES        AlgID = 0x0015
	AlgRSAPSS       AlgID = 0x0016
	AlgOAEP         AlgID = 0x0017
	AlgECDSA        AlgID = 0x0018
	AlgECDH         AlgID = 0x0019
	AlgECDAA        AlgID = 0x001A
	AlgSM2          AlgID = 0x001B
	AlgECSchnorr    AlgID = 0x001C
	AlgECMQV        AlgID = 0x001D
	AlgKDF1SP80056A AlgID = 0x0020
	AlgKDF2         AlgID = 0x0021
	AlgKDF1SP800108 AlgID = 0x0022
	AlgECC          AlgID = 0x0023
	AlgSymCipher    AlgID = 0x0025
	AlgCamellia     AlgID = 0x0026
	AlgSHA3256      AlgID = 0x0027
	AlgSHA3384      AlgID = 0x0028
	AlgSHA3512      AlgID = 0x0029
	AlgCTR          AlgID = 0x0040
	AlgOFB          AlgID = 0x0041
	AlgCBC          AlgID = 0x0042
	AlgCFB          AlgID = 0x0043
	AlgECB          AlgID = 0x0044
)

// ECCCurve values come from Part 2: Structures, section 6.4.
const (
	ECCNone     ECCCurve = 0x0000
	ECCNistP192 ECCCurve = 0x0001
	ECCNistP224 ECCCurve = 0x0002
	ECCNistP256 ECCCurve = 0x0003
	ECCNistP384 ECCCurve = 0x0004
	ECCNistP521 ECCCurve = 0x0005
	ECCBNP256   ECCCurve = 0x0010
	ECCBNP638   ECCCurve = 0x0011
	ECCSM2P256  ECCCurve = 0x0020
)

// Curve returns the elliptic.Curve associated with a ECCCurve.
func (c ECCCurve) Curve() (elliptic.Curve, error) {
	switch c {
	case ECCNistP224:
		return elliptic.P224(), nil
	case ECCNistP256:
		return elliptic.P256(), nil
	case ECCNistP384:
		return elliptic.P384(), nil
	case ECCNistP521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ECC curve: %v", c)
	}
}

// CC values come from Part 2: Structures, section 6.5.2.
const (
	CCNVUndefineSpaceSpecial     CC = 0x0000011F
	CCEvictControl               CC = 0x00000120
	CCHierarchyControl           CC = 0x00000121
	CCNVUndefineSpace            CC = 0x00000122
	CCChangeEPS                  CC = 0x00000124
	CCChangePPS                  CC = 0x00000125
	CCClear                      CC = 0x00000126
	CCClearControl               CC = 0x00000127
	CCClockSet                   CC = 0x00000128
	CCHierarchyChanegAuth        CC = 0x00000129
	CCNVDefineSpace              CC = 0x0000012A
	CCPCRAllocate                CC = 0x0000012B
	CCPCRSetAuthPolicy           CC = 0x0000012C
	CCPPCommands                 CC = 0x0000012D
	CCSetPrimaryPolicy           CC = 0x0000012E
	CCFieldUpgradeStart          CC = 0x0000012F
	CCClockRateAdjust            CC = 0x00000130
	CCCreatePrimary              CC = 0x00000131
	CCNVGlobalWriteLock          CC = 0x00000132
	CCGetCommandAuditDigest      CC = 0x00000133
	CCNVIncrement                CC = 0x00000134
	CCNVSetBits                  CC = 0x00000135
	CCNVExtend                   CC = 0x00000136
	CCNVWrite                    CC = 0x00000137
	CCNVWriteLock                CC = 0x00000138
	CCDictionaryAttackLockReset  CC = 0x00000139
	CCDictionaryAttackParameters CC = 0x0000013A
	CCNVChangeAuth               CC = 0x0000013B
	CCPCREvent                   CC = 0x0000013C
	CCPCRReset                   CC = 0x0000013D
	CCSequenceComplete           CC = 0x0000013E
	CCSetAlgorithmSet            CC = 0x0000013F
	CCSetCommandCodeAuditStatus  CC = 0x00000140
	CCFieldUpgradeData           CC = 0x00000141
	CCIncrementalSelfTest        CC = 0x00000142
	CCSelfTest                   CC = 0x00000143
	CCStartup                    CC = 0x00000144
	CCShutdown                   CC = 0x00000145
	CCStirRandom                 CC = 0x00000146
	CCActivateCredential         CC = 0x00000147
	CCCertify                    CC = 0x00000148
	CCPolicyNV                   CC = 0x00000149
	CCCertifyCreation            CC = 0x0000014A
	CCDuplicate                  CC = 0x0000014B
	CCGetTime                    CC = 0x0000014C
	CCGetSessionAuditDigest      CC = 0x0000014D
	CCNVRead                     CC = 0x0000014E
	CCNVReadLock                 CC = 0x0000014F
	CCObjectChangeAuth           CC = 0x00000150
	CCPolicySecret               CC = 0x00000151
	CCRewrap                     CC = 0x00000152
	CCCreate                     CC = 0x00000153
	CCECDHZGen                   CC = 0x00000154
	CCHMAC                       CC = 0x00000155
	CCMAC                        CC = CCHMAC
	CCImport                     CC = 0x00000156
	CCLoad                       CC = 0x00000157
	CCQuote                      CC = 0x00000158
	CCRSADecrypt                 CC = 0x00000159
	CCHMACStart                  CC = 0x0000015B
	CCMACStart                   CC = CCHMACStart
	CCSequenceUpdate             CC = 0x0000015C
	CCSign                       CC = 0x0000015D
	CCUnseal                     CC = 0x0000015E
	CCPolicySigned               CC = 0x00000160
	CCContextLoad                CC = 0x00000161
	CCContextSave                CC = 0x00000162
	CCECDHKeyGen                 CC = 0x00000163
	CCEncryptDecrypt             CC = 0x00000164
	CCFlushContext               CC = 0x00000165
	CCLoadExternal               CC = 0x00000167
	CCMakeCredential             CC = 0x00000168
	CCNVReadPublic               CC = 0x00000169
	CCPolicyAuthorize            CC = 0x0000016A
	CCPolicyAuthValue            CC = 0x0000016B
	CCPolicyCommandCode          CC = 0x0000016C
	CCPolicyCounterTimer         CC = 0x0000016D
	CCPolicyCpHash               CC = 0x0000016E
	CCPolicyLocality             CC = 0x0000016F
	CCPolicyNameHash             CC = 0x00000170
	CCPolicyOR                   CC = 0x00000171
	CCPolicyTicket               CC = 0x00000172
	CCReadPublic                 CC = 0x00000173
	CCRSAEncrypt                 CC = 0x00000174
	CCStartAuthSession           CC = 0x00000176
	CCVerifySignature            CC = 0x00000177
	CCECCParameters              CC = 0x00000178
	CCFirmwareRead               CC = 0x00000179
	CCGetCapability              CC = 0x0000017A
	CCGetRandom                  CC = 0x0000017B
	CCGetTestResult              CC = 0x0000017C
	CCHash                       CC = 0x0000017D
	CCPCRRead                    CC = 0x0000017E
	CCPolicyPCR                  CC = 0x0000017F
	CCPolicyRestart              CC = 0x00000180
	CCReadClock                  CC = 0x00000181
	CCPCRExtend                  CC = 0x00000182
	CCPCRSetAuthValue            CC = 0x00000183
	CCNVCertify                  CC = 0x00000184
	CCEventSequenceComplete      CC = 0x00000185
	CCHashSequenceStart          CC = 0x00000186
	CCPolicyPhysicalPresence     CC = 0x00000187
	CCPolicyDuplicationSelect    CC = 0x00000188
	CCPolicyGetDigest            CC = 0x00000189
	CCTestParams                 CC = 0x0000018A
	CCCommit                     CC = 0x0000018B
	CCPolicyPassword             CC = 0x0000018C
	CCZGen2Phase                 CC = 0x0000018D
	CCECEphemeral                CC = 0x0000018E
	CCPolicyNvWritten            CC = 0x0000018F
	CCPolicyTemplate             CC = 0x00000190
	CCCreateLoaded               CC = 0x00000191
	CCPolicyAuthorizeNV          CC = 0x00000192
	CCEncryptDecrypt2            CC = 0x00000193
	CCACGetCapability            CC = 0x00000194
	CCACSend                     CC = 0x00000195
	CCPolicyACSendSelect         CC = 0x00000196
	CCCertifyX509                CC = 0x00000197
	CCACTSetTimeout              CC = 0x00000198
)

// RC values come from Part 2: Structures, section 6.6.3.
const (
	RCSuccess RC = 0x00000000
	rcVer1       RC = 0x00000100
	// FMT0 error codes
	RCInitialize      RC = rcVer1 + 0x000
	RCFailure         RC = rcVer1 + 0x001
	RCSequence        RC = rcVer1 + 0x003
	RCPrivate         RC = rcVer1 + 0x00B
	RCHMAC            RC = rcVer1 + 0x019
	RCDisabled        RC = rcVer1 + 0x020
	RCExclusive       RC = rcVer1 + 0x021
	RCAuthType        RC = rcVer1 + 0x024
	RCAuthMissing     RC = rcVer1 + 0x025
	RCPolicy          RC = rcVer1 + 0x026
	RCPCR             RC = rcVer1 + 0x027
	RCPCRChanged      RC = rcVer1 + 0x028
	RCUpgrade         RC = rcVer1 + 0x02D
	RCTooManyContexts RC = rcVer1 + 0x02E
	RCAuthUnavailable RC = rcVer1 + 0x02F
	RCReboot          RC = rcVer1 + 0x030
	RCUnbalanced      RC = rcVer1 + 0x031
	RCCommandSize     RC = rcVer1 + 0x042
	RCCommandCode     RC = rcVer1 + 0x043
	RCAuthSize        RC = rcVer1 + 0x044
	RCAuthContext     RC = rcVer1 + 0x045
	RCNVRange         RC = rcVer1 + 0x046
	RCNVSize          RC = rcVer1 + 0x047
	RCNVLocked        RC = rcVer1 + 0x048
	RCNVAuthorization RC = rcVer1 + 0x049
	RCNVUninitialized RC = rcVer1 + 0x04A
	RCNVSpace         RC = rcVer1 + 0x04B
	RCNVDefined       RC = rcVer1 + 0x04C
	RCBadContext      RC = rcVer1 + 0x050
	RCCPHash          RC = rcVer1 + 0x051
	RCParent          RC = rcVer1 + 0x052
	RCNeedsTest       RC = rcVer1 + 0x053
	RCNoResult        RC = rcVer1 + 0x054
	RCSensitive       RC = rcVer1 + 0x055
	rcFmt1               RC = 0x00000080
	// FMT1 error codes
	RCAsymmetric   RC = rcFmt1 + 0x001
	RCAttributes   RC = rcFmt1 + 0x002
	RCHash         RC = rcFmt1 + 0x003
	RCValue        RC = rcFmt1 + 0x004
	RCHierarchy    RC = rcFmt1 + 0x005
	RCKeySize      RC = rcFmt1 + 0x007
	RCMGF          RC = rcFmt1 + 0x008
	RCMode         RC = rcFmt1 + 0x009
	RCType         RC = rcFmt1 + 0x00A
	RCHandle       RC = rcFmt1 + 0x00B
	RCKDF          RC = rcFmt1 + 0x00C
	RCRange        RC = rcFmt1 + 0x00D
	RCAuthFail     RC = rcFmt1 + 0x00E
	RCNonce        RC = rcFmt1 + 0x00F
	RCPP           RC = rcFmt1 + 0x010
	RCScheme       RC = rcFmt1 + 0x012
	RCSize         RC = rcFmt1 + 0x015
	RCSymmetric    RC = rcFmt1 + 0x016
	RCTag          RC = rcFmt1 + 0x017
	RCSelector     RC = rcFmt1 + 0x018
	RCInsufficient RC = rcFmt1 + 0x01A
	RCSignature    RC = rcFmt1 + 0x01B
	RCKey          RC = rcFmt1 + 0x01C
	RCPolicyFail   RC = rcFmt1 + 0x01D
	RCIntegrity    RC = rcFmt1 + 0x01F
	RCTicket       RC = rcFmt1 + 0x020
	RCReservedBits RC = rcFmt1 + 0x021
	RCBadAuth      RC = rcFmt1 + 0x022
	RCExpired      RC = rcFmt1 + 0x023
	RCPolicyCC     RC = rcFmt1 + 0x024
	RCBinding      RC = rcFmt1 + 0x025
	RCCurve        RC = rcFmt1 + 0x026
	RCECCPoint     RC = rcFmt1 + 0x027
	// Warnings
	rcWarn              RC = 0x00000900
	RCContextGap     RC = rcWarn + 0x001
	RCObjectMemory   RC = rcWarn + 0x002
	RCSessionMemory  RC = rcWarn + 0x003
	RCMemory         RC = rcWarn + 0x004
	RCSessionHandles RC = rcWarn + 0x005
	RCObjectHandles  RC = rcWarn + 0x006
	RCLocality       RC = rcWarn + 0x007
	RCYielded        RC = rcWarn + 0x008
	RCCanceled       RC = rcWarn + 0x009
	RCTesting        RC = rcWarn + 0x00A
	RCReferenceH0    RC = rcWarn + 0x010
	RCReferenceH1    RC = rcWarn + 0x011
	RCReferenceH2    RC = rcWarn + 0x012
	RCReferenceH3    RC = rcWarn + 0x013
	RCReferenceH4    RC = rcWarn + 0x014
	RCReferenceH5    RC = rcWarn + 0x015
	RCReferenceH6    RC = rcWarn + 0x016
	RCReferenceS0    RC = rcWarn + 0x018
	RCReferenceS1    RC = rcWarn + 0x019
	RCReferenceS2    RC = rcWarn + 0x01A
	RCReferenceS3    RC = rcWarn + 0x01B
	RCReferenceS4    RC = rcWarn + 0x01C
	RCReferenceS5    RC = rcWarn + 0x01D
	RCReferenceS6    RC = rcWarn + 0x01E
	RCNVRate         RC = rcWarn + 0x020
	RCLockout        RC = rcWarn + 0x021
	RCRetry          RC = rcWarn + 0x022
	RCNVUnavailable  RC = rcWarn + 0x023
	rcP                 RC = 0x00000040
	rcS                 RC = 0x00000800
)

// ST values come from Part 2: Structures, section  6.9.
const (
	STRspCommand         ST = 0x00C4
	STNull               ST = 0x8000
	STNoSessions         ST = 0x8001
	STSessions           ST = 0x8002
	STAttestNV           ST = 0x8014
	STAttestCommandAudit ST = 0x8015
	STAttestSessionAudit ST = 0x8016
	STAttestCertify      ST = 0x8017
	STAttestQuote        ST = 0x8018
	STAttestTime         ST = 0x8019
	STAttestCreation     ST = 0x801A
	STAttestNVDigest     ST = 0x801C
	STCreation           ST = 0x8021
	STVerified           ST = 0x8022
	STAuthSecret         ST = 0x8023
	STHashCheck          ST = 0x8024
	STAuthSigned         ST = 0x8025
	STFuManifest         ST = 0x8029
)

// SE values come from Part 2: Structures, section 6.11.
const (
	SEHMAC   SE = 0x00
	SEPolicy SE = 0x01
	XETrial  SE = 0x03
)

// Cap values come from Part 2: Structures, section 6.12.
const (
	CapAlgs          Cap = 0x00000000
	CapHandles       Cap = 0x00000001
	CapCommands      Cap = 0x00000002
	CapPPCommands    Cap = 0x00000003
	CapAuditCommands Cap = 0x00000004
	CapPCRs          Cap = 0x00000005
	CapProperties Cap = 0x00000006
	CapPCRProperties Cap = 0x00000007
	CapECCCurves     Cap = 0x00000008
	CapAuthPolicies  Cap = 0x00000009
	CapACT           Cap = 0x0000000A
)

// PTFamilyIndicator values come from Part 2: Structures, section  6.13.
const (
	// a 4-octet character string containing the TPM Family value
	// (TPM_SPEC_FAMILY)
	PTFamilyIndicator PT = 0x00000100
	// the level of the specification
	PTLevel PT = 0x00000101
	// the specification Revision times 100
	PTRevision PT = 0x00000102
	// the specification day of year using TCG calendar
	PTDayofYear PT = 0x00000103
	// the specification year using the CE
	PTYear PT = 0x00000104
	// the vendor ID unique to each TPM manufacturer
	PTManufacturer PT = 0x00000105
	// the first four characters of the vendor ID string
	PTVendorString1 PT = 0x00000106
	// the second four characters of the vendor ID string
	PTVendorString2 PT = 0x00000107
	// the third four characters of the vendor ID string
	PTVendorString3 PT = 0x00000108
	// the fourth four characters of the vendor ID sting
	PTVendorString4 PT = 0x00000109
	// vendor-defined value indicating the TPM model
	PTVendorTPMType PT = 0x0000010A
	// the most-significant 32 bits of a TPM vendor-specific value
	// indicating the version number of the firmware.
	PTFirmwareVersion1 PT = 0x0000010B
	// the least-significant 32 bits of a TPM vendor-specific value
	// indicating the version number of the firmware.
	PTFirmwareVersion2 PT = 0x0000010C
	// the maximum size of a parameter TPM2B_MAX_BUFFER)
	PTInputBuffer PT = 0x0000010D
	// the minimum number of transient objects that can be held in TPM RAM
	PTHRTransientMin PT = 0x0000010E
	// the minimum number of persistent objects that can be held in TPM NV
	// memory
	PTHRPersistentMin PT = 0x0000010F
	// the minimum number of authorization sessions that can be held in TPM
	// RAM
	PTHRLoadedMin PT = 0x00000110
	// the number of authorization sessions that may be active at a time
	PTActiveSessionsMax PT = 0x00000111
	// the number of PCR implemented
	PTPCRCount PT = 0x00000112
	// the minimum number of octets in a TPMS_PCR_SELECT.sizeOfSelect
	PTPCRSelectMin PT = 0x00000113
	// the maximum allowed difference (unsigned) between the contextID
	// values of two saved session contexts
	PTContextGapMax PT = 0x00000114
	// the maximum number of NV Indexes that are allowed to have the
	// TPM_NT_COUNTER attribute
	PTNVCountersMax PT = 0x00000116
	// the maximum size of an NV Index data area
	PTNVIndexMax PT = 0x00000117
	// a TPMA_MEMORY indicating the memory management method for the TPM
	PTMemory PT = 0x00000118
	// interval, in milliseconds, between updates to the copy of
	// TPMS_CLOCK_INFO.clock in NV
	PTClockUpdate PT = 0x00000119
	// the algorithm used for the integrity HMAC on saved contexts and for
	// hashing the fuData of TPM2_FirmwareRead()
	PTContextHash PT = 0x0000011A
	// TPM_ALG_ID, the algorithm used for encryption of saved contexts
	PTContextSym PT = 0x0000011B
	// TPM_KEY_BITS, the size of the key used for encryption of saved
	// contexts
	PTContextSymSize PT = 0x0000011C
	// the modulus - 1 of the count for NV update of an orderly counter
	PTOrderlyCount PT = 0x0000011D
	// the maximum value for commandSize in a command
	PTMaxCommandSize PT = 0x0000011E
	// the maximum value for responseSize in a response
	PTMaxResponseSize PT = 0x0000011F
	// the maximum size of a digest that can be produced by the TPM
	PTMaxDigest PT = 0x00000120
	// the maximum size of an object context that will be returned by
	// TPM2_ContextSave
	PTMaxObjectContext PT = 0x00000121
	// the maximum size of a session context that will be returned by
	// TPM2_ContextSave
	PTMaxSessionContext PT = 0x00000122
	// platform-specific family (a TPM_PS value)(see Table 25)
	PTPSFamilyIndicator PT = 0x00000123
	// the level of the platform-specific specification
	PTPSLevel PT = 0x00000124
	// a platform specific value
	PTPSRevision PT = 0x00000125
	// the platform-specific TPM specification day of year using TCG
	// calendar
	PTPSDayOfYear PT = 0x00000126
	// the platform-specific TPM specification year using the CE
	PTPSYear PT = 0x00000127
	// the number of split signing operations supported by the TPM
	PTSplitMax PT = 0x00000128
	// total number of commands implemented in the TPM
	PTTotalCommands PT = 0x00000129
	// number of commands from the TPM library that are implemented
	PTLibraryCommands PT = 0x0000012A
	// number of vendor commands that are implemented
	PTVendorCommands PT = 0x0000012B
	// the maximum data size in one NV write, NV read, NV extend, or NV
	// certify command
	PTNVBufferMax PT = 0x0000012C
	// a TPMA_MODES value, indicating that the TPM is designed for these
	// modes.
	PTModes PT = 0x0000012D
	// the maximum size of a TPMS_CAPABILITY_DATA structure returned in
	// TPM2_GetCapability().
	PTMaxCapBuffer PT = 0x0000012E
	// TPMA_PERMANENT
	PTPermanent PT = 0x00000200
	// TPMA_STARTUP_CLEAR
	PTStartupClear PT = 0x00000201
	// the number of NV Indexes currently defined
	PTHRNVIndex PT = 0x00000202
	// the number of authorization sessions currently loaded into TPM RAM
	PTHRLoaded PT = 0x00000203
	// the number of additional authorization sessions, of any type, that
	// could be loaded into TPM RAM
	PTHRLoadedAvail PT = 0x00000204
	// the number of active authorization sessions currently being tracked
	// by the TPM
	PTHRActive PT = 0x00000205
	// the number of additional authorization sessions, of any type, that
	// could be created
	PTHRActiveAvail PT = 0x00000206
	// estimate of the number of additional transient objects that could be
	// loaded into TPM RAM
	PTHRTransientAvail PT = 0x00000207
	// the number of persistent objects currently loaded into TPM NV memory
	PTHRPersistent PT = 0x00000208
	// the number of additional persistent objects that could be loaded into
	// NV memory
	PTHRPersistentAvail PT = 0x00000209
	// the number of defined NV Indexes that have NV the TPM_NT_COUNTER
	// attribute
	PTNVCounters PT = 0x0000020A
	// the number of additional NV Indexes that can be defined with their
	// TPM_NT of TPM_NV_COUNTER and the TPMA_NV_ORDERLY attribute SET
	PTNVCountersAvail PT = 0x0000020B
	// code that limits the algorithms that may be used with the TPM
	PTAlgorithmSet PT = 0x0000020C
	// the number of loaded ECC curves
	PTLoadedCurves PT = 0x0000020D
	// the current value of the lockout counter (failedTries)
	PTLockoutCounter PT = 0x0000020E
	// the number of authorization failures before DA lockout is invoked
	PTMaxAuthFail PT = 0x0000020F
	// the number of seconds before the value reported by
	// TPM_PT_LOCKOUT_COUNTER is decremented
	PTLockoutInterval PT = 0x00000210
	// the number of seconds after a lockoutAuth failure before use of
	// lockoutAuth may be attempted again
	PTLockoutRecovery PT = 0x00000211
	// number of milliseconds before the TPM will accept another command
	// that will modify NV
	PTNVWriteRecovery PT = 0x00000212
	// the high-order 32 bits of the command audit counter
	PTAuditCounter0 PT = 0x00000213
	// the low-order 32 bits of the command audit counter
	PTAuditCounter1 PT = 0x00000214
)

// PTPCR values come from Part 2: Structures, section 6.14.
const (
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR is saved and
	// restored by TPM_SU_STATE
	PTPCRSave PTPCR = 0x00000000
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
	// extended from locality 0
	PTPCRExtendL0 PTPCR = 0x00000001
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
	// by TPM2_PCR_Reset() from locality 0
	PTPCRResetL0 PTPCR = 0x00000002
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
	// extended from locality 1
	PTPCRExtendL1 PTPCR = 0x00000003
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
	// by TPM2_PCR_Reset() from locality 1
	PTPCRResetL1 PTPCR = 0x00000004
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
	// extended from locality 2
	PTPCRExtendL2 PTPCR = 0x00000005
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
	// by TPM2_PCR_Reset() from locality 2
	PTPCRResetL2 PTPCR = 0x00000006
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
	// extended from locality 3
	PTPCRExtendL3 PTPCR = 0x00000007
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
	// by TPM2_PCR_Reset() from locality 3
	PTPCRResetL3 PTPCR = 0x00000008
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
	// extended from locality 4
	PTPCRExtendL4 PTPCR = 0x00000009
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
	// by TPM2_PCR_Reset() from locality 4
	PTPCRResetL4 PTPCR = 0x0000000A
	// a SET bit in the TPMS_PCR_SELECT indicates that modifications to this
	// PCR (reset or Extend) will not increment the pcrUpdateCounter
	PTPCRNoIncrement PTPCR = 0x00000011
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR is reset by a
	// D-RTM event
	PTPCRDRTMRest PTPCR = 0x00000012
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR is controlled
	// by policy
	PTPCRPolicy PTPCR = 0x00000013
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR is controlled
	// by an authorization value
	PTPCRAuth PTPCR = 0x00000014
)

// Handle values come from Part 2: Structures, section 7.4.
const (
	RHOwner       Handle = 0x40000001
	RHNull        Handle = 0x40000007
	RSPW          Handle = 0x40000009
	RHLockout     Handle = 0x4000000A
	RHEndorsement Handle = 0x4000000B
	RHPlatform    Handle = 0x4000000C
	RHPlatformNV  Handle = 0x4000000D
)
