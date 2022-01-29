package tpm

import (
	"github.com/google/go-tpm/direct/structures/internal"
)

// AlgID values come from Part 2: Structures, section 6.3.
const (
	AlgRSA          = internal.TPMAlgRSA
	AlgTDES         = internal.TPMAlgTDES
	AlgSHA          = internal.TPMAlgSHA
	AlgSHA1         = internal.TPMAlgSHA1
	AlgHMAC         = internal.TPMAlgHMAC
	AlgAES          = internal.TPMAlgAES
	AlgMGF1         = internal.TPMAlgMGF1
	AlgKeyedHash    = internal.TPMAlgKeyedHash
	AlgXOR          = internal.TPMAlgXOR
	AlgSHA256       = internal.TPMAlgSHA256
	AlgSHA384       = internal.TPMAlgSHA384
	AlgSHA512       = internal.TPMAlgSHA512
	AlgNull         = internal.TPMAlgNull
	AlgSM3256       = internal.TPMAlgSM3256
	AlgSM4          = internal.TPMAlgSM4
	AlgRSASSA       = internal.TPMAlgRSASSA
	AlgRSAES        = internal.TPMAlgRSAES
	AlgRSAPSS       = internal.TPMAlgRSAPSS
	AlgOAEP         = internal.TPMAlgOAEP
	AlgECDSA        = internal.TPMAlgECDSA
	AlgECDH         = internal.TPMAlgECDH
	AlgECDAA        = internal.TPMAlgECDAA
	AlgSM2          = internal.TPMAlgSM2
	AlgECSchnorr    = internal.TPMAlgECSchnorr
	AlgECMQV        = internal.TPMAlgECMQV
	AlgKDF1SP80056A = internal.TPMAlgKDF1SP80056A
	AlgKDF2         = internal.TPMAlgKDF2
	AlgKDF1SP800108 = internal.TPMAlgKDF1SP800108
	AlgECC          = internal.TPMAlgECC
	AlgSymCipher    = internal.TPMAlgSymCipher
	AlgCamellia     = internal.TPMAlgCamellia
	AlgSHA3256      = internal.TPMAlgSHA3256
	AlgSHA3384      = internal.TPMAlgSHA3384
	AlgSHA3512      = internal.TPMAlgSHA3512
	AlgCTR          = internal.TPMAlgCTR
	AlgOFB          = internal.TPMAlgOFB
	AlgCBC          = internal.TPMAlgCBC
	AlgCFB          = internal.TPMAlgCFB
	AlgECB          = internal.TPMAlgECB
)

// ECCCurve = internal.TPMECCCurve
const (
	ECCNone     = internal.TPMECCNone
	ECCNistP192 = internal.TPMECCNistP192
	ECCNistP224 = internal.TPMECCNistP224
	ECCNistP256 = internal.TPMECCNistP256
	ECCNistP384 = internal.TPMECCNistP384
	ECCNistP521 = internal.TPMECCNistP521
	ECCBNP256   = internal.TPMECCBNP256
	ECCBNP638   = internal.TPMECCBNP638
	ECCSM2P256  = internal.TPMECCSM2P256
)

// CC = internal.TPMCC
const (
	CCNVUndefineSpaceSpecial     = internal.TPMCCNVUndefineSpaceSpecial
	CCEvictControl               = internal.TPMCCEvictControl
	CCHierarchyControl           = internal.TPMCCHierarchyControl
	CCNVUndefineSpace            = internal.TPMCCNVUndefineSpace
	CCChangeEPS                  = internal.TPMCCChangeEPS
	CCChangePPS                  = internal.TPMCCChangePPS
	CCClear                      = internal.TPMCCClear
	CCClearControl               = internal.TPMCCClearControl
	CCClockSet                   = internal.TPMCCClockSet
	CCHierarchyChanegAuth        = internal.TPMCCHierarchyChanegAuth
	CCNVDefineSpace              = internal.TPMCCNVDefineSpace
	CCPCRAllocate                = internal.TPMCCPCRAllocate
	CCPCRSetAuthPolicy           = internal.TPMCCPCRSetAuthPolicy
	CCPPCommands                 = internal.TPMCCPPCommands
	CCSetPrimaryPolicy           = internal.TPMCCSetPrimaryPolicy
	CCFieldUpgradeStart          = internal.TPMCCFieldUpgradeStart
	CCClockRateAdjust            = internal.TPMCCClockRateAdjust
	CCCreatePrimary              = internal.TPMCCCreatePrimary
	CCNVGlobalWriteLock          = internal.TPMCCNVGlobalWriteLock
	CCGetCommandAuditDigest      = internal.TPMCCGetCommandAuditDigest
	CCNVIncrement                = internal.TPMCCNVIncrement
	CCNVSetBits                  = internal.TPMCCNVSetBits
	CCNVExtend                   = internal.TPMCCNVExtend
	CCNVWrite                    = internal.TPMCCNVWrite
	CCNVWriteLock                = internal.TPMCCNVWriteLock
	CCDictionaryAttackLockReset  = internal.TPMCCDictionaryAttackLockReset
	CCDictionaryAttackParameters = internal.TPMCCDictionaryAttackParameters
	CCNVChangeAuth               = internal.TPMCCNVChangeAuth
	CCPCREvent                   = internal.TPMCCPCREvent
	CCPCRReset                   = internal.TPMCCPCRReset
	CCSequenceComplete           = internal.TPMCCSequenceComplete
	CCSetAlgorithmSet            = internal.TPMCCSetAlgorithmSet
	CCSetCommandCodeAuditStatus  = internal.TPMCCSetCommandCodeAuditStatus
	CCFieldUpgradeData           = internal.TPMCCFieldUpgradeData
	CCIncrementalSelfTest        = internal.TPMCCIncrementalSelfTest
	CCSelfTest                   = internal.TPMCCSelfTest
	CCStartup                    = internal.TPMCCStartup
	CCShutdown                   = internal.TPMCCShutdown
	CCStirRandom                 = internal.TPMCCStirRandom
	CCActivateCredential         = internal.TPMCCActivateCredential
	CCCertify                    = internal.TPMCCCertify
	CCPolicyNV                   = internal.TPMCCPolicyNV
	CCCertifyCreation            = internal.TPMCCCertifyCreation
	CCDuplicate                  = internal.TPMCCDuplicate
	CCGetTime                    = internal.TPMCCGetTime
	CCGetSessionAuditDigest      = internal.TPMCCGetSessionAuditDigest
	CCNVRead                     = internal.TPMCCNVRead
	CCNVReadLock                 = internal.TPMCCNVReadLock
	CCObjectChangeAuth           = internal.TPMCCObjectChangeAuth
	CCPolicySecret               = internal.TPMCCPolicySecret
	CCRewrap                     = internal.TPMCCRewrap
	CCCreate                     = internal.TPMCCCreate
	CCECDHZGen                   = internal.TPMCCECDHZGen
	CCHMAC                       = internal.TPMCCHMAC
	CCMAC                        = internal.TPMCCMAC
	CCImport                     = internal.TPMCCImport
	CCLoad                       = internal.TPMCCLoad
	CCQuote                      = internal.TPMCCQuote
	CCRSADecrypt                 = internal.TPMCCRSADecrypt
	CCHMACStart                  = internal.TPMCCHMACStart
	CCMACStart                   = internal.TPMCCMACStart
	CCSequenceUpdate             = internal.TPMCCSequenceUpdate
	CCSign                       = internal.TPMCCSign
	CCUnseal                     = internal.TPMCCUnseal
	CCPolicySigned               = internal.TPMCCPolicySigned
	CCContextLoad                = internal.TPMCCContextLoad
	CCContextSave                = internal.TPMCCContextSave
	CCECDHKeyGen                 = internal.TPMCCECDHKeyGen
	CCEncryptDecrypt             = internal.TPMCCEncryptDecrypt
	CCFlushContext               = internal.TPMCCFlushContext
	CCLoadExternal               = internal.TPMCCLoadExternal
	CCMakeCredential             = internal.TPMCCMakeCredential
	CCNVReadPublic               = internal.TPMCCNVReadPublic
	CCPolicyAuthorize            = internal.TPMCCPolicyAuthorize
	CCPolicyAuthValue            = internal.TPMCCPolicyAuthValue
	CCPolicyCommandCode          = internal.TPMCCPolicyCommandCode
	CCPolicyCounterTimer         = internal.TPMCCPolicyCounterTimer
	CCPolicyCpHash               = internal.TPMCCPolicyCpHash
	CCPolicyLocality             = internal.TPMCCPolicyLocality
	CCPolicyNameHash             = internal.TPMCCPolicyNameHash
	CCPolicyOR                   = internal.TPMCCPolicyOR
	CCPolicyTicket               = internal.TPMCCPolicyTicket
	CCReadPublic                 = internal.TPMCCReadPublic
	CCRSAEncrypt                 = internal.TPMCCRSAEncrypt
	CCStartAuthSession           = internal.TPMCCStartAuthSession
	CCVerifySignature            = internal.TPMCCVerifySignature
	CCECCParameters              = internal.TPMCCECCParameters
	CCFirmwareRead               = internal.TPMCCFirmwareRead
	CCGetCapability              = internal.TPMCCGetCapability
	CCGetRandom                  = internal.TPMCCGetRandom
	CCGetTestResult              = internal.TPMCCGetTestResult
	CCHash                       = internal.TPMCCHash
	CCPCRRead                    = internal.TPMCCPCRRead
	CCPolicyPCR                  = internal.TPMCCPolicyPCR
	CCPolicyRestart              = internal.TPMCCPolicyRestart
	CCReadClock                  = internal.TPMCCReadClock
	CCPCRExtend                  = internal.TPMCCPCRExtend
	CCPCRSetAuthValue            = internal.TPMCCPCRSetAuthValue
	CCNVCertify                  = internal.TPMCCNVCertify
	CCEventSequenceComplete      = internal.TPMCCEventSequenceComplete
	CCHashSequenceStart          = internal.TPMCCHashSequenceStart
	CCPolicyPhysicalPresence     = internal.TPMCCPolicyPhysicalPresence
	CCPolicyDuplicationSelect    = internal.TPMCCPolicyDuplicationSelect
	CCPolicyGetDigest            = internal.TPMCCPolicyGetDigest
	CCTestParams                 = internal.TPMCCTestParams
	CCCommit                     = internal.TPMCCCommit
	CCPolicyPassword             = internal.TPMCCPolicyPassword
	CCZGen2Phase                 = internal.TPMCCZGen2Phase
	CCECEphemeral                = internal.TPMCCECEphemeral
	CCPolicyNvWritten            = internal.TPMCCPolicyNvWritten
	CCPolicyTemplate             = internal.TPMCCPolicyTemplate
	CCCreateLoaded               = internal.TPMCCCreateLoaded
	CCPolicyAuthorizeNV          = internal.TPMCCPolicyAuthorizeNV
	CCEncryptDecrypt2            = internal.TPMCCEncryptDecrypt2
	CCACGetCapability            = internal.TPMCCACGetCapability
	CCACSend                     = internal.TPMCCACSend
	CCPolicyACSendSelect         = internal.TPMCCPolicyACSendSelect
	CCCertifyX509                = internal.TPMCCCertifyX509
	CCACTSetTimeout              = internal.TPMCCACTSetTimeout
)

// RC = internal.TPMRC
const (
	RCSuccess = internal.TPMRCSuccess
	// FMT0 error codes
	RCInitialize      = internal.TPMRCInitialize
	RCFailure         = internal.TPMRCFailure
	RCSequence        = internal.TPMRCSequence
	RCPrivate         = internal.TPMRCPrivate
	RCHMAC            = internal.TPMRCHMAC
	RCDisabled        = internal.TPMRCDisabled
	RCExclusive       = internal.TPMRCExclusive
	RCAuthType        = internal.TPMRCAuthType
	RCAuthMissing     = internal.TPMRCAuthMissing
	RCPolicy          = internal.TPMRCPolicy
	RCPCR             = internal.TPMRCPCR
	RCPCRChanged      = internal.TPMRCPCRChanged
	RCUpgrade         = internal.TPMRCUpgrade
	RCTooManyContexts = internal.TPMRCTooManyContexts
	RCAuthUnavailable = internal.TPMRCAuthUnavailable
	RCReboot          = internal.TPMRCReboot
	RCUnbalanced      = internal.TPMRCUnbalanced
	RCCommandSize     = internal.TPMRCCommandSize
	RCCommandCode     = internal.TPMRCCommandCode
	RCAuthSize        = internal.TPMRCAuthSize
	RCAuthContext     = internal.TPMRCAuthContext
	RCNVRange         = internal.TPMRCNVRange
	RCNVSize          = internal.TPMRCNVSize
	RCNVLocked        = internal.TPMRCNVLocked
	RCNVAuthorization = internal.TPMRCNVAuthorization
	RCNVUninitialized = internal.TPMRCNVUninitialized
	RCNVSpace         = internal.TPMRCNVSpace
	RCNVDefined       = internal.TPMRCNVDefined
	RCBadContext      = internal.TPMRCBadContext
	RCCPHash          = internal.TPMRCCPHash
	RCParent          = internal.TPMRCParent
	RCNeedsTest       = internal.TPMRCNeedsTest
	RCNoResult        = internal.TPMRCNoResult
	RCSensitive       = internal.TPMRCSensitive
	// FMT1 error codes
	RCAsymmetric   = internal.TPMRCAsymmetric
	RCAttributes   = internal.TPMRCAttributes
	RCHash         = internal.TPMRCHash
	RCValue        = internal.TPMRCValue
	RCHierarchy    = internal.TPMRCHierarchy
	RCKeySize      = internal.TPMRCKeySize
	RCMGF          = internal.TPMRCMGF
	RCMode         = internal.TPMRCMode
	RCType         = internal.TPMRCType
	RCHandle       = internal.TPMRCHandle
	RCKDF          = internal.TPMRCKDF
	RCRange        = internal.TPMRCRange
	RCAuthFail     = internal.TPMRCAuthFail
	RCNonce        = internal.TPMRCNonce
	RCPP           = internal.TPMRCPP
	RCScheme       = internal.TPMRCScheme
	RCSize         = internal.TPMRCSize
	RCSymmetric    = internal.TPMRCSymmetric
	RCTag          = internal.TPMRCTag
	RCSelector     = internal.TPMRCSelector
	RCInsufficient = internal.TPMRCInsufficient
	RCSignature    = internal.TPMRCSignature
	RCKey          = internal.TPMRCKey
	RCPolicyFail   = internal.TPMRCPolicyFail
	RCIntegrity    = internal.TPMRCIntegrity
	RCTicket       = internal.TPMRCTicket
	RCReservedBits = internal.TPMRCReservedBits
	RCBadAuth      = internal.TPMRCBadAuth
	RCExpired      = internal.TPMRCExpired
	RCPolicyCC     = internal.TPMRCPolicyCC
	RCBinding      = internal.TPMRCBinding
	RCCurve        = internal.TPMRCCurve
	RCECCPoint     = internal.TPMRCECCPoint
	// Warnings
	RCContextGap     = internal.TPMRCContextGap
	RCObjectMemory   = internal.TPMRCObjectMemory
	RCSessionMemory  = internal.TPMRCSessionMemory
	RCMemory         = internal.TPMRCMemory
	RCSessionHandles = internal.TPMRCSessionHandles
	RCObjectHandles  = internal.TPMRCObjectHandles
	RCLocality       = internal.TPMRCLocality
	RCYielded        = internal.TPMRCYielded
	RCCanceled       = internal.TPMRCCanceled
	RCTesting        = internal.TPMRCTesting
	RCReferenceH0    = internal.TPMRCReferenceH0
	RCReferenceH1    = internal.TPMRCReferenceH1
	RCReferenceH2    = internal.TPMRCReferenceH2
	RCReferenceH3    = internal.TPMRCReferenceH3
	RCReferenceH4    = internal.TPMRCReferenceH4
	RCReferenceH5    = internal.TPMRCReferenceH5
	RCReferenceH6    = internal.TPMRCReferenceH6
	RCReferenceS0    = internal.TPMRCReferenceS0
	RCReferenceS1    = internal.TPMRCReferenceS1
	RCReferenceS2    = internal.TPMRCReferenceS2
	RCReferenceS3    = internal.TPMRCReferenceS3
	RCReferenceS4    = internal.TPMRCReferenceS4
	RCReferenceS5    = internal.TPMRCReferenceS5
	RCReferenceS6    = internal.TPMRCReferenceS6
	RCNVRate         = internal.TPMRCNVRate
	RCLockout        = internal.TPMRCLockout
	RCRetry          = internal.TPMRCRetry
	RCNVUnavailable  = internal.TPMRCNVUnavailable
)

// ST = internal.TPMST
const (
	STRspCommand         = internal.TPMSTRspCommand
	STNull               = internal.TPMSTNull
	STNoSessions         = internal.TPMSTNoSessions
	STSessions           = internal.TPMSTSessions
	STAttestNV           = internal.TPMSTAttestNV
	STAttestCommandAudit = internal.TPMSTAttestCommandAudit
	STAttestSessionAudit = internal.TPMSTAttestSessionAudit
	STAttestCertify      = internal.TPMSTAttestCertify
	STAttestQuote        = internal.TPMSTAttestQuote
	STAttestTime         = internal.TPMSTAttestTime
	STAttestCreation     = internal.TPMSTAttestCreation
	STAttestNVDigest     = internal.TPMSTAttestNVDigest
	STCreation           = internal.TPMSTCreation
	STVerified           = internal.TPMSTVerified
	STAuthSecret         = internal.TPMSTAuthSecret
	STHashCheck          = internal.TPMSTHashCheck
	STAuthSigned         = internal.TPMSTAuthSigned
	STFuManifest         = internal.TPMSTFuManifest
)

// SE = internal.TPMSE
const (
	SEHMAC   = internal.TPMSEHMAC
	SEPolicy = internal.TPMSEPolicy
	XETrial  = internal.TPMXETrial
)

// Cap = internal.TPMCap
const (
	CapAlgs          = internal.TPMCapAlgs
	CapHandles       = internal.TPMCapHandles
	CapCommands      = internal.TPMCapCommands
	CapPPCommands    = internal.TPMCapPPCommands
	CapAuditCommands = internal.TPMCapAuditCommands
	CapPCRs          = internal.TPMCapPCRs
	CapTPMProperties = internal.TPMCapTPMProperties
	CapPCRProperties = internal.TPMCapPCRProperties
	CapECCCurves     = internal.TPMCapECCCurves
	CapAuthPolicies  = internal.TPMCapAuthPolicies
	CapACT           = internal.TPMCapACT
)

// PTFamilyIndicator values come from Part 2: Structures, section  6.13.
const (
	// a 4-octet character string containing the  = internal.TPM
	// (_SPEC_FAMILY= internal.TPM_SPEC_FAMILY
	PTFamilyIndicator = internal.TPMPTFamilyIndicator
	// the level of the specification
	PTLevel = internal.TPMPTLevel
	// the specification Revision times 100
	PTRevision = internal.TPMPTRevision
	// the specification day of year using TCG calendar
	PTDayofYear = internal.TPMPTDayofYear
	// the specification year using the CE
	PTYear = internal.TPMPTYear
	// the vendor ID unique to each  = internal.TPM
	PTManufacturer = internal.TPMPTManufacturer
	// the first four characters of the vendor ID string
	PTVendorString1 = internal.TPMPTVendorString1
	// the second four characters of the vendor ID string
	PTVendorString2 = internal.TPMPTVendorString2
	// the third four characters of the vendor ID string
	PTVendorString3 = internal.TPMPTVendorString3
	// the fourth four characters of the vendor ID sting
	PTVendorString4 = internal.TPMPTVendorString4
	// vendor-defined value indicating the  = internal.TPM
	PTVendorTPMType = internal.TPMPTVendorTPMType
	// the most-significant 32 bits of a  = internal.TPM
	// indicating the version number of the firmware.
	PTFirmwareVersion1 = internal.TPMPTFirmwareVersion1
	// the least-significant 32 bits of a  = internal.TPM
	// indicating the version number of the firmware.
	// the maximum value for commandSize in a command
	PTMaxCommandSize = internal.TPMPTMaxCommandSize
	// the maximum value for responseSize in a response
	PTMaxResponseSize = internal.TPMPTMaxResponseSize
	// the maximum size of a digest that can be produced by the TPM
	PTMaxDigest = internal.TPMPTMaxDigest
	// the maximum size of an object context that will be returned by
	// TPM2_ContextSave
	PTMaxObjectContext = internal.TPMPTMaxObjectContext
	// the maximum size of a session context that will be returned by
	// TPM2_ContextSave
	PTMaxSessionContext = internal.TPMPTMaxSessionContext
	// platform-specific family (a TPM_PS value)(see Table 25)
	PTPSFamilyIndicator = internal.TPMPTPSFamilyIndicator
	// the number of split signing operations supported by the TPM
	PTSplitMax = internal.TPMPTSplitMax
	// total number of commands implemented in the TPM
	PTTotalCommands = internal.TPMPTTotalCommands
	// number of commands from the TPM library that are implemented
	PTLibraryCommands = internal.TPMPTLibraryCommands
	// number of vendor commands that are implemented
	PTVendorCommands = internal.TPMPTVendorCommands
	// the maximum data size in one NV write, NV read, NV extend, or NV
	// certify command
	PTNVBufferMax = internal.TPMPTNVBufferMax
	// a TPMA_MODES value, indicating that the TPM is designed for these
	// modes.
	PTModes = internal.TPMPTModes
	// the maximum size of a TPMS_CAPABILITY_DATA structure returned in
	// TPM2_GetCapability().
	PTMaxCapBuffer = internal.TPMPTMaxCapBuffer
	// TPMA_PERMANENT
	PTPermanent = internal.TPMPTPermanent
	// TPMA_STARTUP_CLEAR
	PTStartupClear = internal.TPMPTStartupClear
	// the number of NV Indexes currently defined
	PTHRNVIndex = internal.TPMPTHRNVIndex
	// the number of authorization sessions currently loaded into TPM RAM
	PTHRLoaded = internal.TPMPTHRLoaded
	// the number of additional authorization sessions, of any type, that
	// could be loaded into TPM RAM
	PTHRLoadedAvail = internal.TPMPTHRLoadedAvail
	// the number of active authorization sessions currently being tracked
	// by the TPM
	PTHRActive = internal.TPMPTHRActive
	// the number of additional authorization sessions, of any type, that
	// could be created
	PTHRActiveAvail = internal.TPMPTHRActiveAvail
	// estimate of the number of additional transient objects that could be
	// loaded into TPM RAM
	PTHRTransientAvail = internal.TPMPTHRTransientAvail
	// the number of persistent objects currently loaded into TPM NV memory
	PTHRPersistent = internal.TPMPTHRPersistent
	// the number of additional persistent objects that could be loaded into
	// NV memory
	PTHRPersistentAvail = internal.TPMPTHRPersistentAvail
	// the number of defined NV Indexes that have NV the TPM_NT_COUNTER
	// attribute
	PTNVCounters = internal.TPMPTNVCounters
	// the number of additional NV Indexes that can be defined with their
	// TPM_NT of TPM_NV_COUNTER and the TPMA_NV_ORDERLY attribute SET
	PTNVCountersAvail = internal.TPMPTNVCountersAvail
	// code that limits the algorithms that may be used with the TPM
	PTAlgorithmSet = internal.TPMPTAlgorithmSet
	// the number of loaded ECC curves
	PTLoadedCurves = internal.TPMPTLoadedCurves
	// the current value of the lockout counter (failedTries)
	PTLockoutCounter = internal.TPMPTLockoutCounter
	// the number of authorization failures before DA lockout is invoked
	PTMaxAuthFail = internal.TPMPTMaxAuthFail
	// the number of seconds before the value reported by
	// TPM_PT_LOCKOUT_COUNTER is decremented
	PTLockoutInterval = internal.TPMPTLockoutInterval
	// the number of seconds after a lockoutAuth failure before use of
	// lockoutAuth may be attempted again
	PTLockoutRecovery = internal.TPMPTLockoutRecovery
	// number of milliseconds before the TPM will accept another command
	// that will modify NV
	PTNVWriteRecovery = internal.TPMPTNVWriteRecovery
	// the high-order 32 bits of the command audit counter
	PTAuditCounter0 = internal.TPMPTAuditCounter0
	// the low-order 32 bits of the command audit counter
	PTAuditCounter1 = internal.TPMPTAuditCounter1
)

// TPMPTPCR values come from Part 2: Structures, section 6.14.
const (
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR is saved and
	// restored by TPM_SU_STATE
	PTPCRSave = internal.TPMPTPCRSave
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
	// extended from locality 0
	PTPCRExtendL0 = internal.TPMPTPCRExtendL0
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
	// by TPM2_PCR_Reset() from locality 0
	PTPCRResetL0 = internal.TPMPTPCRResetL0
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
	// extended from locality 1
	PTPCRExtendL1 = internal.TPMPTPCRExtendL1
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
	// by TPM2_PCR_Reset() from locality 1
	PTPCRResetL1 = internal.TPMPTPCRResetL1
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
	// extended from locality 2
	PTPCRExtendL2 = internal.TPMPTPCRExtendL2
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
	// by TPM2_PCR_Reset() from locality 2
	PTPCRResetL2 = internal.TPMPTPCRResetL2
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
	// extended from locality 3
	PTPCRExtendL3 = internal.TPMPTPCRExtendL3
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
	// by TPM2_PCR_Reset() from locality 3
	PTPCRResetL3 = internal.TPMPTPCRResetL3
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
	// extended from locality 4
	PTPCRExtendL4 = internal.TPMPTPCRExtendL4
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
	// by TPM2_PCR_Reset() from locality 4
	PTPCRResetL4 = internal.TPMPTPCRResetL4
	// a SET bit in the TPMS_PCR_SELECT indicates that modifications to this
	// PCR (reset or Extend) will not increment the pcrUpdateCounter
	PTPCRNoIncrement = internal.TPMPTPCRNoIncrement
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR is reset by a
	// D-RTM event
	PTPCRDRTMRest = internal.TPMPTPCRDRTMRest
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR is controlled
	// by policy
	PTPCRPolicy = internal.TPMPTPCRPolicy
	// a SET bit in the TPMS_PCR_SELECT indicates that the PCR is controlled
	// by an authorization value
	PTPCRAuth = internal.TPMPTPCRAuth
)

// TPMHandle values come from Part 2: Structures, section 7.4.
const (
	RHOwner       = internal.TPMRHOwner
	RHNull        = internal.TPMRHNull
	RSPW          = internal.TPMRSPW
	RHLockout     = internal.TPMRHLockout
	RHEndorsement = internal.TPMRHEndorsement
	RHPlatform    = internal.TPMRHPlatform
	RHPlatformNV  = internal.TPMRHPlatformNV
)
