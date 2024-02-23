#!/bin/sh
#
# A POSIX-compliant shell script
#

set -o errexit  # Exits immediately on unexpected errors (does not bypass traps)
set -o nounset  # Errors if variables are used without first being defined

################################################################################
##                                  USAGE
################################################################################

USAGE="USAGE: ${0} [FLAGS]
    unseals information sealed tog this system's endorsement key

FLAGS
  -h       prints this help
  -0       read the encrypted data via stdin as the TPM2B_PUBLIC, TPM2B_PRIVATE,
           and TPM2B_ENCRYPTED_SECRET data structures serialized as binary data,
           encoded with base64, and delimited with '@@NULL@@'
  -u PATH  a binary file with the encrypted data's TPM2B_PUBLIC struct
  -i PATH  a binary file with the encrypted data's TPM2B_PRIVATE struct
  -s PATH  a binary file with the encrypted data's TPM2B_ENCRYPTED_SECRET struct
  -G ALG   ek algorithm. valid choices are rsa and ecc. defaults to rsa
"

################################################################################
##                               TPM_HANDLES
################################################################################

TPK_EK_CRT='0x01C00002'          # reserved handle for endorsement key cert
                                 # - https://via.vmw.com/tpm2-provisioning-guide

TPM_RH_ENDORSEMENT='0x4000000B'  # reserved handle for endorsement primary seed
                                 # - https://via.vmw.com/TPM_RH_ENDORSEMENT
                                 # - https://via.vmw.com/tpm2-structs


################################################################################
##                               temp files
################################################################################

# Create some temporary files used in decrypting the data.
EK_CTX="$(mktemp)";       rm -f "${EK_CTX}"
SESSION_DAT="$(mktemp)";  rm -f "${SESSION_DAT}"
ENC_OBJ_CTX="$(mktemp)";  rm -f "${ENC_OBJ_CTX}"
ENC_OBJ_KEY="$(mktemp)";  rm -f "${ENC_OBJ_KEY}"
ENC_OBJ_PUB="$(mktemp)";  rm -f "${ENC_OBJ_PUB}"
ENC_OBJ_PRIV="$(mktemp)"; rm -f "${ENC_OBJ_PRIV}"
ENC_OBJ_SEED="$(mktemp)"; rm -f "${ENC_OBJ_SEED}"


################################################################################
##                               flag values
################################################################################

READ_STDIN=""
EK_ALG="rsa"


################################################################################
##                                   funcs
################################################################################

# error stores exit code, writes arguments to STDERR, and returns stored exit
# code fatal is like error except it will exit program if exit code >0
error() {
  exit_code="${?}"
  echo "${@}" 1>&2
  return "${exit_code}"
}
fatal() {
  error "${@}"
  exit_code="${?}"
  [ "${exit_code}" -gt "0" ] || exit_code=1
  exit "${exit_code}"
}
check_command() {
  command -v "${1}" >/dev/null 2>&1 || fatal "${1} is required"
}
check_dependencies() {
  check_command tpm2_createek         # https://via.vmw.com/tpm2_createek.md
  check_command tpm2_flushcontext     # https://via.vmw.com/tpm2_flushcontext.md
  check_command tpm2_import           # https://via.vmw.com/tpm2_import.md
  check_command tpm2_load             # https://via.vmw.com/tpm2_load.md
  check_command tpm2_nvread           # https://via.vmw.com/tpm2_nvread.md
  check_command tpm2_policysecret     # https://via.vmw.com/tpm2_policysecret.md
  check_command tpm2_readpublic       # https://via.vmw.com/tpm2_readpublic.md
  check_command tpm2_startauthsession # https://via.vmw.com/tpm2_startauthsession.md
  check_command tpm2_unseal           # https://via.vmw.com/tpm2_unseal.md
}
cleanup() {
  # remove any temp files that might exist
  rm -f "${EK_CTX}" \
        "${SESSION_DAT}" \
        "${ENC_OBJ_CTX}" \
        "${ENC_OBJ_KEY}" \

  # only delete the encrypted object's public, private, and seed files if they
  # were created as temporary files due to the input coming from stdin
  if [ "${READ_STDIN}" = "1" ]; then
    rm -f "${ENC_OBJ_PUB}" \
          "${ENC_OBJ_PRIV}" \
          "${ENC_OBJ_SEED}"
  fi
}


################################################################################
##                                   main
################################################################################

# Clean up any lingering files on exit.
trap cleanup EXIT

# Verify the required dependencies are met.
check_dependencies

# Parse the command line arguments
while getopts ":h0u:i:s:G:" opt; do
  case ${opt} in
    h)
      fatal "${USAGE}"
      ;;
    0)
      READ_STDIN="1"
      ;;
    u)
      ENC_OBJ_PUB="${OPTARG}"
      ;;
    i)
      ENC_OBJ_PRIV="${OPTARG}"
      ;;
    s)
      ENC_OBJ_SEED="${OPTARG}"
      ;;
    G)
      EK_ALG="${OPTARG}"
      ;;
    *)
      # Ignore other flags
      ;;
  esac
done
shift $((OPTIND - 1))

if [ "${READ_STDIN}" = "1" ]; then
  read -r stdin
  echo "${stdin}" | awk -F'@@NULL@@' '{print $1}' | base64 -d >"${ENC_OBJ_PUB}"
  echo "${stdin}" | awk -F'@@NULL@@' '{print $2}' | base64 -d >"${ENC_OBJ_PRIV}"
  echo "${stdin}" | awk -F'@@NULL@@' '{print $3}' | base64 -d >"${ENC_OBJ_SEED}"
fi

if [ ! "${EK_ALG:-}" = "rsa" ] && [ ! "${EK_ALG:-}" = "ecc" ]; then
  fatal "-G ${EK_ALG:-} is invalid. valid choices are rsa or ecc"
fi


#
# VALIDATE EK CERT
#

# vSphere VMs with a vTPM have an EK certificate in their NVRAM at the address
# TPK_EK_CRT. Exit with an error if this certificate does not exist.
tpm2_nvread "${TPK_EK_CRT}" >/dev/null 2>&1 || fatal "missing ek cert"


#
# CREATE EK
#

# While vSphere VMs with a vTPM have an EK certificate in their NVRAM, the
# actual EK is not created by default.
tpm2_createek -c "${EK_CTX}" -G "${EK_ALG}" 1>&2


#
# IMPORT
#

# Create an authentication session with the TPM in order to use it to unseal
# the provided data.
tpm2_startauthsession --policy-session -S "${SESSION_DAT}" 1>&2

# Couple the authentication session with the EK's primary seed.
tpm2_policysecret -c "${TPM_RH_ENDORSEMENT}" -S "${SESSION_DAT}" 1>&2

# Import the encrypted object's cryptographic information as a child of the EK
# and persist to disk the encrypted, private portion of the object to be
# decrypted.
tpm2_import \
  -C "${EK_CTX}" \
  -P "session:${SESSION_DAT}" \
  -u "${ENC_OBJ_PUB}" \
  -i "${ENC_OBJ_PRIV}" \
  -s "${ENC_OBJ_SEED}" \
  -r "${ENC_OBJ_KEY}" 1>&2

# Flush the session context.
tpm2_flushcontext "${SESSION_DAT}" 1>&2

#
# LOAD
#

# Create an authentication session with the TPM in order to use it to unseal
# the provided data.
tpm2_startauthsession --policy-session -S "${SESSION_DAT}" 1>&2

# Couple the authentication session with the EK's primary seed.
tpm2_policysecret -c "${TPM_RH_ENDORSEMENT}" -S "${SESSION_DAT}" 1>&2

# Load the encrypted object into the specified context file so it can be
# unsealed. This step requires the key from the previous step.
tpm2_load \
  -C "${EK_CTX}" \
  -P "session:${SESSION_DAT}" \
  -u "${ENC_OBJ_PUB}" \
  -r "${ENC_OBJ_KEY}" \
  -c "${ENC_OBJ_CTX}" 1>&2

# Flush the session context.
tpm2_flushcontext "${SESSION_DAT}" 1>&2

#
# UNSEAL
#

# Create an authentication session with the TPM in order to use it to unseal
# the provided data.
tpm2_startauthsession --policy-session -S "${SESSION_DAT}" 1>&2

tpm2_unseal -p "session:${SESSION_DAT}" -c "${ENC_OBJ_CTX}"

# Flush the session context.
tpm2_flushcontext "${SESSION_DAT}" 1>&2
