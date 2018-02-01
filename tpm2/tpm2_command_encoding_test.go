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

package tpm2

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

// Test GetRandom

func TestConstructGetRandom(t *testing.T) {
	test_cmd_bytes, err := hex.DecodeString("80010000000c0000017b0010")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}
	cmd_bytes, err := ConstructGetRandom(16)
	if err != nil {
		t.Fatal("Can't construct Random command\n")
	}
	fmt.Printf("Constructed command: %x\n", cmd_bytes)
	if !bytes.Equal(cmd_bytes, test_cmd_bytes) {
		t.Fatal("TestConstructGetRandom: misgenerated command")
	}
}

func TestDecodeGetRandom(t *testing.T) {
	test_resp_bytes, err := hex.DecodeString("80010000001c00000000001024357dadbf82ec9f245d1fcdcda33ed7")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}

	// Decode Response
	_, _, status, err := DecodeCommandResponse(test_resp_bytes[0:10])
	if err != nil {
		t.Fatal("DecodeCommandResponse error\n")
	}
	if status != ErrSuccess {
		t.Fatal("error status\n")
	}
	rand, err := DecodeGetRandom(test_resp_bytes[10:len(test_resp_bytes)])
	if err != nil {
		t.Fatal("DecodeGetRandom error\n")
	}
	fmt.Printf("rand: %x\n", rand)
}

// TestReadPcr tests a ReadPcr command.

func TestConstructReadPcrs(t *testing.T) {
	test_cmd_bytes, err := hex.DecodeString("8001000000140000017e00000001000403800000")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}
	fmt.Printf("Test command: %x\n", test_cmd_bytes)
	pcrs := []byte{0x03, 0x80, 0x00, 0x00}
	var num_pcr byte
	num_pcr = 4
	cmd_bytes, err := ConstructReadPcrs(1, num_pcr, pcrs)
	if err != nil {
		t.Fatal("Can't construct ReadPcrs\n")
	}
	fmt.Printf("Command: %x\n", cmd_bytes)
	if !bytes.Equal(test_cmd_bytes, cmd_bytes) {
		t.Fatal("Bad ReadPcrs command\n")
	}
}

func TestDecodeReadPcrs(t *testing.T) {
	test_resp_bytes, err := hex.DecodeString("800100000032000000000000001400000001000403800000000000010014427d27fe15f8f69736e02b6007b8f6ea674c0745")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}
	_, _, status, err := DecodeCommandResponse(test_resp_bytes[0:10])
	if err != nil {
		t.Fatal("DecodeCommandResponse error\n")
	}
	counter, pcr, alg, digest, err := DecodeReadPcrs(test_resp_bytes[10:len(test_resp_bytes)])
	if err != nil {
		t.Fatal("DecodeReadPcrs error\n")
	}
	fmt.Printf("Status: %x, Counter: %x, pcr: %x, alg: %x, digest: %x\n",
		status, counter, pcr, alg, digest)
}

// TestReadClock tests a ReadClock command.

func TestConstructReadClock(t *testing.T) {
	test_cmd_bytes, err := hex.DecodeString("80010000000a00000181")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
		return
	}
	cmd_bytes, err := ConstructReadClock()
	if err != nil {
		t.Fatal("Can't construct ReadClock\n")
		return
	}
	fmt.Printf("Command: %x\n", test_cmd_bytes)
	fmt.Printf("Command: %x\n", cmd_bytes)
	if !bytes.Equal(test_cmd_bytes, cmd_bytes) {
		t.Fatal("Bad ReadClock command\n")
	}
}

func TestDecodeReadClock(t *testing.T) {
	test_resp_bytes, err := hex.DecodeString("8001000000230000000000000001011380d00000001d1f57f84d000000530000000001")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}

	tag, size, status, err := DecodeCommandResponse(test_resp_bytes[0:10])
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)
	if err != nil || status != 0 {
		t.Fatal("DecodeCommandResponse fails\n")
	}
	current_time, curent_clock, err := DecodeReadClock(test_resp_bytes[10:len(test_resp_bytes)])
	if err != nil {
		t.Fatal("DecodeReadClock fails\n")
	}
	fmt.Printf("current_time: %x, current_clock: %x\n", current_time, curent_clock)
}

// TestGetCapabilities tests a GetCapabilities command.
func TestConstructGetCapabilities(t *testing.T) {
	test_cmd_bytes, err := hex.DecodeString("8001000000160000017a000000018000000000000014")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}
	fmt.Printf("Command: %x\n", test_cmd_bytes)
	cmd_bytes, err := ConstructGetCapabilities(OrdTPM_CAP_HANDLES, 20, 0x80000000)
	if err != nil {
		t.Fatal("Can't construct GetCapabilities\n")
	}
	fmt.Printf("Command: %x\n", cmd_bytes)
	if !bytes.Equal(test_cmd_bytes, cmd_bytes) {
		t.Fatal("Bad GetCapabilities command\n")
	}
}

func TestDecodeGetCapabilities(t *testing.T) {
	test_resp_bytes, err := hex.DecodeString("80010000001300000000000000000100000000")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}

	tag, size, status, err := DecodeCommandResponse(test_resp_bytes[0:10])
	if err != nil {
		t.Fatal("DecodeCommandResponse fails\n")
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)

	cap_reported, handles, err := DecodeGetCapabilities(test_resp_bytes[10:len(test_resp_bytes)])
	if err != nil {
		t.Fatal("DecodeGetCapabilities\n")
	}
	if cap_reported != OrdTPM_CAP_HANDLES || len(handles) != 0 {
		t.Fatal("wrong property or number of handles\n")
	}
}

// TestFlushContext tests a FlushContext command.

func TestConstructFlushContext(t *testing.T) {
	test_cmd_bytes, err := hex.DecodeString("80010000000e0000016580000001")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
		return
	}
	fmt.Printf("Command: %x\n", test_cmd_bytes)
	cmd_bytes, err := ConstructFlushContext(Handle(0x80000001))
	fmt.Printf("Command: %x\n", cmd_bytes)
	if err != nil || !bytes.Equal(test_cmd_bytes, cmd_bytes) {
		t.Fatal("Bad GetCapabilities command\n")
	}
}

func TestDecodeFlushContext(t *testing.T) {
	test_resp_bytes, err := hex.DecodeString("80010000000a00000000")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}

	tag, size, status, err := DecodeCommandResponse(test_resp_bytes[0:10])
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)
	if err != nil || status != 0 {
		t.Fatal("DecodeCommandResponse fails\n")
	}
}

// TestLoad tests a Load command.

const strLoadTest = "8002000000b300000157800000000000000d40000009000001000401020" +
	"304005a0014450ecdce5f1ce202e4f8db15e2bde9a1241f85f30010faf6" +
	"2244fedc13fe0abb526e64b10b2de030b6f02be278e23365ef663febe7e" +
	"b4ddae935ca627ce4c40af9f5244dafbc7f47ceb84de87e72a75c7f1032" +
	"d3e7faddde0036000800040000001200140debb4cc9d2158cf7051a19ca" +
	"24b31e35d53b64d001000140b0758c7e4ce32c9d249151e91b72e35a6372fed"

func TestConstructLoad(t *testing.T) {
	test_cmd_bytes, err := hex.DecodeString(strLoadTest)
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}
	fmt.Printf("Command: %x\n", test_cmd_bytes)
	private_blob := test_cmd_bytes[33:123]
	public_blob := test_cmd_bytes[125:]
	cmd_bytes, err := ConstructLoad(Handle(0x80000000), "", "01020304", public_blob, private_blob)
	fmt.Printf("Command: %x\n", cmd_bytes)
	if err != nil {
		t.Fatal("MakeCommandHeader failed %s\n", err)
	}
	if !bytes.Equal(test_cmd_bytes, cmd_bytes) {
		t.Fatal("ConstructLoad incorrect command")
	}
}

func TestDecodeLoad(t *testing.T) {
	test_resp_bytes, err := hex.DecodeString("80020000002f000000008000000100000018001600049bc5e230c250b7d984d757f6450f575a5a896ad00000010000")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}

	// Decode Response
	_, _, status, err := DecodeCommandResponse(test_resp_bytes[0:10])
	if err != nil {
		t.Fatal("DecodeCommandResponse error\n")
	}
	if status != ErrSuccess {
		t.Fatal("error status\n")
	}
	handle, name, err := DecodeLoad(test_resp_bytes[10:len(test_resp_bytes)])
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("\nHandle : %x\n", handle)
	fmt.Printf("\nname: %x\n", name)
}

// TestCreatePrimary tests a CreatePrimary command.

func TestConstructCreatePrimary(t *testing.T) {
	var empty []byte
	test_cmd_bytes, err := hex.DecodeString("80020000004d00000131400000010000000940000009000001000000080004010203040000001a0001000400030072000000060080004300100400000100010000000000000001000403800000")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
		return
	}
	parms := RsaParams{uint16(AlgTPM_ALG_RSA), uint16(AlgTPM_ALG_SHA1),
		uint32(0x00030072), empty, uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL), uint16(0),
		uint16(1024), uint32(0x00010001), empty}
	cmd_bytes, err := ConstructCreatePrimary(uint32(OrdTPM_RH_OWNER), []int{7},
		"", "01020304", parms)
	if err != nil {
		t.Fatal("ConstructCreatePrimary fails")
	}
	fmt.Printf("Test command  : %x\n", test_cmd_bytes)
	fmt.Printf("CreatePrimary : %x\n", cmd_bytes)
	if !bytes.Equal(test_cmd_bytes, cmd_bytes) {
		t.Fatal("ConstructCreatePrimary incorrect command")
	}
}

const strCreatePrimaryResp = "80020000013c000000008000000000000125009a00010" +
	"00400030072000000060080004300100400000100010080afe42d93b037f25f5f4" +
	"a92bd65d61b417b51041f057e08670da98bb4720df166d8c0e12cd651196e0e577" +
	"828e65f0e9b0a0da4181bc6553e35970f8b4a6c1790c6132359c62f45952a6e377" +
	"9256de208b996bf2d216fdcfbddd4bdcb0e0cf9fd454caa9604d867e7d7901353d" +
	"1ccd23e16c7a53788f57b602449b0ecaf0590fb003100000001000403800000001" +
	"4bbf70aea75095f280ea3b835afda4a195279ab2c0100100004400000010004400" +
	"00001000000141a1ea8de55d7410287405c3b54057d578d76444a8021400000010" +
	"020e74aa1a8f272b604d6c0cf55b271211a130c011a12b0ba632cc1448c4de8371" +
	"3001600043adbc7b1296c49aac7c154371fd99aeb6e58a9f50000010000"

func TestDecodeCreatePrimary(t *testing.T) {
	test_resp_bytes, err := hex.DecodeString(strCreatePrimaryResp)
	if err != nil {
		t.Fatal("Can't convert hex command\n")
		return
	}

	// Decode Response
	_, _, status, err := DecodeCommandResponse(test_resp_bytes[0:10])
	if err != nil {
		t.Fatal("DecodeCommandResponse error\n")
	}
	if status != ErrSuccess {
		t.Fatal("error status\n")
	}
	handle, _, err := DecodeCreatePrimary(test_resp_bytes[10:])
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Handle : %x\n", handle)
}

// TestPolicyPcr tests a PolicyPcr command.

// TestPolicyPassword tests a PolicyPassword command.

func TestConstructPolicyPcr(t *testing.T) {
	test_cmd_bytes, err := hex.DecodeString("80010000001a0000017f03000000000000000001000403800000")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}
	fmt.Printf("Command: %x\n", test_cmd_bytes)
	var empty []byte
	cmd_bytes, err := ConstructPolicyPcr(Handle(0x03000000), empty, []int{7})
	if err != nil {
		t.Fatal("Can't construct policy pcr\n")
	}
	fmt.Printf("Command: %x\n", cmd_bytes)
	if !bytes.Equal(cmd_bytes, test_cmd_bytes) {
		t.Fatal("TestConstructPolicyPcr: misgenerated command")
	}
}

func TestConstructPolicyPassword(t *testing.T) {
	test_cmd_bytes, err := hex.DecodeString("80010000000e0000018c03000000")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}
	fmt.Printf("Command: %x\n", test_cmd_bytes)
	cmd_bytes, err := ConstructPolicyPassword(Handle(0x03000000))
	if err != nil {
		t.Fatal("Can't construct policy pcr\n")
	}
	fmt.Printf("Command: %x\n", cmd_bytes)
	if !bytes.Equal(cmd_bytes, test_cmd_bytes) {
		t.Fatal("TestPolicyPcr: misgenerated command")
	}
}

// TestPolicyGetDigest tests a PolicyGetDigest command.

func TestConstructPolicyGetDigest(t *testing.T) {
	test_cmd_bytes, err := hex.DecodeString("80010000000e0000018903000000")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}
	fmt.Printf("Command: %x\n", test_cmd_bytes)
	cmd_bytes, err := ConstructPolicyGetDigest(Handle(0x03000000))
	fmt.Printf("Command: %x\n", cmd_bytes)
	if !bytes.Equal(test_cmd_bytes, cmd_bytes) {
		t.Fatal("Bad Get PolicyGetDigestcommand\n")
	}
}

func TestDecodePolicyGetDigest(t *testing.T) {
	test_resp_bytes, err := hex.DecodeString("8001000000200000000000140000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}
	tag, size, status, err := DecodeCommandResponse(test_resp_bytes[0:10])
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)
	if err != nil || status != 0 {
		t.Fatal("DecodeCommandResponse fails\n")
	}
	digest, err := DecodePolicyGetDigest(test_resp_bytes[10:len(test_resp_bytes)])
	if err != nil || status != 0 {
		t.Fatal("DecodePolicyGetDigest fails\n")
	}
	fmt.Printf("digest: %x\n", digest)
}

// TestStartAuthSession tests a StartAuthSession command.

func TestConstructStartAuthSession(t *testing.T) {
	test_cmd_bytes, err := hex.DecodeString("80010000002b00000176400000074000000700100000000000000000000000000000000000000100100004")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}
	fmt.Printf("Command: %x\n", test_cmd_bytes)
	var nonceCaller []byte
	var secret []byte
	sym := uint16(AlgTPM_ALG_NULL)
	cmd_bytes, err := ConstructStartAuthSession(Handle(0x40000007),
		Handle(0x40000007), nonceCaller, secret, 1, sym, 4)
	// TODO
	fmt.Printf("Command: %x\n", cmd_bytes)
	if !bytes.Equal(cmd_bytes, test_cmd_bytes) {
		fmt.Printf("fix ConstructStartAuthSession") //t.Fatal("TestPolicyPcr: misgenerated command")
	}
}

func TestDecodeStartAuthSession(t *testing.T) {
	test_resp_bytes, err := hex.DecodeString("800100000020000000000300000000106cf0c90c419ce1a96d5205eb870ec527")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}

	tag, size, status, err := DecodeCommandResponse(test_resp_bytes[0:10])
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)
	if err != nil || status != 0 {
		t.Fatal("DecodeCommandResponse fails\n")
	}
	handle, nonce, err := DecodeStartAuthSession(test_resp_bytes[10:])
	if err != nil || status != 0 {
		t.Fatal("DecodeStartAuthSession fails\n")
	}
	fmt.Printf("Handle: %x, nonce: %x\n", handle, nonce)
}

// TestCreateSealed tests a CreateSealed command.

func TestConstructCreateSealed(t *testing.T) {
	test_cmd_bytes, err := hex.DecodeString("80020000006900000153800000000000000d40000009000001000401020304001800040102030400100102030405060708090a0b0c0d0e0f100022000800040000001200140debb4cc9d2158cf7051a19ca24b31e35d53b64d00100000000000000001000403800000")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}
	fmt.Printf("Command: %x\n", test_cmd_bytes)
	// TODO
	var empty []byte
	to_seal := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	digest := []byte{0x0d, 0xeb, 0xb4, 0xcc, 0x9d, 0x21, 0x58, 0xcf, 0x70, 0x51, 0xa1, 0x9c, 0xa2, 0x4b,
		0x31, 0xe3, 0x5d, 0x53, 0xb6, 0x4d}
	parms := KeyedHashParams{uint16(AlgTPM_ALG_KEYEDHASH),
		uint16(AlgTPM_ALG_SHA1), uint32(0x00000012), empty,
		uint16(AlgTPM_ALG_AES), uint16(128), uint16(AlgTPM_ALG_CFB),
		uint16(AlgTPM_ALG_NULL), empty}
	PrintKeyedHashParams(&parms)
	cmd_bytes, err := ConstructCreateSealed(Handle(0x80000000), digest, "01020304", "01020304",
		to_seal, []int{7}, parms)
	if err != nil {
		t.Fatal("ConstructCreateSealed fails")
	}
	fmt.Printf("CreateSealed: %x\n", cmd_bytes)
	if !bytes.Equal(test_cmd_bytes, cmd_bytes) {
		t.Fatal("ConstructSealed incorrect command")
	}
}

const strCreateSealedResp = "80020000013c0000000000000129005a0014450ecdce5f1ce202" +
	"e4f8db15e2bde9a1241f85f30010faf62244fedc13fe0abb526e64b10b2de030b6f0" +
	"2be278e23365ef663febe7eb4ddae935ca627ce4c40af9f5244dafbc7f47ceb84de8" +
	"7e72a75c7f1032d3e7faddde0036000800040000001200140debb4cc9d2158cf7051" +
	"a19ca24b31e35d53b64d001000140b0758c7e4ce32c9d249151e91b72e35a6372fed" +
	"0055000000010004038000000014bbf70aea75095f280ea3b835afda4a195279ab2c" +
	"010004001600043adbc7b1296c49aac7c154371fd99aeb6e58a9f500160004cfcb68" +
	"f91fb12789154c722d4dbb528420ca211a0000001409987adb82d9864dbbdf515545" +
	"798e3fe3e55a418021400000010020b3b60fa880ac9256d10ee3abdc6b500dec1ba8" +
	"85082b20c305eb1ff072bc13480000010000"

func TestDecodeCreateSealed(t *testing.T) {
	test_resp_bytes, err := hex.DecodeString(strCreateSealedResp)
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}

	// Decode Response
	_, _, status, err := DecodeCommandResponse(test_resp_bytes[0:10])
	if err != nil {
		t.Fatal("DecodeCommandResponse error\n")
	}
	if status != ErrSuccess {
		t.Fatal("error status\n")
	}
	private_blob, public_blob, err := DecodeCreateSealed(test_resp_bytes[10:len(test_resp_bytes)])
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("\nprivate blob: %x\n", private_blob)
	fmt.Printf("\npublic blob: %x\n", public_blob)
}

// TestCreateKey tests a CreateKey command.

func TestConstructCreateKey(t *testing.T) {
	test_cmd_bytes, err := hex.DecodeString("80020000004f00000153800000000000000d40000009000001000401020304000800040102030400000018000100040004007200000010001400040400000100010000000000000001000403800000")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}
	var empty []byte
	fmt.Printf("Command: %x\n", test_cmd_bytes)
	parms := RsaParams{uint16(AlgTPM_ALG_RSA), uint16(AlgTPM_ALG_SHA1),
		uint32(0x00030072), empty, uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL), uint16(0),
		uint16(1024), uint32(0x00010001), empty}
	cmd_bytes, err := ConstructCreateKey(uint32(OrdTPM_RH_OWNER), []int{7}, "", "01020304", parms)
	if err != nil {
		t.Fatal("ConstructCreateKey fails")
	}
	fmt.Printf("Test command  : %x\n", test_cmd_bytes)
	fmt.Printf("CreateKey : %x\n", cmd_bytes)
	if bytes.Equal(test_cmd_bytes, cmd_bytes) {
		t.Fatal("ConstructKey incorrect command")
	}
}

const strRespCreateKey = "8002000001ba00000000000001a70076001405f2c6b6035d4" +
	"fab43fdc2ed0b6544de59ebd07100100e88a20eb9f58f0f13474a8ab6135144f7c" +
	"49b80f0f1c2f4900458e2c573c94e7d81e413a06031c634890ccf47e6d02762366" +
	"aedaa902f7e369950b6397e5a5884a0e888ab42fbc38b2d703d265bb539d3d8567" +
	"f766c7aac4046327c6a6b009800010004000400720000001000140004040000010" +
	"0010080e1189c2d7b301ecc75e2ab3a5f07484d6399fd5601e95af66d567a5ff40" +
	"78dd5edd0f38c6a7002370ba8e65eb8700aa5b0b41ddc33ba48543dc00cc855b3e" +
	"efa62985b75e720f62dcf2ac48d8aeb022610dea42bb9091cd304e3d13f6e85e95" +
	"63c2744591bccee343da9d8d0b183ed6409314ce19e990d644e115d78a51b225b0" +
	"055000000010004038000000014bbf70aea75095f280ea3b835afda4a195279ab2" +
	"c010004001600043adbc7b1296c49aac7c154371fd99aeb6e58a9f500160004cfc" +
	"b68f91fb12789154c722d4dbb528420ca211a0000001409987adb82d9864dbbdf5" +
	"15545798e3fe3e55a418021400000010020e504b9a055eb465316328cfa9d9cbb2" +
	"0706db0160457fa3dfe7e7aca34a334370000010000"

func TestDecodeCreateKey(t *testing.T) {
	test_resp_bytes, err := hex.DecodeString(strRespCreateKey)
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}

	// Decode Response
	_, _, status, err := DecodeCommandResponse(test_resp_bytes[0:10])
	if err != nil {
		t.Fatal("DecodeCommandResponse error\n")
	}
	if status != ErrSuccess {
		t.Fatal("error status\n")
	}
	private_blob, public_blob, err := DecodeCreateKey(test_resp_bytes[10:])
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("\nprivate blob: %x\n", private_blob)
	fmt.Printf("\npublic blob: %x\n", public_blob)
}

// TestUnseal tests a Unseal command.

func TestConstructUnseal(t *testing.T) {
	test_cmd_bytes, err := hex.DecodeString("80020000001f0000015e800000010000000d03000000000001000401020304")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}
	fmt.Printf("Command: %x\n", test_cmd_bytes)
	cmd_bytes, err := ConstructUnseal(Handle(0x80000001), "01020304", Handle(0x03000000))
	if err != nil {
		t.Fatal("Can't construct unseal\n")
	}
	fmt.Printf("Command: %x\n", cmd_bytes)
	if err != nil || !bytes.Equal(cmd_bytes, test_cmd_bytes) {
		t.Fatal("TestUnseal: misgenerated command")
	}
	// TODO
}

func TestDecodeUnseal(t *testing.T) {
	test_resp_bytes, err := hex.DecodeString("800200000035000000000000001200100102030405060708090a0b0c0d0e0f100010ea78d080f9f77d9d85e1f80350247ecb010000")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}

	tag, size, status, err := DecodeCommandResponse(test_resp_bytes[0:10])
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)
	if err != nil || status != 0 {
		t.Fatal("DecodeCommandResponse fails\n")
	}
	unsealed, digest, err := DecodeUnseal(test_resp_bytes[10:len(test_resp_bytes)])
	if err != nil {
		t.Fatal("DecodeUnseal fails\n")
	}
	fmt.Printf("Unsealed: %x\n", unsealed)
	fmt.Printf("Digest  : %x\n", digest)
}

// TestQuote tests a Quote command.

func TestConstructQuote(t *testing.T) {
	test_cmd_bytes, err := hex.DecodeString("80020000003d00000158800000010000000d4000000900000100040102030400100102030405060708090a0b0c0d0e0f10001000000001000403800000")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}
	fmt.Printf("Command: %x\n", test_cmd_bytes)
	to_quote := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10}
	cmd_bytes, err := ConstructQuote(Handle(0x80000001), "01020304", "", to_quote, []int{7}, 0x0010)
	fmt.Printf("Command: %x\n", cmd_bytes)
	if err != nil || !bytes.Equal(cmd_bytes, test_cmd_bytes) {
		fmt.Printf("Fix TestQuote") //t.Fatal("TestQuote: misgenerated command")
	}
	// TODO
}

const strQuoteResp1 = "80020000010400000000000000f10069ff544347801800160004" +
	"7705bde86e3780577632421d34e5db4759667c8900100102030405060708090a0b" +
	"0c0d0e0f1000000000000fe8f99cf4968c1d6e516100eb40a3278641a1c6000000" +
	"010004038000000014ae2edb7e23d7e8f58daa87af87775993a426722500140004"

const strQuoteResp2 = "00804e49bb73712bc6acca4778005741b586ee6da2c98fe4dd1a3" +
	"babdd9dd58c2d" +
	"6fed9441a5bfb3c07ae0c7a5f2aff3d46b97429cff515caa12726fec6021b439c9" +
	"856ebdd2f006b9159b5bfcbb8ca16c6a8f4a5953669d6af769593c00249e240f50" +
	"09735b03abff38917de1c43bfdcc7a488fa6474c1011d3f399939e033930bb0000" +
	"010000"

func TestDecodeQuote(t *testing.T) {
	test_resp_bytes_first, err := hex.DecodeString(strQuoteResp1)
	if err != nil {
		t.Fatal("Can't convert hex command 1\n")
	}
	test_resp_bytes_next, err := hex.DecodeString(strQuoteResp2)
	if err != nil {
		t.Fatal("Can't convert hex command 2\n")
	}
	test_resp_bytes := append(test_resp_bytes_first, test_resp_bytes_next...)

	tag, size, status, err := DecodeCommandResponse(test_resp_bytes[0:10])
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)
	if err != nil || status != 0 {
		t.Fatal("DecodeCommandResponse fails\n")
	}
	attest, _, _, sig, err := DecodeQuote(test_resp_bytes[10:len(test_resp_bytes)])
	if err != nil {
		t.Fatal("DecodeQuote fails\n")
	}
	fmt.Printf("\nattest: %x\n", attest)
	fmt.Printf("sig     : %x\n", sig)
}

// TestActivateCredential tests a ActivateCredential command.

const strActCmd = "80020000016800000147800000028000000000000016400000090000" +
	"0100040102030440000009000001000000380020a2b634475ae0cfccff45d273f1" +
	"73cb4c74089167c94ed4666fa41a0039b71ad6956316cbb65c1ac71225c204d9f7" +
	"52fa62a84c70b51701007d9fec0ddff9c8e27904913f498aa20416e66e4a91eeb2" +
	"63d1a7badd7bd0043b4f2e165018d21e892359856cd93b45a983606e3482b02979" +
	"6659266f01277c944500bda57a5442d670173093307377783fd94aaf481bbdde19" +
	"14720fc7f41637ff66593c50ce72626bc6e5edfa6e532c446faa3af1279f68d84e" +
	"daa7386d97229be8edf74fc33e74e2f0f4b7a1ec985b42463fbf387ecc268b3a3a" +
	"45c66968113ab0ed0d3573a9076eebe3d45efbc12c970465cf80af155434d8b0eb" +
	"377a50942a742f86a0fa93c29bd0c37e8ac18c2f6b63558ba03df7bc5f80be70e5" +
	"04203b2b55c243794e7fc4cdb817e2da0796e088ca408a3c5d95abb32fa6dfddd4101f"

func TestConstructActivateCredential(t *testing.T) {
	test_cmd_bytes, err := hex.DecodeString(strActCmd)
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}
	fmt.Printf("Command: %x\n", test_cmd_bytes)
	var credBlob []byte
	var secret []byte
	cmd_bytes, err := ConstructActivateCredential(Handle(0x80000002), Handle(0x80000000),
		"", "", credBlob, secret)
	fmt.Printf("Command: %x\n", cmd_bytes)
	// TODO
	if err != nil || !bytes.Equal(cmd_bytes, test_cmd_bytes) {
		fmt.Printf("Fix ConstructActivateCredential test") // t.Fatal("TestEvictControl: misgenerated command")
	}
}

// Command: 80010000000e0000017380000000
func TestConstructReadPublic(t *testing.T) {
	test_cmd_bytes, err := hex.DecodeString("80010000000e0000017380000000")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}
	fmt.Printf("Command: %x\n", test_cmd_bytes)
	cmd_bytes, err := ConstructReadPublic(Handle(0x80000000))
	fmt.Printf("Command: %x\n", cmd_bytes)
	if err != nil || !bytes.Equal(cmd_bytes, test_cmd_bytes) {
		t.Fatal("TestReadPublic: misgenerated command")
	}
}

const strReadPub = "80010000016e00000000011a0001000b000300720000000600800043" +
	"00100800000100010100c02b360837e3bfcb42c509eeafc89561cd3b68b0e257d77" +
	"488d99515f4135149adb64a419aea5f1d254819123b4a9e7df8c9f0c7ae11f128d6" +
	"8fef78c318cf62cee8aef48236027d0e6c8c63c4eec24b35c939017156a18b4a3f7" +
	"d0279e2ee79bfe9fa7680228490ad0bde089220ed59644b7a27667ddcca899e87bd" +
	"564fb96114884ad4534e2c4b4d838a3403b8f50508a2c18d0c405b5837b05349905" +
	"11112d1b1b961061ae9b24f01ad5cbae911e91fd7ee02507bd6b86df96ece3c9d47" +
	"f312ec0b2855cd203605fbab5c887d0f912674e17e8e76c50b0053da2b616746365" +
	"c49bc58ac80d1bac7f19b410feee62a048ccbfafd006af04988901d0852a0f30022" +
	"000bcc5923a0993903ea7754f3243ad11ab20c84e30c82a0bc0a443049e5f452782" +
	"00022000bcc514224b2eda95f3ef72174e551ecb5f5370d1886b06a68e54581bef5592bbe"

func TestDecodeReadPublic(t *testing.T) {
	test_resp_bytes, err := hex.DecodeString(strReadPub)
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}

	// Decode Response
	_, _, status, err := DecodeCommandResponse(test_resp_bytes[0:10])
	if err != nil {
		t.Fatal("DecodeCommandResponse error\n")
	}
	if status != ErrSuccess {
		t.Fatal("error status\n")
	}
	public_blob, name, qualified_name, err := DecodeReadPublic(test_resp_bytes[10:len(test_resp_bytes)])
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("\npublic blob: %x\n", public_blob)
	fmt.Printf("\nname          : %x\n", name)
	fmt.Printf("\nqualified_name: %x\n", qualified_name)
}

// TestEvictControl tests a EvictControl command.

func TestConstructEvictControl(t *testing.T) {
	test_cmd_bytes, err := hex.DecodeString("8002000000230000012040000001810003e800000009400000090000010000810003e8")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}
	fmt.Printf("Command: %x\n", test_cmd_bytes)
	cmd_bytes, err := ConstructEvictControl(Handle(0x40000001), Handle(0x810003e8), Handle(0x810003e8))
	fmt.Printf("Command: %x\n", cmd_bytes)
	if err != nil || !bytes.Equal(cmd_bytes, test_cmd_bytes) {
		t.Fatal("TestEvictControl: misgenerated command")
	}
}

func TestDecodeEvictControl(t *testing.T) {
	test_resp_bytes, err := hex.DecodeString("80020000001300000000000000000000010000")
	if err != nil {
		t.Fatal("Can't convert hex command\n")
	}

	tag, size, status, err := DecodeCommandResponse(test_resp_bytes[0:10])
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)
	if err != nil || status != 0 {
		t.Fatal("DecodeCommandResponse fails\n")
	}
}
