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
	"testing"
)

func TestEncodeGetRandom(t *testing.T) {
	testCmdBytes, err := hex.DecodeString("80010000000c0000017b0010")
	if err != nil {
		t.Fatal(err)
	}
	cmdBytes, err := encodeGetRandom(16)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
	}
}

func TestDecodeGetRandom(t *testing.T) {
	testRespBytes, err := hex.DecodeString("80010000001c00000000001024357dadbf82ec9f245d1fcdcda33ed7")
	if err != nil {
		t.Fatal(err)
	}

	_, _, status, err := decodeCommandResponse(testRespBytes[0:10])
	if err != nil {
		t.Fatal(err)
	}
	if status != rcSuccess {
		t.Fatal("error status")
	}
	_, err = decodeGetRandom(testRespBytes[10:len(testRespBytes)])
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncodeReadPCRs(t *testing.T) {
	testCmdBytes, err := hex.DecodeString("8001000000140000017e00000001000403800000")
	if err != nil {
		t.Fatal(err)
	}
	pcrs := []byte{0x03, 0x80, 0x00, 0x00}
	cmdBytes, err := encodeReadPCRs(1, pcrs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
	}
}

func TestDecodeReadPCRs(t *testing.T) {
	testRespBytes, err := hex.DecodeString("800100000032000000000000001400000001000403800000000000010014427d27fe15f8f69736e02b6007b8f6ea674c0745")
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = decodeCommandResponse(testRespBytes[0:10])
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, err = decodeReadPCRs(testRespBytes[10:len(testRespBytes)])
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncodeReadClock(t *testing.T) {
	testCmdBytes, err := hex.DecodeString("80010000000a00000181")
	if err != nil {
		t.Fatal(err)
	}
	cmdBytes, err := encodeReadClock()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
	}
}

func TestDecodeReadClock(t *testing.T) {
	testRespBytes, err := hex.DecodeString("8001000000230000000000000001011380d00000001d1f57f84d000000530000000001")
	if err != nil {
		t.Fatal(err)
	}

	_, _, status, err := decodeCommandResponse(testRespBytes[0:10])
	if err != nil || status != rcSuccess {
		t.Fatal(err)
	}
	_, _, err = decodeReadClock(testRespBytes[10:len(testRespBytes)])
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncodeGetCapabilities(t *testing.T) {
	testCmdBytes, err := hex.DecodeString("8001000000160000017a000000018000000000000014")
	if err != nil {
		t.Fatal(err)
	}
	cmdBytes, err := encodeGetCapabilities(TPM_CAP_HANDLES, 20, 0x80000000)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
	}
}

func TestDecodeGetCapabilities(t *testing.T) {
	testRespBytes, err := hex.DecodeString("80010000001300000000000000000100000000")
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, err = decodeCommandResponse(testRespBytes[0:10])
	if err != nil {
		t.Fatal(err)
	}

	capReported, handles, err := decodeGetCapabilities(testRespBytes[10:len(testRespBytes)])
	if err != nil {
		t.Fatal(err)
	}
	if capReported != TPM_CAP_HANDLES || len(handles) != 0 {
		t.Fatalf("got: (%v, %v), want: (%v, %v)", capReported, handles, TPM_CAP_HANDLES, 0)
	}
}

func TestEncodeFlushContext(t *testing.T) {
	testCmdBytes, err := hex.DecodeString("80010000000e0000016580000001")
	if err != nil {
		t.Fatal(err)
	}
	cmdBytes, err := encodeFlushContext(Handle(0x80000001))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
	}
}

func TestEncodeLoad(t *testing.T) {
	testCmdBytes, err := hex.DecodeString("8002000000b300000157800000000000000d40000009000001000401020" +
		"304005a0014450ecdce5f1ce202e4f8db15e2bde9a1241f85f30010faf6" +
		"2244fedc13fe0abb526e64b10b2de030b6f02be278e23365ef663febe7e" +
		"b4ddae935ca627ce4c40af9f5244dafbc7f47ceb84de87e72a75c7f1032" +
		"d3e7faddde0036000800040000001200140debb4cc9d2158cf7051a19ca" +
		"24b31e35d53b64d001000140b0758c7e4ce32c9d249151e91b72e35a6372fed")
	if err != nil {
		t.Fatal(err)
	}
	privateBlob := testCmdBytes[33:123]
	publicBlob := testCmdBytes[125:]
	cmdBytes, err := encodeLoad(Handle(0x80000000), "", "01020304", publicBlob, privateBlob)
	if err != nil {
		t.Fatalf("encodeLoad failed %s", err)
	}
	if !bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
	}
}

func TestDecodeLoad(t *testing.T) {
	testRespBytes, err := hex.DecodeString("80020000002f000000008000000100000018001600049bc5e230c250b7d984d757f6450f575a5a896ad00000010000")
	if err != nil {
		t.Fatal(err)
	}

	_, _, status, err := decodeCommandResponse(testRespBytes[0:10])
	if err != nil {
		t.Fatal(err)
	}
	if status != rcSuccess {
		t.Fatal("error status")
	}
	_, _, err = decodeLoad(testRespBytes[10:len(testRespBytes)])
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncodeCreatePrimary(t *testing.T) {
	var empty []byte
	testCmdBytes, err := hex.DecodeString("80020000004d00000131400000010000000940000009000001000000080004010203040000001a0001000400030072000000060080004300100400000100010000000000000001000403800000")
	if err != nil {
		t.Fatal(err)
	}
	parms := RSAParams{
		uint16(TPM_ALG_RSA),
		uint16(TPM_ALG_SHA1),
		uint32(0x00030072),
		empty,
		uint16(TPM_ALG_AES),
		uint16(128),
		uint16(TPM_ALG_CFB),
		uint16(TPM_ALG_NULL),
		uint16(0),
		uint16(1024),
		uint32(0x00010001),
		empty,
	}
	cmdBytes, err := encodeCreatePrimary(uint32(TPM_RH_OWNER), []int{7}, "", "01020304", parms)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
	}
}

func TestDecodeCreatePrimary(t *testing.T) {
	testRespBytes, err := hex.DecodeString("80020000013c000000008000000000000125009a00010" +
		"00400030072000000060080004300100400000100010080afe42d93b037f25f5f4" +
		"a92bd65d61b417b51041f057e08670da98bb4720df166d8c0e12cd651196e0e577" +
		"828e65f0e9b0a0da4181bc6553e35970f8b4a6c1790c6132359c62f45952a6e377" +
		"9256de208b996bf2d216fdcfbddd4bdcb0e0cf9fd454caa9604d867e7d7901353d" +
		"1ccd23e16c7a53788f57b602449b0ecaf0590fb003100000001000403800000001" +
		"4bbf70aea75095f280ea3b835afda4a195279ab2c0100100004400000010004400" +
		"00001000000141a1ea8de55d7410287405c3b54057d578d76444a8021400000010" +
		"020e74aa1a8f272b604d6c0cf55b271211a130c011a12b0ba632cc1448c4de8371" +
		"3001600043adbc7b1296c49aac7c154371fd99aeb6e58a9f50000010000")
	if err != nil {
		t.Fatal(err)
	}

	_, _, status, err := decodeCommandResponse(testRespBytes[0:10])
	if err != nil {
		t.Fatal(err)
	}
	if status != rcSuccess {
		t.Fatal("error status")
	}
	_, _, err = decodeCreatePrimary(testRespBytes[10:])
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncodePolicyPCR(t *testing.T) {
	testCmdBytes, err := hex.DecodeString("80010000001a0000017f03000000000000000001000403800000")
	if err != nil {
		t.Fatal(err)
	}
	var empty []byte
	cmdBytes, err := encodePolicyPCR(Handle(0x03000000), empty, []int{7})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
	}
}

func TestEncodePolicyPassword(t *testing.T) {
	testCmdBytes, err := hex.DecodeString("80010000000e0000018c03000000")
	if err != nil {
		t.Fatal(err)
	}
	cmdBytes, err := encodePolicyPassword(Handle(0x03000000))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
	}
}

func TestEncodePolicyGetDigest(t *testing.T) {
	testCmdBytes, err := hex.DecodeString("80010000000e0000018903000000")
	if err != nil {
		t.Fatal(err)
	}
	cmdBytes, err := encodePolicyGetDigest(Handle(0x03000000))
	if !bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
	}
}

func TestDecodePolicyGetDigest(t *testing.T) {
	testRespBytes, err := hex.DecodeString("8001000000200000000000140000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	_, _, status, err := decodeCommandResponse(testRespBytes[0:10])
	if err != nil || status != 0 {
		t.Fatal(err)
	}
	_, err = decodePolicyGetDigest(testRespBytes[10:len(testRespBytes)])
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncodeStartAuthSession(t *testing.T) {
	// TODO(awly): fix this test
	t.Skip()

	testCmdBytes, err := hex.DecodeString("80010000002b00000176400000074000000700100000000000000000000000000000000000000100100004")
	if err != nil {
		t.Fatal(err)
	}
	var nonceCaller []byte
	var secret []byte
	sym := uint16(TPM_ALG_NULL)
	cmdBytes, err := encodeStartAuthSession(Handle(0x40000007), Handle(0x40000007), nonceCaller, secret, 1, sym, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
	}
}

func TestDecodeStartAuthSession(t *testing.T) {
	testRespBytes, err := hex.DecodeString("800100000020000000000300000000106cf0c90c419ce1a96d5205eb870ec527")
	if err != nil {
		t.Fatal(err)
	}

	_, _, status, err := decodeCommandResponse(testRespBytes[0:10])
	if err != nil || status != 0 {
		t.Fatal(err)
	}
	_, _, err = decodeStartAuthSession(testRespBytes[10:])
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncodeCreateSealed(t *testing.T) {
	testCmdBytes, err := hex.DecodeString("80020000006900000153800000000000000d40000009000001000401020304001800040102030400100102030405060708090a0b0c0d0e0f100022000800040000001200140debb4cc9d2158cf7051a19ca24b31e35d53b64d00100000000000000001000403800000")
	if err != nil {
		t.Fatal(err)
	}
	var empty []byte
	toSeal := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	digest := []byte{0x0d, 0xeb, 0xb4, 0xcc, 0x9d, 0x21, 0x58, 0xcf, 0x70, 0x51, 0xa1, 0x9c, 0xa2, 0x4b, 0x31, 0xe3, 0x5d, 0x53, 0xb6, 0x4d}
	parms := KeyedHashParams{uint16(TPM_ALG_KEYEDHASH),
		uint16(TPM_ALG_SHA1), uint32(0x00000012), empty,
		uint16(TPM_ALG_AES), uint16(128), uint16(TPM_ALG_CFB),
		uint16(TPM_ALG_NULL), empty}
	cmdBytes, err := encodeCreateSealed(Handle(0x80000000), digest, "01020304", "01020304", toSeal, []int{7}, parms)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
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
	testRespBytes, err := hex.DecodeString(strCreateSealedResp)
	if err != nil {
		t.Fatal(err)
	}

	_, _, status, err := decodeCommandResponse(testRespBytes[0:10])
	if err != nil {
		t.Fatal(err)
	}
	if status != rcSuccess {
		t.Fatal("error status")
	}
	_, _, err = decodeCreateSealed(testRespBytes[10:len(testRespBytes)])
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncodeCreateKey(t *testing.T) {
	testCmdBytes, err := hex.DecodeString("80020000004f00000153800000000000000d40000009000001000401020304000800040102030400000018000100040004007200000010001400040400000100010000000000000001000403800000")
	if err != nil {
		t.Fatal(err)
	}
	var empty []byte
	parms := RSAParams{
		uint16(TPM_ALG_RSA),
		uint16(TPM_ALG_SHA1),
		uint32(0x00030072),
		empty,
		uint16(TPM_ALG_AES),
		uint16(128),
		uint16(TPM_ALG_CFB),
		uint16(TPM_ALG_NULL),
		uint16(0),
		uint16(1024),
		uint32(0x00010001),
		empty,
	}
	cmdBytes, err := encodeCreateKey(uint32(TPM_RH_OWNER), []int{7}, "", "01020304", parms)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
	}
}

func TestDecodeCreateKey(t *testing.T) {
	testRespBytes, err := hex.DecodeString("8002000001ba00000000000001a70076001405f2c6b6035d4" +
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
		"0706db0160457fa3dfe7e7aca34a334370000010000")
	if err != nil {
		t.Fatal(err)
	}

	_, _, status, err := decodeCommandResponse(testRespBytes[0:10])
	if err != nil {
		t.Fatal(err)
	}
	if status != rcSuccess {
		t.Fatal("error status")
	}
	_, _, err = decodeCreateKey(testRespBytes[10:])
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncodeUnseal(t *testing.T) {
	testCmdBytes, err := hex.DecodeString("80020000001f0000015e800000010000000d03000000000001000401020304")
	if err != nil {
		t.Fatal(err)
	}
	cmdBytes, err := encodeUnseal(Handle(0x80000001), "01020304", Handle(0x03000000))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
	}
}

func TestDecodeUnseal(t *testing.T) {
	testRespBytes, err := hex.DecodeString("800200000035000000000000001200100102030405060708090a0b0c0d0e0f100010ea78d080f9f77d9d85e1f80350247ecb010000")
	if err != nil {
		t.Fatal(err)
	}

	_, _, status, err := decodeCommandResponse(testRespBytes[0:10])
	if err != nil || status != 0 {
		t.Fatal(err)
	}
	_, _, err = decodeUnseal(testRespBytes[10:len(testRespBytes)])
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncodeQuote(t *testing.T) {
	testCmdBytes, err := hex.DecodeString("80020000003d00000158800000010000000d4000000900000100040102030400100102030405060708090a0b0c0d0e0f10001000000001000403800000")
	if err != nil {
		t.Fatal(err)
	}
	toQuote := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10}
	cmdBytes, err := encodeQuote(Handle(0x80000001), "01020304", "", toQuote, []int{7}, 0x0010)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
	}
}

func TestDecodeQuote(t *testing.T) {
	testRespBytes, err := hex.DecodeString("80020000010400000000000000f10069ff544347801800160004" +
		"7705bde86e3780577632421d34e5db4759667c8900100102030405060708090a0b" +
		"0c0d0e0f1000000000000fe8f99cf4968c1d6e516100eb40a3278641a1c6000000" +
		"010004038000000014ae2edb7e23d7e8f58daa87af87775993a426722500140004" +
		"00804e49bb73712bc6acca4778005741b586ee6da2c98fe4dd1a3babdd9dd58c2d" +
		"6fed9441a5bfb3c07ae0c7a5f2aff3d46b97429cff515caa12726fec6021b439c9" +
		"856ebdd2f006b9159b5bfcbb8ca16c6a8f4a5953669d6af769593c00249e240f50" +
		"09735b03abff38917de1c43bfdcc7a488fa6474c1011d3f399939e033930bb0000" +
		"010000")
	if err != nil {
		t.Fatal(err)
	}

	_, _, status, err := decodeCommandResponse(testRespBytes[0:10])
	if err != nil || status != 0 {
		t.Fatal(err)
	}
	_, _, _, _, err = decodeQuote(testRespBytes[10:len(testRespBytes)])
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncodeActivateCredential(t *testing.T) {
	// TODO(awly): fix this test
	t.Skip()

	testCmdBytes, err := hex.DecodeString("80020000016800000147800000028000000000000016400000090000" +
		"0100040102030440000009000001000000380020a2b634475ae0cfccff45d273f1" +
		"73cb4c74089167c94ed4666fa41a0039b71ad6956316cbb65c1ac71225c204d9f7" +
		"52fa62a84c70b51701007d9fec0ddff9c8e27904913f498aa20416e66e4a91eeb2" +
		"63d1a7badd7bd0043b4f2e165018d21e892359856cd93b45a983606e3482b02979" +
		"6659266f01277c944500bda57a5442d670173093307377783fd94aaf481bbdde19" +
		"14720fc7f41637ff66593c50ce72626bc6e5edfa6e532c446faa3af1279f68d84e" +
		"daa7386d97229be8edf74fc33e74e2f0f4b7a1ec985b42463fbf387ecc268b3a3a" +
		"45c66968113ab0ed0d3573a9076eebe3d45efbc12c970465cf80af155434d8b0eb" +
		"377a50942a742f86a0fa93c29bd0c37e8ac18c2f6b63558ba03df7bc5f80be70e5" +
		"04203b2b55c243794e7fc4cdb817e2da0796e088ca408a3c5d95abb32fa6dfddd4101f")
	if err != nil {
		t.Fatal(err)
	}
	var credBlob []byte
	var secret []byte
	cmdBytes, err := encodeActivateCredential(Handle(0x80000002), Handle(0x80000000), "", "", credBlob, secret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
	}
}

func TestEncodeReadPublic(t *testing.T) {
	testCmdBytes, err := hex.DecodeString("80010000000e0000017380000000")
	if err != nil {
		t.Fatal(err)
	}
	cmdBytes, err := encodeReadPublic(Handle(0x80000000))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
	}
}

func TestDecodeReadPublic(t *testing.T) {
	testRespBytes, err := hex.DecodeString("80010000016e00000000011a0001000b000300720000000600800043" +
		"00100800000100010100c02b360837e3bfcb42c509eeafc89561cd3b68b0e257d77" +
		"488d99515f4135149adb64a419aea5f1d254819123b4a9e7df8c9f0c7ae11f128d6" +
		"8fef78c318cf62cee8aef48236027d0e6c8c63c4eec24b35c939017156a18b4a3f7" +
		"d0279e2ee79bfe9fa7680228490ad0bde089220ed59644b7a27667ddcca899e87bd" +
		"564fb96114884ad4534e2c4b4d838a3403b8f50508a2c18d0c405b5837b05349905" +
		"11112d1b1b961061ae9b24f01ad5cbae911e91fd7ee02507bd6b86df96ece3c9d47" +
		"f312ec0b2855cd203605fbab5c887d0f912674e17e8e76c50b0053da2b616746365" +
		"c49bc58ac80d1bac7f19b410feee62a048ccbfafd006af04988901d0852a0f30022" +
		"000bcc5923a0993903ea7754f3243ad11ab20c84e30c82a0bc0a443049e5f452782" +
		"00022000bcc514224b2eda95f3ef72174e551ecb5f5370d1886b06a68e54581bef5592bbe")
	if err != nil {
		t.Fatal(err)
	}

	_, _, status, err := decodeCommandResponse(testRespBytes[0:10])
	if err != nil {
		t.Fatal(err)
	}
	if status != rcSuccess {
		t.Fatal("error status")
	}
	_, _, _, err = decodeReadPublic(testRespBytes[10:len(testRespBytes)])
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncodeEvictControl(t *testing.T) {
	testCmdBytes, err := hex.DecodeString("8002000000230000012040000001810003e800000009400000090000010000810003e8")
	if err != nil {
		t.Fatal(err)
	}
	cmdBytes, err := encodeEvictControl(Handle(0x40000001), Handle(0x810003e8), Handle(0x810003e8))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cmdBytes, testCmdBytes) {
		t.Fatalf("got: %v, want: %v", cmdBytes, testCmdBytes)
	}
}

func TestEncodeShortPCRs(t *testing.T) {
	pcrNums := []int{7, 8}
	pcr, err := encodeShortPCRs(pcrNums)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x03, 0x80, 0x01, 0x00}
	if !bytes.Equal(want, pcr) {
		t.Fatalf("got: %v, want: %v", pcr, want)
	}
}

func TestEncodeHandle(t *testing.T) {
	hand, err := encodeHandle(Handle(TPM_RH_OWNER))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x40, 0, 0, 1}
	if !bytes.Equal(want, hand) {
		t.Fatalf("got: %v, want: %v", hand, want)
	}
}

func TestEncodePasswordData(t *testing.T) {
	pw, err := encodePasswordData("01020304")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 4, 1, 2, 3, 4}
	if !bytes.Equal(want, pw) {
		t.Fatalf("got: %v, want: %v", pw, want)
	}
	pw, err = encodePasswordData("0102030405")
	if err != nil {
		t.Fatal(err)
	}
	want = []byte{0, 5, 1, 2, 3, 4, 5}
	if !bytes.Equal(want, pw) {
		t.Fatalf("got: %v, want: %v", pw, want)
	}
}

func TestEncodePasswordAuthArea(t *testing.T) {
	pwAuth, err := encodePasswordAuthArea("01020304", Handle(TPM_RS_PW))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0xd, 0x40, 0, 0, 9, 0, 0, 1, 0, 4, 1, 2, 3, 4}
	if !bytes.Equal(want, pwAuth) {
		t.Fatalf("got: %v, want: %v", pwAuth, want)
	}

	pwAuth, err = encodePasswordAuthArea("", Handle(TPM_RS_PW))
	if err != nil {
		t.Fatal(err)
	}
	want = []byte{0, 0x9, 0x40, 0, 0, 9, 0, 0, 1, 0, 0}
	if !bytes.Equal(want, pwAuth) {
		t.Fatalf("got: %v, want: %v", pwAuth, want)
	}
}

func TestEncodeSensitiveArea(t *testing.T) {
	a1 := []byte{1, 2, 3, 4}
	var a2 []byte
	s, err := encodeSensitiveArea(a1, a2)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 8, 0, 4, 1, 2, 3, 4, 0, 0}
	if !bytes.Equal(want, s) {
		t.Fatalf("got: %v, want: %v", s, want)
	}
}

func TestEncodeRSAParams(t *testing.T) {
	var empty []byte
	parms := RSAParams{
		uint16(TPM_ALG_RSA),
		uint16(TPM_ALG_SHA1),
		uint32(0x00030072),
		empty,
		uint16(TPM_ALG_AES),
		uint16(128),
		uint16(TPM_ALG_CFB),
		uint16(TPM_ALG_NULL),
		uint16(0),
		uint16(1024),
		uint32(0x00010001),
		empty,
	}

	_, err := encodeRSAParams(parms)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncodeLongPCR(t *testing.T) {
	s, err := encodeLongPCR(uint32(1), []int{7})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 0, 1, 0, 4, 3, 0x80, 0, 0}
	if !bytes.Equal(want, s) {
		t.Fatalf("got: %v, want: %v", s, want)
	}
}
