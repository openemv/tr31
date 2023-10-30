/**
 * @file tr31_decrypt_test.c
 *
 * Copyright (c) 2020, 2021, 2022, 2023 Leon Lynch
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program. If not, see
 * <https://www.gnu.org/licenses/>.
 */

#include "tr31.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

// example data generated using a Thales payShield 10k HSM
static const uint8_t test1_kbpk[] = { 0xEF, 0xE0, 0x85, 0x3B, 0x25, 0x6B, 0x58, 0x3D, 0x86, 0x8F, 0x25, 0x1C, 0xE9, 0x9E, 0xA1, 0xD9 };
static const char test1_tr31_format_a[] = "A0072K0TN00N0000F40D5672C6D0EC86F860BA88D44D00F0CA9A8CE8CD2F640287A9A9EB";
static const char test1_tr31_format_b[] = "B0080K0TN00N00001C414014375212C24995E405B5EE052CB92B67F455EA2680F6751088F9F1C228";
static const char test1_tr31_format_c[] = "C0072K0TN00N0000C9B875FF7A5316BF221C09ED52080DE0B45632A4EA9CE87699CB565E";
static const uint8_t test1_tr31_key_verify[] = { 0x5D, 0xB5, 0x0B, 0x45, 0x4F, 0x83, 0x89, 0xAD, 0xCE, 0x57, 0x3B, 0xE5, 0x08, 0x61, 0xF2, 0xBF };
static const uint8_t test1_tr31_kcv_verify[] = { 0x5C, 0x94, 0x05 };

// TR-31:2018, A.7.2.1
static const uint8_t test2_kbpk[] = { 0x89, 0xE8, 0x8C, 0xF7, 0x93, 0x14, 0x44, 0xF3, 0x34, 0xBD, 0x75, 0x47, 0xFC, 0x3F, 0x38, 0x0C };
static const char test2_tr31_ascii[] = "A0072P0TE00E0000F5161ED902807AF26F1D62263644BD24192FDB3193C730301CEE8701";
static const uint8_t test2_tr31_key_verify[] = { 0xF0, 0x39, 0x12, 0x1B, 0xEC, 0x83, 0xD2, 0x6B, 0x16, 0x9B, 0xDC, 0xD5, 0xB2, 0x2A, 0xAF, 0x8F };
static const uint8_t test2_tr31_kcv_verify[] = { 0xCB, 0x9D, 0xEA };

// TR-31:2018, A.7.2.2
static const uint8_t test3_kbpk[] = { 0xDD, 0x75, 0x15, 0xF2, 0xBF, 0xC1, 0x7F, 0x85, 0xCE, 0x48, 0xF3, 0xCA, 0x25, 0xCB, 0x21, 0xF6 };
static const char test3_tr31_ascii[] = "B0080P0TE00E000094B420079CC80BA3461F86FE26EFC4A3B8E4FA4C5F5341176EED7B727B8A248E";
static const uint8_t test3_tr31_key_verify[] = { 0x3F, 0x41, 0x9E, 0x1C, 0xB7, 0x07, 0x94, 0x42, 0xAA, 0x37, 0x47, 0x4C, 0x2E, 0xFB, 0xF8, 0xB8 };
static const uint8_t test3_tr31_kcv_verify[] = { 0x57, 0xC4, 0x09 };

// TR-31:2018, A.7.3.1
static const uint8_t test4_kbpk[] = { 0xB8, 0xED, 0x59, 0xE0, 0xA2, 0x79, 0xA2, 0x95, 0xE9, 0xF5, 0xED, 0x79, 0x44, 0xFD, 0x06, 0xB9 };
static const char test4_tr31_ascii[] = "C0096B0TX12S0100KS1800604B120F9292800000BFB9B689CB567E66FC3FEE5AD5F52161FC6545B9D60989015D02155C";
static const uint8_t test4_tr31_ksn_verify[] = { 0x00, 0x60, 0x4B, 0x12, 0x0F, 0x92, 0x92, 0x80, 0x00, 0x00 };
static const uint8_t test4_tr31_key_verify[] = { 0xED, 0xB3, 0x80, 0xDD, 0x34, 0x0B, 0xC2, 0x62, 0x02, 0x47, 0xD4, 0x45, 0xF5, 0xB8, 0xD6, 0x78 };
static const uint8_t test4_tr31_kcv_verify[] = { 0xF4, 0xB0, 0x8D };

// TR-31:2018, A.7.3.2
static const uint8_t test5_kbpk[] = { 0x1D, 0x22, 0xBF, 0x32, 0x38, 0x7C, 0x60, 0x0A, 0xD9, 0x7F, 0x9B, 0x97, 0xA5, 0x13, 0x11, 0xAC };
static const char test5_tr31_ascii[] = "B0104B0TX12S0100KS1800604B120F9292800000BB68BE8680A400D9191AD4ECE45B6E6C0D21C4738A52190E248719E24B433627";
static const uint8_t test5_tr31_ksn_verify[] = { 0x00, 0x60, 0x4B, 0x12, 0x0F, 0x92, 0x92, 0x80, 0x00, 0x00 };
static const uint8_t test5_tr31_key_verify[] = { 0xE8, 0xBC, 0x63, 0xE5, 0x47, 0x94, 0x55, 0xE2, 0x65, 0x77, 0xF7, 0x15, 0xD5, 0x87, 0xFE, 0x68 };
static const uint8_t test5_tr31_kcv_verify[] = { 0x9A, 0x42, 0x12 };

// TR-31:2018, A.7.4
static const uint8_t test6_kbpk[] = {
	0x88, 0xE1, 0xAB, 0x2A, 0x2E, 0x3D, 0xD3, 0x8C, 0x1F, 0xA0, 0x39, 0xA5, 0x36, 0x50, 0x0C, 0xC8,
	0xA8, 0x7A, 0xB9, 0xD6, 0x2D, 0xC9, 0x2C, 0x01, 0x05, 0x8F, 0xA7, 0x9F, 0x44, 0x65, 0x7D, 0xE6,
};
static const char test6_tr31_ascii[] = "D0112P0AE00E0000B82679114F470F540165EDFBF7E250FCEA43F810D215F8D207E2E417C07156A27E8E31DA05F7425509593D03A457DC34";
static const uint8_t test6_tr31_key_verify[] = { 0x3F, 0x41, 0x9E, 0x1C, 0xB7, 0x07, 0x94, 0x42, 0xAA, 0x37, 0x47, 0x4C, 0x2E, 0xFB, 0xF8, 0xB8 };
static const uint8_t test6_tr31_kcv_verify[] = { 0x08, 0x79, 0x3E };

// example data generated using a Thales payShield 10k HSM
static const uint8_t test7_kbpk[] = {
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
};
static const char test7_tr31_ascii[] = "D0112B0TN00N000037DB9B046B7B0048785690759580ABC3B9842AB4BB7717B49E92528E575785D8123559376A2553B27BE94F054F4E971C";
static const uint8_t test7_tr31_key_verify[] = { 0x1F, 0xA1, 0xF7, 0xCE, 0xC7, 0x98, 0xD9, 0x15, 0x45, 0xDA, 0x8A, 0xE0, 0xC7, 0x79, 0x6B, 0xD9 };
static const uint8_t test7_tr31_kcv_verify[] = { 0xFF, 0x50, 0x87 };

// example data generated using a Thales payShield 10k HSM
static const uint8_t test8_kbpk[] = {
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
};
static const char test8_tr31_ascii[] = "D0144D0AN00N0000127862F945C2DED04530FAF7CDBC8B0BA10C7AA79BD5E0C2C5D6AC173BF588E4B19ACF1357178D50EA0AB193228E13958304FC6149632DFDCADF3A5B3D57E814";
static const uint8_t test8_tr31_key_verify[] = {
	0xBE, 0x19, 0xE6, 0xA0, 0x7A, 0x76, 0x0F, 0x10, 0xEF, 0x8E, 0x83, 0xA2, 0x26, 0xB6, 0x3A, 0xAD,
	0x14, 0x1F, 0x46, 0x3F, 0xDD, 0xD4, 0xF4, 0x7D, 0xB2, 0x44, 0xB4, 0x02, 0x3E, 0xC3, 0xCA, 0xCC,
};
static const uint8_t test8_tr31_kcv_verify[] = { 0x0A, 0x00, 0xE3 };

// ISO 20038:2017, B.2
static const uint8_t test9_kbpk[] = {
	0x32, 0x35, 0x36, 0x2D, 0x62, 0x69, 0x74, 0x20, 0x41, 0x45, 0x53, 0x20, 0x77, 0x72, 0x61, 0x70,
	0x70, 0x69, 0x6E, 0x67, 0x20, 0x28, 0x49, 0x53, 0x4F, 0x20, 0x32, 0x30, 0x30, 0x33, 0x38, 0x29,
};
static const char test9_tr31_ascii[] = "E0084B0TV16N0000B2AE5E26BBA7F246E84D5EA24167E208A6B66EF2E27E55A52DB52F0AEACB94C57547";
static const uint8_t test9_tr31_key_verify[] = {
	0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x20, 0x33, 0x44, 0x45, 0x53, 0x20, 0x6B, 0x65, 0x79,
};
static const uint8_t test9_tr31_kcv_verify[] = { 0xB2, 0x9D, 0x42 };

// ISO 20038:2017, B.3
static const uint8_t test10_kbpk[] = {
	0x32, 0x35, 0x36, 0x2D, 0x62, 0x69, 0x74, 0x20, 0x41, 0x45, 0x53, 0x20, 0x77, 0x72, 0x61, 0x70,
	0x70, 0x69, 0x6E, 0x67, 0x20, 0x28, 0x49, 0x53, 0x4F, 0x20, 0x32, 0x30, 0x30, 0x33, 0x38, 0x29,
};
static const char test10_tr31_ascii[] = "D0112M3TV16N000018462FA5903B8D2B82FEE26B29713C0BE7ED81601087F12252093D06FC0A012C1CF769AD0E3E9E4877166AB013FC22B4";
static const uint8_t test10_tr31_key_verify[] = {
	// ISO 20038:2017, B.3 provides this is the wrapped key, but it doesn't match the input data...
	//0x76, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x20, 0x33, 0x44, 0x45, 0x53, 0x20, 0x6B, 0x65, 0x79,

	// ISO 20038:2017, B.3 MAC input data shows that this is the wrapped key...
	0x76, 0x73, 0x61, 0x70, 0x70, 0x64, 0x64, 0x20, 0x32, 0x45, 0x45, 0x52, 0x20, 0x6B, 0x64, 0x79,
};
static const uint8_t test10_tr31_kcv_verify[] = { 0xB2, 0x9D, 0x42 };

// ANSI X9.143:2021, 8.1
static const uint8_t test11_kbpk[] = {
	0x88, 0xE1, 0xAB, 0x2A, 0x2E, 0x3D, 0xD3, 0x8C, 0x1F, 0xA0, 0x39, 0xA5, 0x36, 0x50, 0x0C, 0xC8,
	0xA8, 0x7A, 0xB9, 0xD6, 0x2D, 0xC9, 0x2C, 0x01, 0x05, 0x8F, 0xA7, 0x9F, 0x44, 0x65, 0x7D, 0xE6,
};
static const char test11_tr31_ascii[] = "D0144P0AE00E00002C77FA3F4A553BED6E88AE5C172A4166E3D4ACA8E2AC71C158A476FAC12C13C3829DE55D3AB54C48F4C4FEF7AC75E90FC47F1B77E7B19A73ED46E64410082557";
static const uint8_t test11_tr31_key_verify[] = { 0x3F, 0x41, 0x9E, 0x1C, 0xB7, 0x07, 0x94, 0x42, 0xAA, 0x37, 0x47, 0x4C, 0x2E, 0xFB, 0xF8, 0xB8 };
static const uint8_t test11_tr31_kcv_verify[] = { 0x08, 0x79, 0x3E, 0x25, 0xAB };

// ANSI X9.143:2021, 8.2
// Unfortunately the key block provided by ANSI X9.143:2021 for this test is
// invalid because optional block KS contains invalid characters
/*
static const uint8_t test12_kbpk[] = {
	0xE3, 0x83, 0x31, 0xFB, 0xAC, 0xE3, 0x3F, 0x0B, 0x86, 0x94, 0xAB, 0xA5, 0xDC, 0x61, 0x1C, 0xA2,
	0x08, 0x31, 0x94, 0x9F, 0xEB, 0x89, 0x88, 0x10, 0x21, 0x47, 0x29, 0x15, 0x78, 0xF7, 0x04, 0xE1,
};
static const char test12_tr31_ascii[] = "D0192C0AVA1N0300KS08VM9ATS1A2018-06-18T20:42:39.22PB0E00000000005FDAFA00A1E84F599C2EB51A1F7A767D5E42314F0E84A3FC1A7B84C1DE81114659E6306AD544208F68F15602BD3E12DA0C7F9FC551F1C8E6385FAFC1F7B499F5";
static const char test12_tr31_ksn_verify[] = "VM9A";
static const char test12_tr31_ts_verify[] = "2018-06-18T20:42:39.22";
static const uint8_t test12_tr31_key_verify[] = {
	0x8C, 0x32, 0x60, 0x37, 0xF8, 0x91, 0x0B, 0xBF, 0xDB, 0xC2, 0x67, 0xE5, 0x10, 0x1D, 0xFB, 0xF9,
	0x48, 0x04, 0x33, 0x02, 0x8D, 0x5E, 0x67, 0xB3, 0x46, 0x73, 0x44, 0x0F, 0x8A, 0xCE, 0xC9, 0x72,
};
static const uint8_t test12_tr31_kcv_verify[] = { 0x00, 0x00, 0x00, 0x00, 0x00 };
*/

// ANSI X9.143:2021, 8.3.2.1
// Unfortunately the key block provided by ANSI X9.143:2021 for this test is
// invalid because the header length is incorrect
/*
static const uint8_t test13_kbpk[] = { 0x89, 0xE8, 0x8C, 0xF7, 0x93, 0x14, 0x44, 0xF3, 0x34, 0xBD, 0x75, 0x47, 0xFC, 0x3F, 0x38, 0x0C };
static const char test13_tr31_ascii[] = "A0072P0TE00E0000A8974C06DBFD58D197101A28DEC1A6C7C23F00A3B18EC6D538DE4A5B5F49A542D61A8A8B";
static const uint8_t test13_tr31_key_verify[] = { 0xF0, 0x39, 0x12, 0x1B, 0xEC, 0x83, 0xD2, 0x6B, 0x16, 0x9B, 0xDC, 0xD5, 0xB2, 0x2A, 0xAF, 0x8F };
static const uint8_t test13_tr31_kcv_verify[] = { 0xCB, 0x9D, 0xEA };
*/

// ANSI X9.143:2021, 8.3.2.2
// Unfortunately the key block provided by ANSI X9.143:2021 for this test is
// invalid because the header length is incorrect
/*
static const uint8_t test14_kbpk[] = { 0xDD, 0x75, 0x15, 0xF2, 0xBF, 0xC1, 0x7F, 0x85, 0xCE, 0x48, 0xF3, 0xCA, 0x25, 0xCB, 0x21, 0xF6 };
static const char test14_tr31_ascii[] = "B0080P0TE00E000094B420079CC80BA3461F86FE26EFC4A38C6B0A146BF1B0BE0D3277F17A3AD5146EED7B727B8A248E";
static const uint8_t test14_tr31_key_verify[] = { 0x3F, 0x41, 0x9E, 0x1C, 0xB7, 0x07, 0x94, 0x42, 0xAA, 0x37, 0x47, 0x4C, 0x2E, 0xFB, 0xF8, 0xB8 };
static const uint8_t test14_tr31_kcv_verify[] = { 0x57, 0xC4, 0x09 };
*/

// ANSI X9.143:2021, 8.4.1
static const uint8_t test15_kbpk[] = { 0xB8, 0xED, 0x59, 0xE0, 0xA2, 0x79, 0xA2, 0x95, 0xE9, 0xF5, 0xED, 0x79, 0x44, 0xFD, 0x06, 0xB9 };
static const char test15_tr31_ascii[] = "C0112B0TX12S0100KS1800604B120F929280000042B758A2400AB598AE37782823DAF0BA4BDB0DAFF34915345CA169AE1F976A429EB139E5";
static const uint8_t test15_tr31_ksn_verify[] = { 0x00, 0x60, 0x4B, 0x12, 0x0F, 0x92, 0x92, 0x80, 0x00, 0x00 };
static const uint8_t test15_tr31_key_verify[] = { 0xED, 0xB3, 0x80, 0xDD, 0x34, 0x0B, 0xC2, 0x62, 0x02, 0x47, 0xD4, 0x45, 0xF5, 0xB8, 0xD6, 0x78 };
static const uint8_t test15_tr31_kcv_verify[] = { 0xF4, 0xB0, 0x8D };

// ANSI X9.143:2021, 8.4.2
static const uint8_t test16_kbpk[] = { 0x1D, 0x22, 0xBF, 0x32, 0x38, 0x7C, 0x60, 0x0A, 0xD9, 0x7F, 0x9B, 0x97, 0xA5, 0x13, 0x11, 0xAC };
static const char test16_tr31_ascii[] = "B0120B0TX12S0100KS1800604B120F929280000015CEB14B76D551F21EC43A75390FA118A98C6CB049E3B9E864A5F4A8B9A5108A6DB5635C95B042D7";
static const uint8_t test16_tr31_ksn_verify[] = { 0x00, 0x60, 0x4B, 0x12, 0x0F, 0x92, 0x92, 0x80, 0x00, 0x00 };
static const uint8_t test16_tr31_key_verify[] = { 0xE8, 0xBC, 0x63, 0xE5, 0x47, 0x94, 0x55, 0xE2, 0x65, 0x77, 0xF7, 0x15, 0xD5, 0x87, 0xFE, 0x68 };
static const uint8_t test16_tr31_kcv_verify[] = { 0x9A, 0x42, 0x12 };

// ANSI X9.143:2021, 8.5
static const uint8_t test17_kbpk[] = { 0xFA, 0x36, 0xE4, 0x42, 0x78, 0xDB, 0x3A, 0xB5, 0xF2, 0x98, 0xF9, 0xF7, 0xDA, 0x8F, 0x1F, 0x88 };
static const char test17_tr31_ascii[] =
	// Header
	"D3776S0RS00N0400CT0004050000MIIDszCCApugAwIBAgIIKpD5FKMfCZEwDQYJKoZIhvcNAQELBQAwLTEXMBUGA1UECgwOQWxwaGEgTWVyY2hhbnQxEjAQBgNVBAMMCVNhbXBsZSBDQTAeFw0yMDA4MTUwMjE0MTBaFw0yMTA4MTUwMjE0MTBaME8xFzAVBgNVBAoMDkFscGhhIE1lcmNoYW50MR8wHQYDVQQLDBZUTFMgQ2xpZW50IENlcnRpZmljYXRlMRMwEQYDVQQDDAoxMjM0NTY3ODkwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1sRg+wEuje3y14V0tFHpvxxpY/fyrldB0nRctBDn4AvkBfyJuDLG59vqkGXVd8J8YQdwEHZJrVq+7B8rjtM6PMoyH/7QAZZAC7tw740P4cfen1IryubZVviV9QUp+gHToelZfr1rfIsuEGhzo6UhwY70kkS87/rYHCVathZEjMmvUIEdpzg0PZ2+Heg6D35OQ70I+np+BsEQf71Zr+d2iKqVGEd50l8tbn4W3A4rOyUERPTaACwS9rvdF7nlmTqSI5ybN6lmm37a71h77n6M54aaw2KkJYWVo+1stUTyFVsv/YBs9aylbBHQOYqp/U2tB0TxM58QYGzyaWvNqbFzOQIDAQABo4G0MIGxMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB0GA1UdDgQWBBR837QRAGx5uL9xDnRjr9L9WSBSlzAfBgNVHSMEGDAWgBSlXhVYy9bic9OLnRsxsFgKQQbLmTA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3JsLmFscGhhLW1lcmNoYW50LmV4YW1wbGUvU2FtcGxlQ0EuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQCH6JusIBSkRDqzAohaSoJVAEwQGMdcUSQWDfMyJjZqkOep1kT8Sl7LolFmmmVRJdkTWZe4PxBfQUc/eIql9BIx90506B+j9aoVA7212OExAid78GgqKA6JoalhYQKRta9ixY8iolydTYyEYpegA1jFZavMQma4ZGwX/bDJWr4+cJYxJXWaf67g4AMqHaWC8J60MVjrrBe9BZ0ZstuIlNkktQUOZanqxqsrFeqz02ibwTwNHtaHQCztB4KgdTkrTNahkqeq6xjafDoTllNo1EddajnbA/cVzF9ZCNigDtg5chXHWIQbgEK7HmU3sY3/wd2Bh1KdF3+vpN+5iZMRNv7ZKP1001D77F007724TS1320200818221218ZPB0D000000000"

	// Encrypted data
	"A7C9F8FA80A4BA3555CA071503CE1A6133649BB18A5A9130492172CA4E7360C060379738A28503230BDB04EED4E9B209643867613F5090A0E0392C21EB74747795B397315AB5D1F49A33693533E73AC0BEDA172FF530BE986F5EC1C25F481F05A69DF8B33624E621AF35FFAEC06C2005F37872923EEBFF38182FB290BFBA2A9FF88AD36278625868FA38A0DC9A53E0202C4D1DEF3B9DACFD249DA85DE3CCF92A8E6C0F8CDF8DE5FD17331BE5D580F210CE4EA1B01F1A0BFD6EFF410A71661234AD363D4B60885F00358729900FF95D7C87D3DE6FB4C83B24C8C7BB5A2E3763E9CBA50A0E3A8C1AF908699952BCB6B038FEA9D13FDE08801DC0573E55B842219DBF6D5DA5F028C73793AA718D01DE93D85AE06E7E08DC94ADB4EAA51B6DDAEA3750D0B77467D2982AC96F3EB28889715CBB81C71E97A60E58D44977C1D8220A422E98E17ACEBF72A8A18D4E7FC1695F442860E6063E8BB6BFF2184F77E635C2F5A02DADE4897A3B1374145C3AD6DF06C0D556F5DE9454CF40C4FC8922DFE245F868E668F1DA5BE0079F9D1D1861CA4B5E6C782F296098C07CB43784D64D8B8557410E5BAFF59333A791FF030EB0661C0590A665B50A3A727217100C4550B2AD9C96C658D6731C09B55DFAE665952E2913A4E090F45DCEB45D6683C3FC15E3A4CA49C7F2E684B3580DB47A53E5BDB228FAD250C584548D5DEDBB45004B5E0E75C37ACE8167CC6D9574A74876718D2F42996622B8EC0B895FF7A6739E4CF64B7F03FABDFBC0A565CB3455736D2B4E2B64D6EC175A569F78DB7ACB331B00804279677F4BFD0C35CBF0A38D646AA9051961123E16075A06B6331A9A30601AF3FD6A89AD9924AE1D9EC2FE0FF3B3A1B3E3E13D09B08B80D91F9EDF51B2E6D8DABD0FEB6C5C1085A11FA6A98CE8CC09E36C8A24D981A74E140EF30912E8CDBBE2A0CBD52B40C72D1958F4BB2F49BCBABBD80116FEF21BC91D219EEAEDA4DC11692C624B0836C3137A3BEE4549DEAB750A9DD5ACA7E3F822084783CDFEEB765EBEB9E3CFF053E8B8D5A1F1854B8AFF6325F10B81C7627D0DA895B1D19FEEF0AE3F3E138E87C4ADDF0BA53CA40ED0D1452044600FF4838D710F6D03474C317AC306DD7DA169B6C918E999E3A50DA1A34DDFCA3899F4469B9E969C0BD144F04B2621AB9E9E18455D526844155309565DA9D1726CD3A7ACC5FEDEF30DED078547CED31CEF84A31A810FA966F303CB950ACC324AE54BFAB9A04FAD93C38CD6239D7FAD2C59A9B71171F5676DA8ED3A3FFB5287DF141C1F5CE972CA26857AD3039B82B625960A7859F19EF0E94F8C4680A33189870942139DDFA64D5095FA46EB49085DB99EFC9C6A3F3A290DB9592F8B76B017113F7D1FEFE52E70FE26574467257CFEEA6D3F2BBD1BAEDDDCE3468827568A78536DE78E7AC872247BDB120A55DDE16A3D0CFBB7D097AD7AD0FA2671390D8D532A3915F5B3163FF1EE23553D83A1109980859C420F754BC74ECD1449B9A60EA252D3F035D715BCBD491485261C51238926E290BD7F0617E90BD6AB8B46443B05C28D61F8BB897417926623AF91B499C661629795165EF56460850F1D4F9CE199C2B9E21F1884A4D14644DAE5FB963B880EC2FFF70021772D524289D068A24F0283C42F0B4779996D2CF60EE6E45C364E2547DB92361B3DBCEDBAA96B9F10A1AAA1AB23"

	// MAC
	"CDE1B75F3299D4544787A07F6A9F7127";
static const uint8_t test17_kcv_kbpk_verify[] = { 0xD7, 0x7F, 0x00, 0x77, 0x24 };
static const char test17_tr31_ts_verify[] = "20200818221218Z";

// ANSI X9.143:2021, 8.6
static const uint8_t test18_kbpk[] = {
	0x88, 0xE1, 0xAB, 0x2A, 0x2E, 0x3D, 0xD3, 0x8C, 0x1F, 0xA0, 0x39, 0xA5, 0x36, 0x50, 0x0C, 0xC8,
	0xA8, 0x7A, 0xB9, 0xD6, 0x2D, 0xC9, 0x2C, 0x01, 0x05, 0x8F, 0xA7, 0x9F, 0x44, 0x65, 0x7D, 0xE6,
};
static const char test18_tr31_ascii[] =
	// Header
	"D1840S0ES00N0400CT000405CC020002F0MIICLjCCAdSgAwIBAgIIGDrdWBxuNpAwCgYIKoZIzj0EAwIwMTEXMBUGA1UECgwOQWxwaGEgTWVyY2hhbnQxFjAUBgNVBAMMDVNhbXBsZSBFQ0MgQ0EwHhcNMjAwODE1MDIxMDEwWhcNMjEwODE1MDIxMDEwWjBPMRcwFQYDVQQKDA5BbHBoYSBNZXJjaGFudDEfMB0GA1UECwwWVExTIENsaWVudCBDZXJ0aWZpY2F0ZTETMBEGA1UEAwwKMTIzNDU2Nzg5MDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEI/SLrH6fITA9y6Y3BneuoT/5+EHSepZxCYeSstGll2sVvmSDZWWSbN6lh5Fb/zagrDjjQ/gZtWIOTf2wL1vSGjgbcwgbQwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFHuvP526vFMywEoVoXZ5aXNfhnfeMB8GA1UdIwQYMBaAFI+ZFhOWF+oMtcfYwg15vH5WmWccMEIGA1UdHwQ7MDkwN6A1oDOGMWh0dHA6Ly9jcmwuYWxwaGEtbWVyY2hhbnQuZXhhbXBsZS9TYW1wbGVFQ0NDQS5jcmwwCgYIKoZIzj0EAwIDSAAwRQIhAPuWWvCTmOdvQzUjCUmTX7H4sX4Ebpw+CI+aOQLu1DqwAiA0eR4FdMtvXV4P6+WMz5B10oea5xtLTfSgoBDoTkvKYQ==0002C4MIICDjCCAbOgAwIBAgIIfnOsCbsxHjwwCgYIKoZIzj0EAwIwNjEXMBUGA1UECgwOQWxwaGEgTWVyY2hhbnQxGzAZBgNVBAMMElNhbXBsZSBSb290IEVDQyBDQTAeFw0yMDA4MTUwMjEwMDlaFw0zMDA4MTMwMjEwMDlaMDExFzAVBgNVBAoMDkFscGhhIE1lcmNoYW50MRYwFAYDVQQDDA1TYW1wbGUgRUNDIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHCanM9n+Rji+3EROj+HlogmXMU1Fk1td7N3I/8rfFnre1GwWCUqXSePHxwQ9DRHCV3oht3OUU2kDfitfUIujA6OBrzCBrDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUj5kWE5YX6gy1x9jCDXm8flaZZxwwHwYDVR0jBBgwFoAUvElIifFlt6oeUaopV9Y0lJtyPVQwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NybC5hbHBoYS1tZXJjaGFudC5leGFtcGxlL1NhbXBsZVJvb3RFQ0NDQS5jcmwwCgYIKoZIzj0EAwIDSQAwRgIhALT8+DG+++KuqqUGyBQ4YG4s34fqbujclxZTHxYWVVSNAiEAn3v5Xmct7fkLpkjGexiHsy6D90r0K2LlUqpN/069y5s=KP10012331550BC9TS1320200818004100ZPB110000000000000"

	// Encrypted data
	"23806274FDDE312047FA37117320D914DD1CF20705A140E39FF88DF107110F26DDFDB20AD909B4C67987C76907C6518B63C8BB7969A52BA3EE6218C9B29F02C243D23E5DF5F87D4CBC0E587DD619F1F228D3F605316DC39DDD6E9D13BAB633D13A97BE7EF67DBEECADA32FA968E57BDF87EE5AEAA47CDCF427154AE66508B99E"

	// MAC
	"F6186011C7BE905F875B24C5D05EA14E";
static const uint8_t test18_kcv_kbpk_verify[] = { 0x23, 0x31, 0x55, 0x0B, 0xC9 };
static const char test18_tr31_ts_verify[] = "20200818004100Z";

int main(void)
{
	int r;
	struct tr31_key_t test_kbpk;
	struct tr31_ctx_t test_tr31;
	const struct tr31_opt_ctx_t* opt_ctx;
	uint8_t ksn[20];
	struct tr31_opt_blk_kcv_data_t kcv_data;

	// populate key block protection key
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_TDES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test1_kbpk);
	test_kbpk.data = (void*)test1_kbpk;

	// test key block decryption for format version A
	printf("Test 1 (Basic format version A)...\n");
	r = tr31_import(test1_tr31_format_a, strlen(test1_tr31_format_a), &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_A ||
		test_tr31.length != 72 ||
		test_tr31.key.usage != TR31_KEY_USAGE_KEK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ANY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_str[0] != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != sizeof(test1_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test1_tr31_key_verify, sizeof(test1_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test1_tr31_kcv_verify, sizeof(test1_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// test key block decryption for format version B
	printf("Test 1 (Basic format version B)...\n");
	r = tr31_import(test1_tr31_format_b, strlen(test1_tr31_format_b), &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_B ||
		test_tr31.length != 80 ||
		test_tr31.key.usage != TR31_KEY_USAGE_KEK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ANY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_str[0] != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != sizeof(test1_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test1_tr31_key_verify, sizeof(test1_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test1_tr31_kcv_verify, sizeof(test1_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// test key block decryption for format version C
	printf("Test 1 (Basic format version C)...\n");
	r = tr31_import(test1_tr31_format_c, strlen(test1_tr31_format_c), &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_C ||
		test_tr31.length != 72 ||
		test_tr31.key.usage != TR31_KEY_USAGE_KEK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ANY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_str[0] != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != sizeof(test1_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test1_tr31_key_verify, sizeof(test1_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test1_tr31_kcv_verify, sizeof(test1_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// TR-31:2018, A.7.2.1
	printf("Test 2 (TR-31:2018, A.7.2.1)...\n");
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_TDES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test2_kbpk);
	test_kbpk.data = (void*)test2_kbpk;
	r = tr31_import(test2_tr31_ascii, strlen(test2_tr31_ascii), &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_A ||
		test_tr31.length != 72 ||
		test_tr31.key.usage != TR31_KEY_USAGE_PEK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ENC ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_str[0] != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_TRUSTED ||
		test_tr31.key.length != sizeof(test2_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test2_tr31_key_verify, sizeof(test2_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test2_tr31_kcv_verify, sizeof(test2_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// TR-31:2018, A.7.2.2
	printf("Test 3 (TR-31:2018, A.7.2.2)...\n");
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_TDES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test3_kbpk);
	test_kbpk.data = (void*)test3_kbpk;
	r = tr31_import(test3_tr31_ascii, strlen(test3_tr31_ascii), &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_B ||
		test_tr31.length != 80 ||
		test_tr31.key.usage != TR31_KEY_USAGE_PEK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ENC ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_str[0] != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_TRUSTED ||
		test_tr31.key.length != sizeof(test3_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test3_tr31_key_verify, sizeof(test3_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test3_tr31_kcv_verify, sizeof(test3_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// TR-31:2018, A.7.3.1
	printf("Test 4 (TR-31:2018, A.7.3.1)...\n");
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_TDES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test4_kbpk);
	test_kbpk.data = (void*)test4_kbpk;
	r = tr31_import(test4_tr31_ascii, strlen(test4_tr31_ascii), &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_C ||
		test_tr31.length != 96 ||
		test_tr31.key.usage != TR31_KEY_USAGE_BDK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_DERIVE||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_VALID ||
		memcmp(test_tr31.key.key_version_str, "12", 2) != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_SENSITIVE ||
		test_tr31.key.length != sizeof(test4_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 1 ||
		test_tr31.opt_blocks == NULL ||
		test_tr31.opt_blocks[0].id != TR31_OPT_BLOCK_KS ||
		test_tr31.opt_blocks[0].data == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test4_tr31_key_verify, sizeof(test4_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test4_tr31_kcv_verify, sizeof(test4_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	opt_ctx = tr31_opt_block_find(&test_tr31, TR31_OPT_BLOCK_KS);
	if (opt_ctx != &test_tr31.opt_blocks[0]) {
		fprintf(stderr, "tr31_opt_block_find() failed; r=%d\n", r);
		r = 1;
		goto exit;
	}
	if (opt_ctx->data_length != sizeof(test4_tr31_ksn_verify) * 2) {
		fprintf(stderr, "TR-31 optional block KS data length is incorrect\n");
		r = 1;
		goto exit;
	}
	memset(ksn, 0, sizeof(ksn));
	r = tr31_opt_block_decode_KS(opt_ctx, ksn, sizeof(test4_tr31_ksn_verify));
	if (r) {
		fprintf(stderr, "tr31_opt_block_decode_KS() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(ksn, test4_tr31_ksn_verify, sizeof(test4_tr31_ksn_verify)) != 0) {
		fprintf(stderr, "TR-31 optional block KS decoded data is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// TR-31:2018, A.7.3.2
	printf("Test 5 (TR-31:2018, A.7.3.2)...\n");
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_TDES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test5_kbpk);
	test_kbpk.data = (void*)test5_kbpk;
	r = tr31_import(test5_tr31_ascii, strlen(test5_tr31_ascii), &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_B ||
		test_tr31.length != 104 ||
		test_tr31.key.usage != TR31_KEY_USAGE_BDK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_DERIVE||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_VALID ||
		memcmp(test_tr31.key.key_version_str, "12", 2) != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_SENSITIVE ||
		test_tr31.key.length != sizeof(test5_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 1 ||
		test_tr31.opt_blocks == NULL ||
		test_tr31.opt_blocks[0].id != TR31_OPT_BLOCK_KS ||
		test_tr31.opt_blocks[0].data == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test5_tr31_key_verify, sizeof(test5_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test5_tr31_kcv_verify, sizeof(test5_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	opt_ctx = tr31_opt_block_find(&test_tr31, TR31_OPT_BLOCK_KS);
	if (opt_ctx != &test_tr31.opt_blocks[0]) {
		fprintf(stderr, "tr31_opt_block_find() failed; r=%d\n", r);
		r = 1;
		goto exit;
	}
	if (opt_ctx->data_length != sizeof(test5_tr31_ksn_verify) * 2) {
		fprintf(stderr, "TR-31 optional block KS data length is incorrect\n");
		r = 1;
		goto exit;
	}
	memset(ksn, 0, sizeof(ksn));
	r = tr31_opt_block_decode_KS(opt_ctx, ksn, sizeof(test5_tr31_ksn_verify));
	if (r) {
		fprintf(stderr, "tr31_opt_block_decode_KS() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(ksn, test5_tr31_ksn_verify, sizeof(test5_tr31_ksn_verify)) != 0) {
		fprintf(stderr, "TR-31 optional block KS decoded data is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// TR-31:2018, A.7.4
	printf("Test 6 (TR-31:2018, A.7.4)...\n");
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_AES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test6_kbpk);
	test_kbpk.data = (void*)test6_kbpk;
	r = tr31_import(test6_tr31_ascii, strlen(test6_tr31_ascii), &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_D ||
		test_tr31.length != 112 ||
		test_tr31.key.usage != TR31_KEY_USAGE_PEK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_AES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ENC ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_str[0] != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_TRUSTED ||
		test_tr31.key.length != sizeof(test6_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test6_tr31_key_verify, sizeof(test6_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test6_tr31_kcv_verify, sizeof(test6_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// test key block decryption for format version D containing TDES key
	printf("Test 7 (Format version D containing TDES key)...\n");
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_AES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test7_kbpk);
	test_kbpk.data = (void*)test7_kbpk;
	r = tr31_import(test7_tr31_ascii, strlen(test7_tr31_ascii), &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_D ||
		test_tr31.length != 112 ||
		test_tr31.key.usage != TR31_KEY_USAGE_BDK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ANY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_str[0] != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != sizeof(test7_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test7_tr31_key_verify, sizeof(test7_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test7_tr31_kcv_verify, sizeof(test7_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// test key block decryption for format version D containing AES key
	printf("Test 8 (Format version D containing AES key)...\n");
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_AES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test8_kbpk);
	test_kbpk.data = (void*)test8_kbpk;
	r = tr31_import(test8_tr31_ascii, strlen(test8_tr31_ascii), &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_D ||
		test_tr31.length != 144 ||
		test_tr31.key.usage != TR31_KEY_USAGE_DATA ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_AES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ANY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_str[0] != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != sizeof(test8_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test8_tr31_key_verify, sizeof(test8_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test8_tr31_kcv_verify, sizeof(test8_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// ISO 20038:2017, B.2
	printf("Test 9 (ISO 20038:2017, B.2)...\n");
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_AES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test9_kbpk);
	test_kbpk.data = (void*)test9_kbpk;
	r = tr31_import(test9_tr31_ascii, strlen(test9_tr31_ascii), &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_E ||
		test_tr31.length != 84 ||
		test_tr31.key.usage != TR31_KEY_USAGE_BDK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_MAC_VERIFY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_VALID ||
		memcmp(test_tr31.key.key_version_str, "16", 2) != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != sizeof(test9_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test9_tr31_key_verify, sizeof(test9_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test9_tr31_kcv_verify, sizeof(test9_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// ISO 20038:2017, B.3
	printf("Test 10 (ISO 20038:2017, B.3)...\n");
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_AES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test10_kbpk);
	test_kbpk.data = (void*)test10_kbpk;
	r = tr31_import(test10_tr31_ascii, strlen(test10_tr31_ascii), &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_D ||
		test_tr31.length != 112 ||
		test_tr31.key.usage != TR31_KEY_USAGE_ISO9797_1_MAC_3 ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_MAC_VERIFY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_VALID ||
		memcmp(test_tr31.key.key_version_str, "16", 2) != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != sizeof(test10_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test10_tr31_key_verify, sizeof(test10_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test10_tr31_kcv_verify, sizeof(test10_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// ANSI X9.143:2021, 8.1
	printf("Test 11 (ANSI X9.143:2021, 8.1)...\n");
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_AES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test11_kbpk);
	test_kbpk.data = (void*)test11_kbpk;
	r = tr31_import(test11_tr31_ascii, strlen(test11_tr31_ascii), &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_D ||
		test_tr31.length != 144 ||
		test_tr31.key.usage != TR31_KEY_USAGE_PEK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_AES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ENC ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_str[0] != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_TRUSTED ||
		test_tr31.key.length != sizeof(test11_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test11_tr31_key_verify, sizeof(test11_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test11_tr31_kcv_verify, sizeof(test11_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// ANSI X9.143:2021, 8.4.1
	printf("Test 15 (ANSI X9.143:2021, 8.4.1)...\n");
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_TDES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test15_kbpk);
	test_kbpk.data = (void*)test15_kbpk;
	r = tr31_import(test15_tr31_ascii, strlen(test15_tr31_ascii), &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_C ||
		test_tr31.length != 112 ||
		test_tr31.key.usage != TR31_KEY_USAGE_BDK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_DERIVE ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_VALID ||
		memcmp(test_tr31.key.key_version_str, "12", 2) != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_SENSITIVE ||
		test_tr31.key.length != sizeof(test15_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 1 ||
		test_tr31.opt_blocks == NULL ||
		test_tr31.opt_blocks[0].id != TR31_OPT_BLOCK_KS ||
		test_tr31.opt_blocks[0].data == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test15_tr31_key_verify, sizeof(test15_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test15_tr31_kcv_verify, sizeof(test15_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	opt_ctx = tr31_opt_block_find(&test_tr31, TR31_OPT_BLOCK_KS);
	if (opt_ctx != &test_tr31.opt_blocks[0]) {
		fprintf(stderr, "tr31_opt_block_find() failed; r=%d\n", r);
		r = 1;
		goto exit;
	}
	if (opt_ctx->data_length != sizeof(test15_tr31_ksn_verify) * 2) {
		fprintf(stderr, "TR-31 optional block KS data length is incorrect\n");
		r = 1;
		goto exit;
	}
	memset(ksn, 0, sizeof(ksn));
	r = tr31_opt_block_decode_KS(opt_ctx, ksn, sizeof(test15_tr31_ksn_verify));
	if (r) {
		fprintf(stderr, "tr31_opt_block_decode_KS() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(ksn, test15_tr31_ksn_verify, sizeof(test15_tr31_ksn_verify)) != 0) {
		fprintf(stderr, "TR-31 optional block KS decoded data is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// ANSI X9.143:2021, 8.4.2
	printf("Test 16 (ANSI X9.143:2021, 8.4.2)...\n");
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_TDES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test16_kbpk);
	test_kbpk.data = (void*)test16_kbpk;
	r = tr31_import(test16_tr31_ascii, strlen(test16_tr31_ascii), &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_B ||
		test_tr31.length != 120 ||
		test_tr31.key.usage != TR31_KEY_USAGE_BDK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_DERIVE ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_VALID ||
		memcmp(test_tr31.key.key_version_str, "12", 2) != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_SENSITIVE ||
		test_tr31.key.length != sizeof(test16_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 1 ||
		test_tr31.opt_blocks == NULL ||
		test_tr31.opt_blocks[0].id != TR31_OPT_BLOCK_KS ||
		test_tr31.opt_blocks[0].data == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test16_tr31_key_verify, sizeof(test16_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test16_tr31_kcv_verify, sizeof(test16_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	opt_ctx = tr31_opt_block_find(&test_tr31, TR31_OPT_BLOCK_KS);
	if (opt_ctx != &test_tr31.opt_blocks[0]) {
		fprintf(stderr, "tr31_opt_block_find() failed; r=%d\n", r);
		r = 1;
		goto exit;
	}
	if (opt_ctx->data_length != sizeof(test16_tr31_ksn_verify) * 2) {
		fprintf(stderr, "TR-31 optional block KS data length is incorrect\n");
		r = 1;
		goto exit;
	}
	memset(ksn, 0, sizeof(ksn));
	r = tr31_opt_block_decode_KS(opt_ctx, ksn, sizeof(test16_tr31_ksn_verify));
	if (r) {
		fprintf(stderr, "tr31_opt_block_decode_KS() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(ksn, test16_tr31_ksn_verify, sizeof(test16_tr31_ksn_verify)) != 0) {
		fprintf(stderr, "TR-31 optional block KS decoded data is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// ANSI X9.143:2021, 8.5
	printf("Test 17 (ANSI X9.143:2021, 8.5)...\n");
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_AES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test17_kbpk);
	test_kbpk.data = (void*)test17_kbpk;
	r = tr31_import(test17_tr31_ascii, strlen(test17_tr31_ascii), &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_D ||
		test_tr31.length != 3776 ||
		test_tr31.key.usage != TR31_KEY_USAGE_AKP_SIG ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_RSA ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_SIG ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != 1192 ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 4 ||
		test_tr31.opt_blocks == NULL ||
		test_tr31.opt_blocks[0].id != TR31_OPT_BLOCK_CT ||
		test_tr31.opt_blocks[0].data_length != 0x500 - 10 ||
		test_tr31.opt_blocks[1].id != TR31_OPT_BLOCK_KP ||
		test_tr31.opt_blocks[1].data == NULL ||
		test_tr31.opt_blocks[2].id != TR31_OPT_BLOCK_TS ||
		test_tr31.opt_blocks[2].data == NULL ||
		memcmp(test_tr31.opt_blocks[2].data, test17_tr31_ts_verify, strlen(test17_tr31_ts_verify)) != 0 ||
		test_tr31.opt_blocks[3].id != TR31_OPT_BLOCK_PB
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	opt_ctx = tr31_opt_block_find(&test_tr31, TR31_OPT_BLOCK_KP);
	if (opt_ctx != &test_tr31.opt_blocks[1]) {
		fprintf(stderr, "tr31_opt_block_find() failed; r=%d\n", r);
		r = 1;
		goto exit;
	}
	if (opt_ctx->data_length != (sizeof(test17_kcv_kbpk_verify) + 1) * 2) {
		fprintf(stderr, "TR-31 optional block KP data length is incorrect\n");
		r = 1;
		goto exit;
	}
	memset(&kcv_data, 0, sizeof(kcv_data));
	r = tr31_opt_block_decode_KP(opt_ctx, &kcv_data);
	if (r) {
		fprintf(stderr, "tr31_opt_block_decode_KP() failed; r=%d\n", r);
		goto exit;
	}
	if (kcv_data.kcv_algorithm != TR31_OPT_BLOCK_KCV_CMAC) {
		fprintf(stderr, "TR-31 optional block KP algorithm is incorrect\n");
		r = 1;
		goto exit;
	}
	if (kcv_data.kcv_len != sizeof(test17_kcv_kbpk_verify) ||
		memcmp(kcv_data.kcv, test17_kcv_kbpk_verify, sizeof(test17_kcv_kbpk_verify)) != 0
	) {
		fprintf(stderr, "TR-31 optional block KP data is incorrect\n");
		r = 1;
		goto exit;
	}
	opt_ctx = tr31_opt_block_find(&test_tr31, TR31_OPT_BLOCK_TS);
	if (opt_ctx != &test_tr31.opt_blocks[2]) {
		fprintf(stderr, "tr31_opt_block_find() failed; r=%d\n", r);
		r = 1;
		goto exit;
	}
	if (opt_ctx->data_length != strlen(test17_tr31_ts_verify)) {
		fprintf(stderr, "TR-31 optional block TS data length is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// ANSI X9.143:2021, 8.6
	printf("Test 18 (ANSI X9.143:2021, 8.6)...\n");
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_AES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test18_kbpk);
	test_kbpk.data = (void*)test18_kbpk;
	r = tr31_import(test18_tr31_ascii, strlen(test18_tr31_ascii), &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_D ||
		test_tr31.length != 1840 ||
		test_tr31.key.usage != TR31_KEY_USAGE_AKP_SIG ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_EC ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_SIG ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != 121 ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 4 ||
		test_tr31.opt_blocks == NULL ||
		test_tr31.opt_blocks[0].id != TR31_OPT_BLOCK_CT ||
		test_tr31.opt_blocks[0].data_length != 0x5CC - 10 ||
		test_tr31.opt_blocks[1].id != TR31_OPT_BLOCK_KP ||
		test_tr31.opt_blocks[1].data == NULL ||
		test_tr31.opt_blocks[2].id != TR31_OPT_BLOCK_TS ||
		test_tr31.opt_blocks[2].data == NULL ||
		memcmp(test_tr31.opt_blocks[2].data, test18_tr31_ts_verify, strlen(test18_tr31_ts_verify)) != 0 ||
		test_tr31.opt_blocks[3].id != TR31_OPT_BLOCK_PB
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	opt_ctx = tr31_opt_block_find(&test_tr31, TR31_OPT_BLOCK_KP);
	if (opt_ctx != &test_tr31.opt_blocks[1]) {
		fprintf(stderr, "tr31_opt_block_find() failed; r=%d\n", r);
		r = 1;
		goto exit;
	}
	if (opt_ctx->data_length != (sizeof(test18_kcv_kbpk_verify) + 1) * 2) {
		fprintf(stderr, "TR-31 optional block KP data length is incorrect\n");
		r = 1;
		goto exit;
	}
	memset(&kcv_data, 0, sizeof(kcv_data));
	r = tr31_opt_block_decode_KP(opt_ctx, &kcv_data);
	if (r) {
		fprintf(stderr, "tr31_opt_block_decode_KP() failed; r=%d\n", r);
		goto exit;
	}
	if (kcv_data.kcv_algorithm != TR31_OPT_BLOCK_KCV_CMAC) {
		fprintf(stderr, "TR-31 optional block KP algorithm is incorrect\n");
		r = 1;
		goto exit;
	}
	if (kcv_data.kcv_len != sizeof(test18_kcv_kbpk_verify) ||
		memcmp(kcv_data.kcv, test18_kcv_kbpk_verify, sizeof(test18_kcv_kbpk_verify)) != 0
	) {
		fprintf(stderr, "TR-31 optional block KP data is incorrect\n");
		r = 1;
		goto exit;
	}
	opt_ctx = tr31_opt_block_find(&test_tr31, TR31_OPT_BLOCK_TS);
	if (opt_ctx != &test_tr31.opt_blocks[2]) {
		fprintf(stderr, "tr31_opt_block_find() failed; r=%d\n", r);
		r = 1;
		goto exit;
	}
	if (opt_ctx->data_length != strlen(test18_tr31_ts_verify)) {
		fprintf(stderr, "TR-31 optional block TS data length is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	tr31_release(&test_tr31);
	return r;
}
