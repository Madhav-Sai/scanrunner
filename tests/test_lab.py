"""Offline checks for the independent live-lab negotiation verifier."""
import struct
import unittest
from unittest import mock

from lab import negotiate


class LabVerifierTests(unittest.TestCase):
    def test_negotiation_requests_have_correct_headers_and_dialects(self):
        request = negotiate.smb2_request()
        self.assertEqual(len(request), 102)
        self.assertEqual(request[:4], b"\xfeSMB")
        self.assertEqual(struct.unpack_from("<H", request, 64)[0], 36)
        self.assertEqual(struct.unpack_from("<H", request, 100)[0], 0x0210)
        request = negotiate.smb1_request()
        self.assertEqual(request[:5], b"\xffSMB\x72")
        self.assertEqual(request[35:], b"\x02NT LM 0.12\x00")
        self.assertEqual(struct.unpack_from("<H", request, 33)[0], len(request) - 35)

    def test_smb2_required_optional_and_malformed_responses(self):
        for mode in (1, 3):
            response = bytearray(128)
            response[:4] = b"\xfeSMB"
            struct.pack_into("<H", response, 4, 64)
            struct.pack_into("<I", response, 16, 1)
            struct.pack_into("<HHH", response, 64, 65, mode, 0x0210)
            self.assertEqual(negotiate.parse_smb2(response)["signing_required"], mode == 3)
            with self.assertRaises(ValueError):
                negotiate.parse_smb2(response[:70])
            struct.pack_into("<I", response, 8, 0xC00000BB)
            with self.assertRaises(ValueError):
                negotiate.parse_smb2(response)

    def test_smb1_acceptance_and_rejection_are_distinct_from_malformed_data(self):
        response = bytearray(69)
        response[:5] = b"\xffSMB\x72"
        response[32] = 17
        self.assertTrue(negotiate.parse_smb1(response))
        struct.pack_into("<H", response, 33, 0xFFFF)
        self.assertFalse(negotiate.parse_smb1(response))
        with self.assertRaises(ValueError):
            negotiate.parse_smb1(b"unrecognized response")

    def test_probes_refuse_addresses_outside_the_owned_lab_before_connecting(self):
        with mock.patch.object(negotiate.socket, "create_connection") as connect, self.assertRaises(ValueError):
            negotiate.exchange("192.0.2.1", b"test")
        connect.assert_not_called()
