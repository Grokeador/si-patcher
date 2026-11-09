import struct
import unittest
import si_pe_inspect as m


def build_minimal_pe64() -> bytes:
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    pe_hdr = bytearray(24)
    pe_hdr[0:4] = b"PE\x00\x00"
    # machine=0x8664 (x64), num_sections=1, opt_hdr_size=112
    struct.pack_into("<HHIIIHH", pe_hdr, 4, 0x8664, 1, 0, 0, 0, 112, 0x0022)
    opt = bytearray(112)
    struct.pack_into("<H", opt, 0, 0x20B)  # PE32+
    struct.pack_into("<I", opt, 16, 0x1500)  # EntryPoint RVA
    struct.pack_into("<Q", opt, 24, 0x140000000)  # ImageBase
    struct.pack_into("<H", opt, 70, 0x0040)  # ASLR enabled
    sec = bytearray(40)
    sec[0:5] = b".text"
    struct.pack_into("<IIII", sec, 8, 0x4000, 0x1000, 0x4000, 0x400)
    return bytes(dos + pe_hdr + opt + sec)


class TestSiPatcher(unittest.TestCase):
    def test_exact_length_patch(self):
        res = m.validate_and_pad_patch("B8 1E 00 00 00", "B8 78 00 00 00")
        self.assertEqual(res["nopPaddingCount"], 0)
        self.assertEqual(res["paddedHex"], "B8 78 00 00 00")

    def test_shorter_patch_pads_with_nops(self):
        res = m.validate_and_pad_patch("74 12 8B 45 FC", "90 90")
        self.assertEqual(res["nopPaddingCount"], 3)
        self.assertEqual(res["paddedHex"], "90 90 90 90 90")

    def test_longer_patch_raises_value_error(self):
        with self.assertRaises(ValueError):
            m.validate_and_pad_patch("74 08", "E9 00 01 00 00")

    def test_wildcard_aob_masks_rip_relative_and_call(self):
        aob = m.generate_wildcard_aob("48 8B 05 12 34 56 78 B8 1E 00 00 00 E8 AA BB CC DD")
        self.assertEqual(aob, "48 8B 05 ?? ?? ?? ?? B8 1E 00 00 00 E8 ?? ?? ?? ??")

    def test_wildcard_aob_masks_conditional_near_jump(self):
        aob = m.generate_wildcard_aob("0F 84 11 22 33 44 90")
        self.assertEqual(aob, "0F 84 ?? ?? ?? ?? 90")

    def test_parse_minimal_pe64(self):
        pe = build_minimal_pe64()
        info = m.parse_pe_headers(pe)
        self.assertEqual(info["architecture"], "x64")
        self.assertEqual(info["peFormat"], "PE32+")
        self.assertEqual(info["imageBase"], "0x140000000")
        self.assertEqual(info["entryPointRVA"], "0x1500")
        self.assertTrue(info["aslrEnabled"])
        self.assertEqual(info["sections"][0]["name"], ".text")

    def test_invalid_pe_raises(self):
        with self.assertRaises(ValueError):
            m.parse_pe_headers(b"NOT_A_PE_FILE")

    def test_generate_asi_cpp_contains_rva_and_bytes(self):
        cpp = m.generate_asi_cpp("0x2A4F18", "B8 1E 00 00 00", "B8 78 00 00 00")
        self.assertIn("0x2A4F18", cpp)
        self.assertIn("0xB8, 0x78, 0x00, 0x00, 0x00", cpp)
        self.assertIn("VirtualProtect", cpp)


if __name__ == "__main__":
    unittest.main()
