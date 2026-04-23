"""
Tests for stale-reply detection and _parse_multi_read_response hardening.

These tests exercise the two captured production failure cases described in the
GitHub issue, plus a happy-path test to confirm normal MSP parsing still works.

No live PLC is required — all I/O is bypassed by injecting raw byte payloads
directly into the methods under test.
"""

import sys
import os
import unittest
from struct import pack, unpack_from

# Ensure we import from the local source tree, not any installed copy.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pylogix
from pylogix import PLC
from pylogix.lgx_comm import Connection, _StaleReplyError


# ---------------------------------------------------------------------------
# Shared tag list used across fixtures (4 tags, no known type yet)
# ---------------------------------------------------------------------------
TAGS_4 = [
    ("Program:Event.logBuffer[54].sequence",  1, None),
    ("Program:Event.logBuffer[54].timeStamp", 1, None),
    ("Program:Event.logBuffer[54].logLevel",  1, None),
    ("Program:Event.logBuffer[54].source",    1, None),
]

# ---------------------------------------------------------------------------
# Fixture 1: wrong CIP service — raw reply is a single ReadTag reply (0xCC)
# instead of an MSP reply (0x8A).  service_count field would be 196 (garbage).
# ---------------------------------------------------------------------------
RAW_1 = bytes.fromhex(
    "70002000ee030040"
    "000000000000000000000000000000000000000000000200"
    "a100040059c60000"
    "b1000c003275"
    "cc000000"          # CIP reply service 0xCC (ReadTag reply, NOT MSP)
    "c40008000000"      # DINT type + value 8
)

# ---------------------------------------------------------------------------
# Fixture 2: correct MSP service (0x8A) but service_count=10 while only 4
# tags were requested → _parse_multi_read_response would IndexError at i=4.
# ---------------------------------------------------------------------------
RAW_2 = bytes.fromhex(
    "70008200ed030040"
    "000000000000000000000000000000000000000000000200"
    "a1000400a7b50000"
    "b1006e003b93"
    "8a000000"          # CIP reply service 0x8A (MSP reply) + status 0
    "0a00"              # service_count = 10  (but 4 tags were sent)
    "160020002a00310038003f004600500057005e00"   # 10 offsets
    "cc000000ca003400c841"
    "cc000000ca0000001644"
    "cc000000c10001"
    "cc000000c10000"
    "cc000000c10001"
    "cc000000c10000"
    "cc000000ca0000002643"
    "cc000000c10000"
    "cc000000c10001"
    "cc000000ca0000e02f44"
)

# ---------------------------------------------------------------------------
# Happy-path fixture: hand-crafted valid MSP reply for exactly 4 DINT tags.
#
# Layout after the 50-byte header (bytes 0-49):
#   [50-51]  service_count = 4
#   [52-53]  offset[0] = 10  (2 + 4*2 = 10)
#   [54-55]  offset[1] = 16  (10 + 6)
#   [56-57]  offset[2] = 22
#   [58-59]  offset[3] = 28
#   sub-reply 0 @ 10: cc 00 00 00  c4 00  01 00 00 00   (DINT=1)
#   sub-reply 1 @ 16: cc 00 00 00  c4 00  02 00 00 00   (DINT=2)
#   sub-reply 2 @ 22: cc 00 00 00  c4 00  03 00 00 00   (DINT=3)
#   sub-reply 3 @ 28: cc 00 00 00  c4 00  04 00 00 00   (DINT=4)
# ---------------------------------------------------------------------------
def _build_happy_path_raw():
    """Build a minimal valid connected MSP reply for 4 DINT tags."""
    # Fixed 50-byte preamble (EIP encap header + CPF items + CIP reply header)
    # bytes 0-23:  EIP encap header
    eip_command    = pack('<H', 0x0070)
    # We will fill in length after we know payload size
    session_handle = pack('<I', 0x400003ED)
    status         = pack('<I', 0x00000000)
    context        = pack('<Q', 0x0000000000000000)
    options        = pack('<I', 0x00000000)
    # bytes 24-29: interface handle + timeout
    iface_handle   = pack('<I', 0x00000000)
    timeout        = pack('<H', 0x0000)
    # bytes 30-31: item count = 2
    item_count     = pack('<H', 0x0002)
    # bytes 32-39: item1 (0xA1, len=4, OT conn ID)
    item1_type     = pack('<H', 0x00A1)
    item1_len      = pack('<H', 0x0004)
    item1_data     = pack('<I', 0x0000B5A7)
    # bytes 40-45: item2 header (0xB1, len, seq)
    item2_type     = pack('<H', 0x00B1)
    # item2 length and seq filled in below
    cpf_seq        = pack('<H', 0x0001)
    # bytes 46-49: CIP reply header (service=0x8A, res, res, status=0)
    cip_hdr        = pack('<BBBB', 0x8A, 0x00, 0x00, 0x00)

    # Build the MSP payload (bytes 50+)
    # Each sub-reply for a DINT is 10 bytes:
    #   [0] CIP reply service (0xCC)
    #   [1] reserved
    #   [2] general status (0 = success)
    #   [3] extended status count (0)
    #   [4-5] data type (0xC4 = DINT, little-endian H)
    #   [6-9] value (little-endian i)
    # After strip, data layout:
    #   [0-1]  service_count = 4
    #   [2-3]  offset[0] = 10  (2 + 4*2)
    #   [4-5]  offset[1] = 20
    #   [6-7]  offset[2] = 30
    #   [8-9]  offset[3] = 40
    #   [10-19] sub-reply 0
    #   [20-29] sub-reply 1
    #   [30-39] sub-reply 2
    #   [40-49] sub-reply 3
    service_count  = pack('<H', 4)
    offsets        = pack('<HHHH', 10, 20, 30, 40)
    sub_replies    = (
        pack('<BBBB', 0xCC, 0x00, 0x00, 0x00) + pack('<H', 0xC4) + pack('<i', 1) +
        pack('<BBBB', 0xCC, 0x00, 0x00, 0x00) + pack('<H', 0xC4) + pack('<i', 2) +
        pack('<BBBB', 0xCC, 0x00, 0x00, 0x00) + pack('<H', 0xC4) + pack('<i', 3) +
        pack('<BBBB', 0xCC, 0x00, 0x00, 0x00) + pack('<H', 0xC4) + pack('<i', 4)
    )
    msp_payload = service_count + offsets + sub_replies

    # item2 length = cpf_seq (2 bytes) + cip_hdr (4 bytes) + msp_payload
    item2_len_val = 2 + 4 + len(msp_payload)
    item2_len     = pack('<H', item2_len_val)

    # encap length = everything after the 24-byte encap header
    inner = (iface_handle + timeout + item_count +
             item1_type + item1_len + item1_data +
             item2_type + item2_len + cpf_seq +
             cip_hdr + msp_payload)
    eip_len = pack('<H', len(inner))

    return eip_command + eip_len + session_handle + status + context + options + inner


RAW_HAPPY = _build_happy_path_raw()


# ---------------------------------------------------------------------------
# Helper: create a PLC instance without touching the network
# ---------------------------------------------------------------------------
def _make_plc():
    plc = PLC.__new__(PLC)
    # Manually initialise __slots__
    plc.IPAddress = "127.0.0.1"
    plc.Port = 44818
    plc.ProcessorSlot = 0
    plc.SocketTimeout = 5.0
    plc.Micro800 = False
    plc.Route = None
    plc.Offset = 0
    plc.UDT = {}
    plc.UDTByName = {}
    plc.KnownTags = {}
    plc.TagList = []
    plc.ProgramNames = []
    plc.StringID = 0x0fce
    plc.StringEncoding = 'utf-8'
    plc.callback = None
    plc.element_count = 0
    plc.msg_values = []
    plc.msg_bytes = b''
    plc.CIPTypes = {
        0x00: (1,  "UNKNOWN", '<B'),
        0xa0: (88, "STRUCT",  '<B'),
        0xc4: (4,  "DINT",    '<i'),
        0xc1: (1,  "BOOL",    '<?'),
        0xca: (4,  "REAL",    '<f'),
    }
    plc.conn = Connection(plc)
    return plc


class TestParseMultiReadResponse(unittest.TestCase):
    """Unit tests for _parse_multi_read_response hardening."""

    def setUp(self):
        self.plc = _make_plc()

    # ------------------------------------------------------------------
    # Fixture 1: wrong CIP service (0xCC instead of 0x8A)
    # ------------------------------------------------------------------
    def test_wrong_cip_service_no_exception(self):
        """Must not raise; returns 4-element failure list."""
        result = self.plc._parse_multi_read_response(RAW_1, TAGS_4)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 4)

    def test_wrong_cip_service_all_values_none(self):
        result = self.plc._parse_multi_read_response(RAW_1, TAGS_4)
        for tag_name, value, status in result:
            self.assertIsNone(value)

    def test_wrong_cip_service_status_is_string(self):
        """Status must be a non-empty string describing the problem."""
        result = self.plc._parse_multi_read_response(RAW_1, TAGS_4)
        for tag_name, value, status in result:
            self.assertIsInstance(status, str)
            self.assertTrue(len(status) > 0)

    # ------------------------------------------------------------------
    # Fixture 2: MSP service_count mismatch (10 vs 4 requested tags)
    # ------------------------------------------------------------------
    def test_service_count_mismatch_no_exception(self):
        """Must not raise IndexError; returns 4-element failure list."""
        result = self.plc._parse_multi_read_response(RAW_2, TAGS_4)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 4)

    def test_service_count_mismatch_all_values_none(self):
        result = self.plc._parse_multi_read_response(RAW_2, TAGS_4)
        for tag_name, value, status in result:
            self.assertIsNone(value)

    def test_service_count_mismatch_status_is_string(self):
        result = self.plc._parse_multi_read_response(RAW_2, TAGS_4)
        for tag_name, value, status in result:
            self.assertIsInstance(status, str)
            self.assertIn("10", status)   # reports the received count
            self.assertIn("4", status)    # reports the expected count

    # ------------------------------------------------------------------
    # Happy path: valid 4-DINT MSP reply
    # ------------------------------------------------------------------
    def test_happy_path_returns_four_results(self):
        result = self.plc._parse_multi_read_response(RAW_HAPPY, TAGS_4)
        self.assertEqual(len(result), 4)

    def test_happy_path_values_correct(self):
        result = self.plc._parse_multi_read_response(RAW_HAPPY, TAGS_4)
        values = [v for _, v, _ in result]
        self.assertEqual(values, [1, 2, 3, 4])

    def test_happy_path_status_success(self):
        result = self.plc._parse_multi_read_response(RAW_HAPPY, TAGS_4)
        for tag_name, value, status in result:
            self.assertEqual(status, 0)


class TestValidateReply(unittest.TestCase):
    """Unit tests for Connection._validate_reply."""

    def setUp(self):
        self.conn = Connection(_make_plc())

    def test_no_expected_values_skips_validation(self):
        """When _last_sent_cpf_seq is None, _validate_reply must not raise."""
        self.conn._last_sent_cpf_seq = None
        self.conn._last_sent_cip_service = None
        # Should not raise even for a garbage buffer
        self.conn._validate_reply(b'\x00' * 100)

    def test_too_short_raises(self):
        self.conn._last_sent_cpf_seq = 0x0001
        self.conn._last_sent_cip_service = 0x8A
        with self.assertRaises(_StaleReplyError):
            self.conn._validate_reply(b'\x00' * 46)

    def test_cpf_seq_mismatch_raises(self):
        self.conn._last_sent_cpf_seq = 0x0001
        self.conn._last_sent_cip_service = 0x8A
        # Build a 50-byte buffer with CPF seq = 0x9999 at bytes 44-45
        buf = bytearray(50)
        buf[44] = 0x99
        buf[45] = 0x99
        buf[46] = 0x8A
        with self.assertRaises(_StaleReplyError) as ctx:
            self.conn._validate_reply(bytes(buf))
        self.assertIn("CPF seq", str(ctx.exception))

    def test_cip_service_mismatch_raises(self):
        self.conn._last_sent_cpf_seq = 0x7532
        self.conn._last_sent_cip_service = 0x8A
        buf = bytearray(50)
        # CPF seq matches
        buf[44] = 0x32
        buf[45] = 0x75
        # Wrong CIP service
        buf[46] = 0xCC
        with self.assertRaises(_StaleReplyError) as ctx:
            self.conn._validate_reply(bytes(buf))
        self.assertIn("CIP service", str(ctx.exception))

    def test_matching_reply_does_not_raise(self):
        self.conn._last_sent_cpf_seq = 0x7532
        self.conn._last_sent_cip_service = 0x8A
        buf = bytearray(50)
        buf[44] = 0x32
        buf[45] = 0x75
        buf[46] = 0x8A
        # Should not raise
        self.conn._validate_reply(bytes(buf))

    def test_fixture1_wrong_service_raises(self):
        """Fixture 1 with expected MSP service should raise _StaleReplyError."""
        self.conn._last_sent_cpf_seq = 0x7532
        self.conn._last_sent_cip_service = 0x8A
        with self.assertRaises(_StaleReplyError):
            self.conn._validate_reply(RAW_1)


class TestStaleReplyErrorClass(unittest.TestCase):
    """Basic smoke-test for the _StaleReplyError exception."""

    def test_is_exception(self):
        self.assertTrue(issubclass(_StaleReplyError, Exception))

    def test_message_preserved(self):
        err = _StaleReplyError("test message")
        self.assertEqual(str(err), "test message")


class TestVersion(unittest.TestCase):
    def test_version_string(self):
        self.assertIn("manusolve", pylogix.__version__)


# ---------------------------------------------------------------------------
# Helper: build a minimal single-tag connected reply with struct (0xa0) type
# ---------------------------------------------------------------------------
def _build_single_struct_reply(struct_id_bytes: bytes, struct_content: bytes) -> bytes:
    """
    Build a minimal connected EIP reply for a single ReadTag of a struct type.
    Layout matches what _read_tag → _get_values sees:
      bytes  0-23: EIP encap header (command 0x70)
      bytes 24-29: interface handle + timeout
      bytes 30-31: item count = 2
      bytes 32-39: item1 (0xA1, len=4, conn ID)
      bytes 40-43: item2 header (0xB1, len)
      bytes 44-45: CPF seq
      byte  46:    CIP reply service (0xCC = ReadTag reply)
      bytes 47-49: CIP reserved, status, ext_status_size
      bytes 50-51: data_type (0xa0 = struct)
      bytes 52-53: struct_id
      bytes 54+:   struct content
    """
    cip_payload = (
        pack('<BB', 0xa0, 0x00) +   # data_type = struct
        struct_id_bytes[:2] +        # struct_id (2 bytes)
        struct_content               # struct content
    )
    cip_hdr    = pack('<BBBB', 0xCC, 0x00, 0x00, 0x00)  # ReadTag reply, status 0
    cpf_seq    = pack('<H', 0x0001)
    item2_len  = pack('<H', 2 + 4 + len(cip_payload))   # seq + cip_hdr + payload

    item1      = pack('<HHI', 0x00A1, 0x0004, 0x0000B5A7)
    item2_hdr  = pack('<H', 0x00B1) + item2_len
    inner      = (pack('<IH', 0, 0) +        # interface handle, timeout
                  pack('<H', 2) +             # item count
                  item1 +
                  item2_hdr + cpf_seq + cip_hdr + cip_payload)
    eip_hdr    = (pack('<H', 0x0070) +
                  pack('<H', len(inner)) +
                  pack('<I', 0x400003ED) +   # session handle
                  pack('<I', 0) +            # status
                  pack('<Q', 0) +            # context
                  pack('<I', 0))             # options
    return eip_hdr + inner


# Helper: build a single-tag struct sub-reply segment for _parse_multi_read_response
def _build_struct_segment(struct_id: int, struct_content: bytes) -> bytes:
    """Return a CIP sub-reply segment for a struct tag."""
    return (
        pack('<BBBB', 0xCC, 0x00, 0x00, 0x00) +  # CIP reply service, status=0
        pack('<H', 0xa0) +                          # data_type = struct
        pack('<H', struct_id) +                     # struct_id
        struct_content
    )


def _build_std_string_content(text: str, encoding: str = 'utf-8') -> bytes:
    """Standard Logix STRING on-wire: 4-byte length + 82 bytes zero-padded data."""
    encoded = text.encode(encoding)[:82]
    return pack('<I', len(encoded)) + encoded + b'\x00' * (82 - len(encoded))


class TestCustomStringUDTDecode(unittest.TestCase):
    """
    Tests that structs with non-standard struct_ids are decoded as strings
    when they follow the same length-prefixed wire format (custom STRING UDTs).
    """

    def setUp(self):
        self.plc = _make_plc()
        self.plc.KnownTags['Program:ModeAuto'] = (0xa0, 88)

    # ------------------------------------------------------------------
    # _parse_multi_read_response path (batch reads)
    # ------------------------------------------------------------------
    def _run_batch_one_struct(self, struct_id, struct_content, expected_value):
        """Send a 1-tag batch with a single struct sub-reply."""
        tag = [("Program:ModeAuto.message", 1, None)]
        segment = _build_struct_segment(struct_id, struct_content)
        # Build minimal 50-byte preamble + MSP for 1 tag
        msp_service_count = pack('<H', 1)
        msp_offset        = pack('<H', 2 + 1*2)   # offset[0] = 4
        msp_payload       = msp_service_count + msp_offset + segment

        inner_data = (
            pack('<IH', 0, 0) +
            pack('<H', 2) +
            pack('<HHI', 0x00A1, 0x0004, 0) +
            pack('<HH', 0x00B1, 2 + 4 + len(msp_payload)) +
            pack('<H', 0x0001) +
            pack('<BBBB', 0x8A, 0x00, 0x00, 0x00) +
            msp_payload
        )
        raw = (
            pack('<H', 0x0070) +
            pack('<H', len(inner_data)) +
            pack('<I', 0x400003ED) +
            pack('<I', 0) +
            pack('<Q', 0) +
            pack('<I', 0) +
            inner_data
        )
        result = self.plc._parse_multi_read_response(raw, tag)
        self.assertEqual(len(result), 1)
        tag_name, value, status = result[0]
        self.assertEqual(value, expected_value)
        self.assertEqual(status, 0)

    def test_standard_string_id_decoded(self):
        """Sanity: struct_id == StringID (0x0fce) always decodes to str."""
        content = _build_std_string_content("hello")
        self._run_batch_one_struct(0x0fce, content, "hello")

    def test_custom_string_udt_decoded_as_str(self):
        """Custom struct_id but standard wire format → decoded as str."""
        content = _build_std_string_content("world")
        self._run_batch_one_struct(0x1234, content, "world")

    def test_custom_string_empty(self):
        """Custom UDT with empty string (length=0)."""
        content = _build_std_string_content("")
        self._run_batch_one_struct(0xABCD, content, "")

    def test_garbage_struct_falls_back_to_bytes(self):
        """If name_length would exceed segment bounds → falls back to bytes."""
        # name_length = 9999 far exceeds segment size
        bad_content = pack('<I', 9999) + b'\x41' * 10
        tag = [("Program:ModeAuto.message", 1, None)]
        segment = _build_struct_segment(0x1234, bad_content)
        msp_service_count = pack('<H', 1)
        msp_offset        = pack('<H', 4)
        msp_payload = msp_service_count + msp_offset + segment
        inner_data = (
            pack('<IH', 0, 0) + pack('<H', 2) +
            pack('<HHI', 0x00A1, 4, 0) +
            pack('<HH', 0x00B1, 2 + 4 + len(msp_payload)) +
            pack('<H', 1) +
            pack('<BBBB', 0x8A, 0, 0, 0) +
            msp_payload
        )
        raw = (pack('<H', 0x70) + pack('<H', len(inner_data)) +
               pack('<I', 0x400003ED) + pack('<I', 0) +
               pack('<Q', 0) + pack('<I', 0) + inner_data)
        result = self.plc._parse_multi_read_response(raw, tag)
        _, value, status = result[0]
        self.assertIsInstance(value, (bytes, bytearray))

    # ------------------------------------------------------------------
    # _get_values path (single-tag reads via _read_tag)
    # ------------------------------------------------------------------
    def _call_get_values(self, struct_id: int, struct_content: bytes):
        """Directly exercise _get_values for a struct tag."""
        # parse_tag_name('ModeAuto.message') returns base_tag='ModeAuto.message'
        self.plc.KnownTags['ModeAuto.message'] = (0xa0, 88)
        # Build data as _read_tag sees it (ret_data[50:]):
        #   [0:2]  = data_type (0xa0)
        #   [2:4]  = struct_id
        #   [4:]   = struct content
        data = pack('<BB', 0xa0, 0x00) + pack('<H', struct_id) + struct_content
        return self.plc._get_values('ModeAuto.message', data)

    def test_get_values_standard_string_id(self):
        content = _build_std_string_content("abc")
        values = self._call_get_values(0x0fce, content)
        self.assertEqual(values, ["abc"])

    def test_get_values_custom_string_id_decoded(self):
        content = _build_std_string_content("custom")
        values = self._call_get_values(0xDEAD, content)
        self.assertEqual(values, ["custom"])

    def test_get_values_garbage_falls_back_to_bytes(self):
        bad_content = pack('<I', 50000) + b'\x00' * 4
        values = self._call_get_values(0xDEAD, bad_content)
        self.assertEqual(len(values), 1)
        self.assertIsInstance(values[0], (bytes, bytearray))



