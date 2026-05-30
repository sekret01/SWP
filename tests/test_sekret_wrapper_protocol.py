import pytest

from sekret_wrapper_protocol.sekret_wrapper_protocol import SWP
from sekret_wrapper_protocol.swp_enums import MessageType
from sekret_wrapper_protocol.exceptions import AesGcmKeyError, HeaderNotCompliteError


class TestSWP:

    @pytest.fixture(scope="function", autouse=True)
    def reset_swp(self):
        SWP.reset()

    def test_pack(self):
        msg = b"message"
        swp_message = SWP.pack(
            msg_type=MessageType.MSG_CONNECT.value,
            target=b"127.0.0.1",
            payload=msg
        )
        expect_val = b"SWP" + b"\x01" + b"\x09" + b"\x00\x07" + b"127.0.0.1" + b"message"
        assert swp_message == expect_val
    
    def test_unpack(self):
        msg = b"message"
        swp_message = SWP.pack(
            msg_type=MessageType.MSG_CONNECT.value,
            target=b"127.0.0.1",
            payload=msg
        )

        unpack_res = SWP.unpack(buffer=swp_message)
        assert unpack_res["msg_type"] == 0x01
        assert unpack_res["target"] == b"127.0.0.1"
        assert unpack_res["payload"] == b"message"

    def test_get_full_package_size(self):
        msg = b"message"
        target = b"127.0.0.1"
        swp_message = SWP.pack(
            msg_type=MessageType.MSG_CONNECT.value,
            target=target,
            payload=msg
        )

        expect_val = 7 + len(target) + len(msg)
        assert SWP.get_full_package_size(swp_message) == expect_val
    
    def test_unpack_header(self):
        msg = b"message"
        target = b"127.0.0.1"
        swp_message = SWP.pack(
            msg_type=MessageType.MSG_CONNECT.value,
            target=target,
            payload=msg
        )

        exp_val = (b"SWP", 0x01, 9, 7)
        assert SWP.unpack_header(swp_message) == exp_val
    
    def test_unpack_header__header_not_complite(self):
        with pytest.raises(HeaderNotCompliteError) as ex:
            SWP.unpack_header(b"SWP\x01\x09")
        assert ex is not None
    
    def test_set_auto_encode(self):
        SWP.load_aesgcm(b"a" * 32)
        SWP.set_auto_encrypt(True)
        assert SWP.AUTO_ENCRYPT == True

    def test_set_auto_encode_after_load_key(self):
        SWP.load_aesgcm(b"a" * 32)
        assert SWP.AUTO_ENCRYPT == True
    
    def test_set_auto_encode__not_load_key(self):
        with pytest.raises(AesGcmKeyError) as ex:
            SWP.set_auto_encrypt(True)
        assert ex is not None

    def test_pack_with_auto_encrypt(self):
        SWP.load_aesgcm(b"a" * 32)
        msg = b"message"
        target = b"127.0.0.1"
        swp_message = SWP.pack(
            msg_type=MessageType.MSG_CONNECT.value,
            target=target,
            payload=msg
        )

        expect_val = b"SWP" + b"\x01" + b"\x09" + b"\x00\x07" + b"127.0.0.1" + b"message"
        assert swp_message[:3] == expect_val[:3]
        assert swp_message[3:] != expect_val[3:]
    
    def test_unpack_with_auto_encrypt(self):
        SWP.load_aesgcm(b"a" * 32)
        msg = b"message"
        target = b"127.0.0.1"
        swp_message = SWP.pack(
            msg_type=MessageType.MSG_CONNECT.value,
            target=target,
            payload=msg
        )

        decode_data = SWP.unpack(swp_message)
        assert decode_data["msg_type"] == 0x01
        assert decode_data["target"] == b"127.0.0.1"
        assert decode_data["payload"] == b"message"
