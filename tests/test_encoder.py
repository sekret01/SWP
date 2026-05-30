from swp_protocol._encoder import AesGcmCrypto, AesGcmKeyError
import pytest


class TestAesGcmKeyError:

    def get_test_aesgcm_key(self) -> bytes:
        return ("abcd" * 8).encode()

    def test_encode(self):
        crypto = AesGcmCrypto(key=self.get_test_aesgcm_key())
        msg = b"test message"
        res = crypto.encode(msg)
        assert res != msg

    def test_decode(self):
        crypto = AesGcmCrypto(key=self.get_test_aesgcm_key())
        msg = b"test message"
        res = crypto.encode(msg)
        
        after_decode = crypto.decode(res)
        assert after_decode == msg

    def test_key_len_error(self):
        with pytest.raises(AesGcmKeyError) as ex:
            _ = AesGcmCrypto(b"len_not_32")
        assert ex is not None
