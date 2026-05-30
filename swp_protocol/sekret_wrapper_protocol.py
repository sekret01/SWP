import struct

from swp_protocol.exceptions import AesGcmKeyError, HeaderNotCompliteError
from swp_protocol._encoder import AesGcmCrypto


class SWP:
    """
    Sekret Wrapper Protocol

    Протокол, оборачиваемый поверх нужного протокола
    Вид протокола:
    [sid][msg_type][target_len][payload_len][target][payload]
    """

    PROTOCOL_MAGIC = b"\x53\x57\x50"
    HEADER_FMT = "!3sBBH"
    HEADER_SIZE = struct.calcsize(HEADER_FMT)

    MSG_CONNECT = 0x01      # Начало подключения
    MSG_DATA = 0x02         # Передача данных
    MSG_CLOSE = 0x03        # Завершение подключения

    AESGCM: bytes = b""
    AUTO_ENCRYPT: bool = False

    def __init__(self, buffer: bytes = None):
        if len(buffer) < SWP.HEADER_SIZE:
            return

        header = struct.unpack(SWP.HEADER_FMT, buffer[:SWP.HEADER_SIZE])

        self.msg_type = header[2]                   # BYTE  - тип запроса
        target_len = header[3]                      # BYTE  - длина адреса в payload
        payload_len = header[4]                     # SHORT - длина target

        offset = SWP.HEADER_SIZE
        self.target = buffer[offset:offset + target_len]
        self.payload = buffer[offset + target_len : offset + target_len + payload_len]
    
    @classmethod
    def reset(cls):
        """ Сброс параметров """
        cls.AESGCM = b""
        cls.AUTO_ENCRYPT = False

    @classmethod
    def set_auto_encrypt(cls, value: bool) -> None:
        """ Установка автоматического шифрования тела """
        if (SWP.AESGCM == b""):
            raise AesGcmKeyError("Отсутствует AESGCM ключ для шифрования. Выполните команду SWP.load_aesgcm")
        SWP.AUTO_ENCRYPT = value

    @classmethod
    def pack(cls,
             msg_type: int,
             target: bytes,
             payload: bytes = b""
             ) -> bytes:
        """ Создание пакета из данных """
        if (cls.AUTO_ENCRYPT):
            payload = cls.encode(message=payload)

        target_len = len(target)
        payload_len = len(payload)

        header = struct.pack(
            cls.HEADER_FMT,
            cls.PROTOCOL_MAGIC,
            msg_type,
            target_len,
            payload_len
        )
        return header + target + payload

    @classmethod
    def unpack_header(cls, buffer: bytes) -> tuple[bytes, int, int, int]:
        """ Извлечь данные заголовка из пакета """
        if len(buffer) < SWP.HEADER_SIZE:
            raise HeaderNotCompliteError()
        return struct.unpack(SWP.HEADER_FMT, buffer[:SWP.HEADER_SIZE])

    @classmethod
    def unpack(cls, buffer: bytes) -> dict:
        """ Извлечь данные из пакета """
        _, msg_type, target_len, payload_len = SWP.unpack_header(buffer)
        offset = cls.HEADER_SIZE
        target = buffer[offset:offset + target_len]
        offset += target_len
        payload = buffer[offset:offset + payload_len]

        if cls.AUTO_ENCRYPT:
            payload = cls.decode(message=payload)

        return {
            "msg_type": msg_type,
            "target": target,
            "payload": payload
        }

    @classmethod
    def get_full_package_size(cls, buffer: bytes) -> int:
        """ Определение полного размера пакета """
        if len(buffer) < SWP.HEADER_SIZE:
            return -1
        _, _, target_size, payload_size = cls.unpack_header(buffer)
        return cls.HEADER_SIZE + target_size + payload_size
    
    @classmethod
    def load_aesgcm(cls, key: bytes) -> None:
        """ Загрузка AESGCM ключа для автоматического шифрования тела пакетов """
        if len(key) != 32:
            raise AesGcmKeyError(f"Длина ключа AESGCM должна быть равна 32, текущая длина: {len(key)}")
        cls.AESGCM = key
        cls.AUTO_ENCRYPT = True

    @classmethod
    def encode(cls, message: str | bytes) -> bytes:
        """ Шифрование сообщения """
        crypto = AesGcmCrypto(cls.AESGCM)
        if isinstance(message, str):
            message = message.encode()
        return crypto.encode(payload=message)

    @classmethod
    def decode(cls, message: bytes) -> bytes:
        """ Расшифровка сообщения """
        crypto = AesGcmCrypto(cls.AESGCM)
        return crypto.decode(encrypted_payload=message)
    