import struct

from swp_protocol.exceptions import AesGcmKeyError, HeaderNotCompliteError
from swp_protocol._encoder import AesGcmCrypto
from swp_enums import MessageType


class SWP:
    """
    Sekret Wrapper Protocol

    Протокол, оборачиваемый поверх нужного протокола  
    Вид протокола:  
    [magic][msg_type][target_len][payload_len][target][payload]  

    - magic - 3b, служат для определения протокола;
    - msg_type - 1b, имеет варианты "подключение", "передача данных", "отключение";
    - target_len - 1b, длина значения домена-назначения;
    - payload_len - 2b, длина исходного пакета;
    - target - ``target_len`` b, домен или ip:port;
    - payload - пакет, который необходимо обернуть (при AUTO_ENCRYPT=True шифруется только эти данные);
    """

    PROTOCOL_MAGIC = b"\x53\x57\x50"
    HEADER_FMT = "!3sBBH"
    HEADER_SIZE = struct.calcsize(HEADER_FMT)

    AESGCM: bytes = b""
    AUTO_ENCRYPT: bool = False
    
    
    @classmethod
    def reset(cls):
        """ Сброс параметров шифрования """
        cls.AESGCM = b""
        cls.AUTO_ENCRYPT = False

    @classmethod
    def set_auto_encrypt(cls, value: bool) -> None:
        """
        Включение и отключение автоматического шифрования payload

        :param value:
            ``True`` - включение автоматического шифрования и расшифровки
            ``False`` - отключение шифрования и расшифровки
        
        Если вызвать ``SWP.set_auto_encrypt(True)`` без предварительного
        ``SWP.load_aesgcm()``, будет выброшена ошибка AesGcmKeyError
        """
        if (SWP.AESGCM == b""):
            raise AesGcmKeyError("Отсутствует AESGCM ключ для шифрования. Выполните команду SWP.load_aesgcm")
        SWP.AUTO_ENCRYPT = value

    @classmethod
    def pack(cls,
             msg_type: int,
             target: bytes,
             payload: bytes = b""
             ) -> bytes:
        """
        Создание пакета из данных

        :param msg_type:
            Параметр обозначает вид сообщения. Используется для работы в узлах прокси.
            Может иметь значения:
                ``0x01`` - запрос на подключение;
                ``0x02`` - передача данных;
                `0x03`` - завершение подключения.
            Все типы сообщений есть в модуле swp_protocol.swp_enums.MessageType
        
        :param target:
            Домен или хост, к которому идет подключение в исходном пакете.
            Принимает как вариант b"https://example.com", так и b"127.0.0.1:9999"
        
        :param payload:
            Целый сходный пакет в виде байтов
            
        :return:
            Строка байтов, которую может принять другой узел, работающий с SWP протоколом
        """
        if (cls.AUTO_ENCRYPT):
            payload = cls._encode(message=payload)

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
        """
        Извлечь данные заголовка из пакета
        
        :param buffer:
            Байтовая строка, обернутая в протокол SWP

        :return:
            Кортеж значений ``PROTOCOL_MAGIC``, ``msg_type``, ``target_len``, ``payload_len``
        
        Если заголовок не собран, бросает исключение ``HeaderNotCompliteError``
        """
        if len(buffer) < SWP.HEADER_SIZE:
            raise HeaderNotCompliteError()
        return struct.unpack(SWP.HEADER_FMT, buffer[:SWP.HEADER_SIZE])

    @classmethod
    def unpack(cls, buffer: bytes) -> dict:
        """
        Извлечь данные из пакета
        
        :param buffer:
            Байтовая строка, обернутая в протокол SWP
        
        :return:
            Словарь с ключами
                - msg_type - `int``, тип сообщения
                - target - ``bytes``, хост назначения
                - payload - исходный пакет (исходные данные)
        """
        _, msg_type, target_len, payload_len = SWP.unpack_header(buffer)
        offset = cls.HEADER_SIZE
        target = buffer[offset:offset + target_len]
        offset += target_len
        payload = buffer[offset:offset + payload_len]

        if cls.AUTO_ENCRYPT:
            payload = cls._decode(message=payload)

        return {
            "msg_type": msg_type,
            "target": target,
            "payload": payload
        }
    
    @classmethod
    def create_connect_package(cls, target_address: bytes = b"") -> bytes:
        """ Создание пакета для подключения к узлу """
        return cls.pack(
            msg_type=MessageType.MSG_CONNECT, 
            target=target_address, 
            payload=b""
            )

    @classmethod
    def create_data_package(cls, data: bytes, target_address: bytes = b"") -> bytes:
        """ Создание пакета для передачи данных между узлами """
        return cls.pack(
            msg_type=MessageType.MSG_DATA, 
            target=target_address, 
            payload=data
        )
    
    @classmethod
    def create_close_package(cls):
        """ Создание пакета для отключения от узла """
        return cls.pack(
            msg_type=MessageType.MSG_CLOSE, 
            target=b"", 
            payload=b""
            )

    @classmethod
    def get_full_package_size(cls, buffer: bytes) -> int:
        """ Определение полного размера пакета """
        if len(buffer) < SWP.HEADER_SIZE:
            return -1
        _, _, target_size, payload_size = cls.unpack_header(buffer)
        return cls.HEADER_SIZE + target_size + payload_size
    
    @classmethod
    def load_aesgcm(cls, key: bytes) -> None:
        """
        Загрузка AESGCM ключа для автоматического шифрования тела пакетов
        
        :param key:
            AESGCM ключ из 32 символов. Если len(key) != 32, будет выброшено 
            искоючерние AesGcmKeyError
        """
        if len(key) != 32:
            raise AesGcmKeyError(f"Длина ключа AESGCM должна быть равна 32, текущая длина: {len(key)}")
        cls.AESGCM = key
        cls.AUTO_ENCRYPT = True

    @classmethod
    def _encode(cls, message: str | bytes) -> bytes:
        """ Шифрование сообщения """
        crypto = AesGcmCrypto(cls.AESGCM)
        if isinstance(message, str):
            message = message.encode()
        return crypto.encode(payload=message)

    @classmethod
    def _decode(cls, message: bytes) -> bytes:
        """ Расшифровка сообщения """
        crypto = AesGcmCrypto(cls.AESGCM)
        return crypto.decode(encrypted_payload=message)
    