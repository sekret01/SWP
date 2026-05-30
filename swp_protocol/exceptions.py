
class ProtocolError(Exception):
    """ Базовый класс ошибок протокола """
    def __init__(self, message: str):
        super().__init__(message)


class AesGcmKeyError(ProtocolError):
    """ Ошибка ключа шифрования """
    pass


class HeaderNotCompliteError(ProtocolError):
    """ Ошибка заголовка протокола """
    def __init__(self):
        super().__init__(f"Недостаточно данных для заголовка")
