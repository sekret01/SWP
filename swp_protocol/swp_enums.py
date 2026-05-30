import enum

class MessageType(enum.IntEnum):

    MSG_CONNECT = 0x01      # Начало подключения
    MSG_DATA = 0x02         # Передача данных
    MSG_CLOSE = 0x03        # Завершение подключения