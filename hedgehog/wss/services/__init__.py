"""Сервисы, вынесенные из HedgehogServer (wss/server.py).

Каждый сервис получает хост (сервер) в конструкторе и вызывает его методы как
``self.host._x(...)`` в момент вызова; сервисы НЕ импортируют wss.server.
Контракт хоста — typing.Protocol в services/base.py.
"""
