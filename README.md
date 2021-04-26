# Proxy Server
Версия 1.0
Автор: Gilmutdinov Daniil (fregire@yandex.ru)

## Описание
Прокси сервер 

## Состав
- Главный файл - `server.py`
- Модули: `modules/`

## Требования
- Python не ниже версии 3.7
- Linux

## Запуск/Управление
- Справка к запуску: `python server.py --h`
- Пример запуска прокси сервера с портом 143: `python server.py -p 143`

## Особенности реализации
После запуска в консоли показывается ip и порт сервера (в формате - ip:port, 
которые необходимо ввести в параметры прокси сервера в ОС/браузере)

Если при запуске сервера порт был не указан, выдается любой свободный порт,
который предоставляет операционная система (Посмотреть его можно опять же
в консоли при запуске или с помощью метода `get_addr` класса `ProxyServer`)






