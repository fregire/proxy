# Proxy Server
Версия 1.0
Автор: Gilmutdinov Daniil (fregire@yandex.ru)

## Описание
Прокси сервер 

## Состав
- Главный файл - `proxy_server.py`
- Модули: `modules/`
- Тесты: `tests/`

## Требования
- Python не ниже версии 3.7
- Наличие модуля pyOpenSSL

## Запуск/Управление
- Справка к запуску: `python proxy_server.py --h`
- Пример запуска прокси сервера с портом 143: `python proxy_server -p 143`

## Особенности реализации
Перед запуском сервера необходимо добавить корневой сертификат rootCA.crt в
качестве корневого доверенного центра сертификации в бразуере или операционной системе, файл rootCA.key 
должен лежать в корне проекта. 

После запуска в консоли показывается ip и порт сервера (в формате - ip:port, 
которые необходимо ввести в параметры прокси сервера в ОС/браузере 
(Например, в Windows - "Прокси-сервер")

Если при запуске сервера порт был не указан, выдается любой свободный порт,
который предоставляет операционная система (Посмотреть его можно опять же
в консоли при запуске или с помощью метода `get_addr` класса `ProxyServer`)





