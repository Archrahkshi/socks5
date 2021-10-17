# socks5

Реализация асинхронного параллельного SOCKS5-прокси-сервера на языке C++ при помощи библиотеки Boost.

Сборка и запуск:
```
mkdir debug && cd debug
cmake ..
make
./server <port> <number of threads>
```
