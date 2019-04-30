wss
===

A simple WebSocket server that runs on Linux. This project is far from usable.
Massive refactoring is on the way.

Building
--------

Meson build system is used. Install Meson (and python as dependency) first.

Dependencies:

 - CryptoPP 7.0

 - Linux kernel 4.5 or newer

.. code:: sh

    meson build
    cd build
    ninja
    # output is in <project>/build/src/wss

Running
-------

.. code:: sh

    ./build/src/wss <port>
