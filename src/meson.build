sources = ['main.cpp', 'hash.cpp', 'utility.cpp', 'ws.cpp']
threads = dependency('threads')
cryptopp = dependency('libcrypto++')

executable('wss', sources, dependencies: [threads, cryptopp])
