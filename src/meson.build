sources = ['main.cpp', 'hash.cpp', 'utility.cpp', 'ws.cpp', 'epoll.cpp']
threads = dependency('threads')
cryptopp = dependency('libcrypto++')

cpp = meson.get_compiler('cpp')
librt = cpp.find_library('rt')

executable('wss', sources, dependencies: [threads, cryptopp, librt])
