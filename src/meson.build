sources = ['main.cpp', 'hash.cpp', 'utility.cpp', 'ws.cpp', 'epoll.cpp']

threads = dependency('threads')
cryptopp = dependency('libcrypto++')

cpp = meson.get_compiler('cpp')
librt = cpp.find_library('rt')

compiler_args = []
if not get_option('buildtype').startswith('release')
  compiler_args += '-DDEBUG'
endif

executable('wss', sources, dependencies: [threads, cryptopp, librt],
cpp_args: compiler_args)
