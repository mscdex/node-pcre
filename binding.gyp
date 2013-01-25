{
  'targets': [
    {
      'target_name': 'pcre',
      'sources': [ 'src/binding.cc' ],
      'dependencies': [
        'deps/libpcre/pcre.gyp:libpcre',
      ],
      'cflags!': [ '-O2' ],
      'cflags+': [ '-O3' ],
      'cflags_cc!': [ '-O2' ],
      'cflags_cc+': [ '-O3' ],
      'cflags_c!': [ '-O2' ],
      'cflags_c+': [ '-O3' ],
    },
  ]
}
