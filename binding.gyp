{
  'targets': [
    {
      'target_name': 'pcre',
      'sources': [ 'src/binding.cc' ],
      'dependencies': [
        'deps/libpcre/pcre.gyp:libpcre',
      ],
      'conditions': [
        [ 'OS!="win"', {
          'include_dirs': [ 'config/win' ],
          'cflags+': [ '-std=c++11' ],
          'cflags_c+': [ '-std=c++11' ],
          'cflags_cc+': [ '-std=c++11' ],
        }],
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
