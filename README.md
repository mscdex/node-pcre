Description
===========

A pcre binding for [node.js](http://nodejs.org/) with UTF8 and Unicode properties support.


Requirements
============

* [node.js](http://nodejs.org/) -- v0.8.0 or newer
* Windows, Linux, or OSX
  * BSD or OpenSolaris support is possible -- just need to generate and submit a config.h for [PCRE 8.32](ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-8.32.tar.gz) with these options:
```
./configure --enable-utf8 --enable-unicode-properties --enable-static --disable-shared --enable-jit --disable-cpp --enable-pcre8 --disable-pcre16 --disable-pcre32
```


Install
=======

    npm install pcre


Examples
========

* Simple one-off regexp execution:

```javascript
var inspect = require('util').inspect;
var PCRE = require('pcre').PCRE;

console.log(inspect(PCRE.exec("(?<nodejsrules>o)", "foo", 0), false, Infinity));

// output:
// [ 1, 2, 1, 2, named: { nodejsrules: [ 1, 2 ] } ]
```

* Simple one-off regexp execution returning all matches:

```javascript
var inspect = require('util').inspect;
var PCRE = require('pcre').PCRE;

console.log(inspect(PCRE.execAll("(?<nodejsrules>o)", "foo", 0), false, Infinity));

// output:
// [ [ 1, 2, 1, 2, named: { nodejsrules: [ 1, 2 ] } ],
//   [ 2, 3, 2, 3, named: { nodejsrules: [ 2, 3 ] } ] ]
```

* Instantiate a regexp and test it:

```javascript
var PCRE = require('pcre').PCRE;

var re = new PCRE("o");
console.log(re.test("foo", 0));
console.log(re.test("bar", 0));
console.log(re.test("node.js rules", 2));

// output:
// true
// false
// false
```

* Instantiate a regexp, JIT compile it, and execute it, returning all matches:

```javascript
var inspect = require('util').inspect;
var PCRE = require('pcre').PCRE;

var re = new PCRE("o");
re.study(PCRE.PCRE_STUDY_JIT_COMPILE);
console.log(inspect(re.execAll("fooooo", 0), false, Infinity));

// output:
// [ [ 1, 2 ], [ 2, 3 ], [ 3, 4 ], [ 4, 5 ], [ 5, 6 ] ]
```


API
===

PCRE static constants
---------------------

All static constants for regexp flags/options and errors can be found in `lib/pcre.js`.


PCRE static methods
-------------------

* **exec**(< _string_ >pattern, < _mixed_ >subject, < _integer_ >offset[, < _integer_ >flags]) - _mixed_ - Compiles `pattern` and executes it on `subject` starting at `offset` in `subject`. `subject` can be a _string_ or _Buffer_. The return value is either _null_ in case of no match, an _integer_ error code in case of error, or an _array_ on success containing offsets in the `subject` for the first match. The first two offsets reference the entirety of the matched part of the `subject`. Any additional offsets reference capture groups in order from left to right. Offsets for named capture groups are additionally available on the `named` object.

* **execAll**(< _string_ >pattern, < _mixed_ >subject, < _integer_ >offset[, < _integer_ >flags]) - _mixed_ - Same as exec() except an _array_ of _array_ matches is returned on success.

* **test**(< _string_ >pattern, < _mixed_ >subject, < _integer_ >offset[, < _integer_ >flags]) - _boolean_ - Similar to exec(), but used merely to test if `pattern` matches at least once.

* **version**() - _string_ - Returns the version and date of the PCRE library used (e.g. "8.32 2012-11-30").


PCRE methods
------------

* **(constructor)**(< _string_ >pattern[, < _integer_ >flags]) - Compiles `pattern` and returns a new PCRE instance.

* **study**([< _integer_ >flags][, < _integer_ >jitStackStart=1, < _integer_ >jitStackMax=32KB]) - _boolean_ - Performs some analysis of the compiled regexp in order to optimize it. `jitStackStart` and `jitStackMax` are custom starting and maximum JIT stack sizes (in bytes) respectively for when one of the JIT flags are passed in. The return value indicates the success of the analysis.

* **set**(< _string_ >pattern[, < _integer_ >flags]) - _(void)_ - Compiles a new `pattern` and replaces the existing regexp.

* **save**() - _Buffer_ - Returns the internal state object representing the compiled regexp. Note: this does not save the result of any previous optimizations performed by study().

* **load**(< _Buffer_ >state) - _(void)_ - Loads previously saved internal state data from save().

* **exec**(< _mixed_ >subject, < _integer_ >offset[, < _integer_ >flags]) - _mixed_ - Similar to PCRE.exec().

* **execAll**(< _mixed_ >subject, < _integer_ >offset[, < _integer_ >flags]) - _mixed_ - Same as exec() except an _array_ of _array_ matches is returned on success.

* **test**(< _mixed_ >subject, < _integer_ >offset[, < _integer_ >flags]) - _boolean_ - Similar to exec(), but used merely to test if `pattern` matches at least once.
