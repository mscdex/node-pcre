var PCRE = require('../build/Release/pcre');

/* Public options. Some are compile-time only, some are run-time only, and some
are both, so we keep them all distinct. However, almost all the bits in the
options word are now used. In the long run, we may have to re-use some of the
compile-time only bits for runtime options, or vice versa. Any of the
compile-time options may be inspected during studying (and therefore JIT
compiling).

Some options for pcre_compile() change its behaviour but do not affect the
behaviour of the execution functions. Other options are passed through to the
execution functions and affect their behaviour, with or without affecting the
behaviour of pcre_compile().

Options that can be passed to pcre_compile() are tagged Cx below, with these
variants:

C1     Affects compile only
C2     Does not affect compile; affects exec
C3     Affects compile, exec
C4,C5  Affects compile, exec, study

Options that can be set for pcre_exec() are flagged with E.
They take precedence over C3, C4, and C5 settings passed from pcre_compile().
Those that are compatible with JIT execution are flagged with J. */

PCRE.PCRE.PCRE_CASELESS =          0x00000001;  /* C1       */
PCRE.PCRE.PCRE_MULTILINE =         0x00000002;  /* C1       */
PCRE.PCRE.PCRE_DOTALL =            0x00000004;  /* C1       */
PCRE.PCRE.PCRE_EXTENDED =          0x00000008;  /* C1       */
PCRE.PCRE.PCRE_ANCHORED =          0x00000010;  /* C4 E     */
PCRE.PCRE.PCRE_DOLLAR_ENDONLY =    0x00000020;  /* C2       */
PCRE.PCRE.PCRE_EXTRA =             0x00000040;  /* C1       */
PCRE.PCRE.PCRE_NOTBOL =            0x00000080;  /*    E   J */
PCRE.PCRE.PCRE_NOTEOL =            0x00000100;  /*    E   J */
PCRE.PCRE.PCRE_UNGREEDY =          0x00000200;  /* C1       */
PCRE.PCRE.PCRE_NOTEMPTY =          0x00000400;  /*    E   J */
PCRE.PCRE.PCRE_UTF8 =              0x00000800;  /* C4       */
PCRE.PCRE.PCRE_NO_AUTO_CAPTURE =   0x00001000;  /* C1       */
PCRE.PCRE.PCRE_NO_UTF8_CHECK =     0x00002000;  /* C1 E   J */
PCRE.PCRE.PCRE_AUTO_CALLOUT =      0x00004000;  /* C1       */
PCRE.PCRE.PCRE_PARTIAL_SOFT =      0x00008000;  /*    E   J  ) Synonyms */
PCRE.PCRE.PCRE_PARTIAL =           0x00008000;  /*    E   J  )          */
PCRE.PCRE.PCRE_FIRSTLINE =         0x00040000;  /* C3       */
PCRE.PCRE.PCRE_DUPNAMES =          0x00080000;  /* C1       */
PCRE.PCRE.PCRE_NEWLINE_CR =        0x00100000;  /* C3 E     */
PCRE.PCRE.PCRE_NEWLINE_LF =        0x00200000;  /* C3 E     */
PCRE.PCRE.PCRE_NEWLINE_CRLF =      0x00300000;  /* C3 E     */
PCRE.PCRE.PCRE_NEWLINE_ANY =       0x00400000;  /* C3 E     */
PCRE.PCRE.PCRE_NEWLINE_ANYCRLF =   0x00500000;  /* C3 E     */
PCRE.PCRE.PCRE_BSR_ANYCRLF =       0x00800000;  /* C3 E     */
PCRE.PCRE.PCRE_BSR_UNICODE =       0x01000000;  /* C3 E     */
PCRE.PCRE.PCRE_JAVASCRIPT_COMPAT = 0x02000000;  /* C5       */
PCRE.PCRE.PCRE_NO_START_OPTIMIZE = 0x04000000;  /* C2 E      ) Synonyms */
PCRE.PCRE.PCRE_NO_START_OPTIMISE = 0x04000000;  /* C2 E      )          */
PCRE.PCRE.PCRE_PARTIAL_HARD =      0x08000000;  /*    E   J */
PCRE.PCRE.PCRE_NOTEMPTY_ATSTART =  0x10000000;  /*    E   J */
PCRE.PCRE.PCRE_UCP =               0x20000000;  /* C3       */

// PCRE study() options

PCRE.PCRE.PCRE_STUDY_JIT_COMPILE =               0x0001;
PCRE.PCRE.PCRE_STUDY_JIT_PARTIAL_SOFT_COMPILE =  0x0002;
PCRE.PCRE.PCRE_STUDY_JIT_PARTIAL_HARD_COMPILE =  0x0004;
PCRE.PCRE.PCRE_STUDY_EXTRA_NEEDED =              0x0008;

// PCRE errors

PCRE.PCRE.PCRE_ERROR_NOMATCH =          (-1);
PCRE.PCRE.PCRE_ERROR_NULL =             (-2);
PCRE.PCRE.PCRE_ERROR_BADOPTION =        (-3);
PCRE.PCRE.PCRE_ERROR_BADMAGIC =         (-4);
PCRE.PCRE.PCRE_ERROR_UNKNOWN_OPCODE =   (-5);
PCRE.PCRE.PCRE_ERROR_UNKNOWN_NODE =     (-5); /* For backward compatibility */
PCRE.PCRE.PCRE_ERROR_NOMEMORY =         (-6);
PCRE.PCRE.PCRE_ERROR_NOSUBSTRING =      (-7);
PCRE.PCRE.PCRE_ERROR_MATCHLIMIT =       (-8);
PCRE.PCRE.PCRE_ERROR_CALLOUT =          (-9);  /* Never used by PCRE itself */
PCRE.PCRE.PCRE_ERROR_BADUTF8 =         (-10);
PCRE.PCRE.PCRE_ERROR_BADUTF8_OFFSET =  (-11);
PCRE.PCRE.PCRE_ERROR_PARTIAL =         (-12);
PCRE.PCRE.PCRE_ERROR_BADPARTIAL =      (-13);
PCRE.PCRE.PCRE_ERROR_INTERNAL =        (-14);
PCRE.PCRE.PCRE_ERROR_BADCOUNT =        (-15);
PCRE.PCRE.PCRE_ERROR_DFA_UITEM =       (-16);
PCRE.PCRE.PCRE_ERROR_DFA_UCOND =       (-17);
PCRE.PCRE.PCRE_ERROR_DFA_UMLIMIT =     (-18);
PCRE.PCRE.PCRE_ERROR_DFA_WSSIZE =      (-19);
PCRE.PCRE.PCRE_ERROR_DFA_RECURSE =     (-20);
PCRE.PCRE.PCRE_ERROR_RECURSIONLIMIT =  (-21);
PCRE.PCRE.PCRE_ERROR_NULLWSLIMIT =     (-22);  /* No longer actually used */
PCRE.PCRE.PCRE_ERROR_BADNEWLINE =      (-23);
PCRE.PCRE.PCRE_ERROR_BADOFFSET =       (-24);
PCRE.PCRE.PCRE_ERROR_SHORTUTF8 =       (-25);
PCRE.PCRE.PCRE_ERROR_RECURSELOOP =     (-26);
PCRE.PCRE.PCRE_ERROR_JIT_STACKLIMIT =  (-27);
PCRE.PCRE.PCRE_ERROR_BADMODE =         (-28);
PCRE.PCRE.PCRE_ERROR_BADENDIANNESS =   (-29);
PCRE.PCRE.PCRE_ERROR_DFA_BADRESTART =  (-30);
PCRE.PCRE.PCRE_ERROR_JIT_BADOPTION =   (-31);
PCRE.PCRE.PCRE_ERROR_BADLENGTH =       (-32);

// Specific PCRE error codes for UTF-8 validity checks

PCRE.PCRE.PCRE_UTF8_ERR0 =              0;
PCRE.PCRE.PCRE_UTF8_ERR1 =              1;
PCRE.PCRE.PCRE_UTF8_ERR2 =              2;
PCRE.PCRE.PCRE_UTF8_ERR3 =              3;
PCRE.PCRE.PCRE_UTF8_ERR4 =              4;
PCRE.PCRE.PCRE_UTF8_ERR5 =              5;
PCRE.PCRE.PCRE_UTF8_ERR6 =              6;
PCRE.PCRE.PCRE_UTF8_ERR7 =              7;
PCRE.PCRE.PCRE_UTF8_ERR8 =              8;
PCRE.PCRE.PCRE_UTF8_ERR9 =              9;
PCRE.PCRE.PCRE_UTF8_ERR10 =            10;
PCRE.PCRE.PCRE_UTF8_ERR11 =            11;
PCRE.PCRE.PCRE_UTF8_ERR12 =            12;
PCRE.PCRE.PCRE_UTF8_ERR13 =            13;
PCRE.PCRE.PCRE_UTF8_ERR14 =            14;
PCRE.PCRE.PCRE_UTF8_ERR15 =            15;
PCRE.PCRE.PCRE_UTF8_ERR16 =            16;
PCRE.PCRE.PCRE_UTF8_ERR17 =            17;
PCRE.PCRE.PCRE_UTF8_ERR18 =            18;
PCRE.PCRE.PCRE_UTF8_ERR19 =            19;
PCRE.PCRE.PCRE_UTF8_ERR20 =            20;
PCRE.PCRE.PCRE_UTF8_ERR21 =            21;
PCRE.PCRE.PCRE_UTF8_ERR22 =            22;

module.exports = PCRE;