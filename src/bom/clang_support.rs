use std::ffi::OsStr;

/// Regular expressions for the programs that are recognized as C/C++ compilers
/// that we can interpose on and substitute a clang call to generate bitcode.
/// Note that these are not start-anchored since there may be many variants
/// (e.g. "arm-gcc", "/usr/bin/gcc").
static COMPILE_COMMANDS: &'static [&str] =
    &[r"gcc$",
      r"g\+\+$",
      r"cc$",
      r"c\+\+$",
      r"clang$",
      r"clang\+\+$",
      r"clang-\d+(\.\d+)$",
      r"clang\+\+-\d+(\.\d+)$",
      r"gcc-\d+(\.\d+)$",
      r"g\+\+-\d+(\.\d+)$"
    ];

lazy_static::lazy_static! {
    static ref COMPILE_COMMAND_RE : regex::RegexSet = regex::RegexSet::new(COMPILE_COMMANDS).unwrap();
}

/// Return true if the given command matches one of our regular expressions for
/// known C/C++ compiler commands
pub fn is_compile_command_name(cmd_name : &OsStr) -> bool {
    match cmd_name.to_str() {
        None => { false }
        Some(s) => { COMPILE_COMMAND_RE.is_match(s) }
    }
}

// Regex for determining if the next command-line argument is a value associated
// with the current argument (i.e. a unary argument whose value is not part of
// the current argument).
//
// Unary option arguments may be single-letter or multi-letter option, and
// multi-letter options may begin with one or two dashes (always
// option-specific).  The value for a unary option may be:
//
//   (a) the next command-line argument
//
//   (b) immediately after the option in the current argument (if it is a
//       single-letter option)
//
//   (c) following an = sign for *some* single-dash multi-letter options
//
//   (d) following an = sign for two-dash multi-letter options
//
// Notably *not* supported for gcc/clang/compilers (but which sometimes appear
// for getopts or other utilities):
//
//   * combining single letter options (e.g. "-i -j" cannot be "-ij")
//
//   * single-letter options with no dashes (e.g. "tar jcv", "ar u")
//
// There are two principle uses for this value identification:
//
//  (1) skipping values for blacklisted arguments (builtlins or cmdline)
//
//  (2) skipping arguments (and their values) when trying to identify files
//      specified on the command line.
//
// Thus, the code here is solely attempting to identify if the next command-line
// word should be skipped, rather than trying to identify a "unary argument".
// For both usages, the *current* command-line word has been identified by virtue
// of it starting with a dash character (irrespective of whether it actually has
// one or two dashes), so the only other information needed is whether to skip
// the next command-line argument.
//
// Note that the compilers do not utilize N-ary arguments for N > 1.
//
// Also note that it is not necessary here to be concerned with values containing
// spaces or other whitespace, as that will have been handled by the shell's
// command-line parsing:
//    $ gcc -o "foo bar"        --> [ "gcc", "-o", "foo bar" ]
//    $ gcc --target="foo bar"  --> [ "gcc", "--target="foo bar"" ]
//    $ gcc "-ofoo bar"         --> [ "gcc", "-ofoo bar" ]
//
// There are a plethora of -f and -W options, some of which take values.  It
// appears that all those which take values must always take the value as a
// =VALUE at the end of the same option, rather than allowing the value to be
// whitespace separated (i.e. the following argument).
//
// tl;dr This table only identifies arguments for which the following argument is
// a value.  It does *not* need to match the form of arguments that specify both
// the option and the value in the single argument.

static FOLLOWING_ARG_OPTIONS : &'static [&str] =
    &[r"^-o$",
      r"^--param$",
      r"^-aux-info$",
      r"^-auxbase-strip$",
      r"^-A$",
      r"^-D$",
      r"^-U$",
      r"^-arch$",
      r"^-MF$",
      r"^-MT$",
      r"^-MQ$",
      r"^-I$",
      r"^-idirafter$",
      r"^-include$",
      r"^-imacros$",
      r"^-iprefix$",
      r"^-iwithprefix$",
      r"^-iwithprefixbefore$",
      r"^-isystem$",
      r"^-isysroot$",
      r"^-iquote$",
      r"^-imultilib$",
      r"^-iplugindir$",
      r"^--sysroot$",
      r"^--target$",
      r"^-x$",
      r"^-Xclang$",
      r"^-Xpreprocessor$",
      r"^-Xassembler$",
      r"^-Xlinker$",
      r"^-l$",
      r"^-L$",
      r"^-B$",
      r"^-T$",
      r"^-u$",
      r"^-z$",
      r"^-e$",
      r"^--entry$",
      r"^-rpath$",   // unique to clang
      r"^-current_version$",
      r"^-compatibility_version$",
      r"^-dumpbase$"
    ];

lazy_static::lazy_static! {
    static ref FOLLOWING_ARG_OPTION_RE : regex::RegexSet = regex::RegexSet::new(FOLLOWING_ARG_OPTIONS).unwrap();
}

/// Return true if the argument is a gcc/clang option that takes a single argument
pub fn next_arg_is_option_value(arg : &OsStr) -> bool {
    match arg.to_str() {
        None => { false }
        Some(arg_str) => {
            FOLLOWING_ARG_OPTION_RE.is_match(arg_str)
        }
    }
}


/// Return true if the argument is a gcc/clang option.  This is primarily used to
/// determine if this argument should be skipped when searching for filenames on
/// the compilation command line.
pub fn is_option_arg(arg : &OsStr) -> bool {
    arg.to_str().map( |s| s.chars().nth(0) ).flatten() == Some('-')
}


static CLANG_ARGUMENT_BLACKLIST : &'static [&str] =
    &[r"^-fno-tree-loop-im$",

      // Most warnings are disabled because this is a background compilation
      // operation.  The primary compilation already emitted code warnings (if
      // directed to), so these would either be a duplicate or be caused by clang
      // differences or other argument changes made for the clang -emit-llvm
      // background operation.
      r"^-Wmaybe-uninitialized$",
      r"^-Wno-maybe-uninitialized$",
      r"^-Wframe-address$",
      r"^-Wno-frame-address$",
      r"^-Wno-format-truncation$",
      r"^-Wno-format-overflow$",
      r"^-Wformat-overflow$",
      r"^-Wformat-truncation$",
      r"^-Wpacked-not-aligned$",
      r"^-Wno-packed-not-aligned$",
      r"^-Wno-restrict$",
      r"^-Wrestrict$",
      r"^-Wno-unused-but-set-variable$",
      r"^-Wunused-but-set-variable$",
      r"^-Wno-stringop-truncation$",
      r"^-Wno-stringop-overflow$",
      r"^-Wstringop-truncation$",
      r"^-Wstringop-overflow$",
      r"^-Wzero-length-bounds$",
      r"^-Wno-zero-length-bounds$",
      r"^-Wunsafe-loop-optimizations$",

      // -Werror is removed because, in addition to the above note about
      // warnings, bitcode generation disables optimization, which frequently
      // causes the following libc error:
      //
      //      warning _FORTIFY_SOURCE requires compiling with optimization (-O)
      r"^-Werror($|=)",

      // The following are GCC-only and unknown to CLANG
      r"^-fno-allow-store-data-races$",
      r"^-fno-var-tracking-assignments$",
      r"^-fmerge-constants$",
      r"^-fconserve-stack$",
      r"^-falign-jumps=\d+$",
      r"^-falign-loops=\d+$",
      r"^-fsingle-precision-constant$",
      r"^--param=",
      r"^-quiet$",
      r"^-auxbase-strip$", // https://gcc.gnu.org/legacy-ml/gcc-help/2013-08/msg00067.html

      // clang sees "-dumpbase ARG" as a "multiple output file mode"
      // and doesn't support the use of -o with it (although gcc does)
      r"^-dumpbase$",

      // Options which override output generation and will conflict with the
      // -emit-llvm option.
      r"^-fdump-rtl-",
      r"^-M{1,2}D$",
      r"^-d[MDNIU]$",

      // Options which generate ancillary files that should not be changed from
      // the primary compilation run.
      r"^-MF$",
      r"^-MT$", // not strictly output, but fails without -M or -MM

      r"^-Q$",
      ];


/// The following are also blacklisted *unless* the --strict flag was used to
/// invoke build-bom.  Removing these arguments can allow the bitcode to be
/// somewhat different than the actual compiled code.
static CLANG_ARGUMENT_STRICT_WHITELIST : &'static [&str] =
    &[
        // LLVM bitcode is reasonably generic to any machine type (this is not
        // entirely true, but sufficiently so for many types of analyses that the
        // bitcode is intended to be used for).  The advantage to removing these
        // (ofsetting the disadvantage of small divergences) is that the
        // installed LLVM don't necessarily need to support cross-compilation to
        // the same targets that the main compiler is targeting.
        //
        // The target here is to remove -march, -mcpu, and all other
        // machine-specific controls, which all start with the -m prefix, thus
        // the regexp should only match the prefix with any following text.
        r"^-m",

        // Disable *all* optimization.  This can allow the generated bitcode to
        // be more comprehensive (e.g. no inlining, no dead code removal),
        // although it is potentially less-representative of the actually
        // executed code.
        r"^-O$",
        r"^-O[0123gsz]$",
        r"^-Ofast$",
        r"^-Osize$",
    ];

lazy_static::lazy_static! {
    static ref CLANG_ARGUMENT_BLACKLIST_RE : regex::RegexSet = regex::RegexSet::new(CLANG_ARGUMENT_BLACKLIST).unwrap();
    static ref CLANG_ARGUMENT_STRICT_WHITELIST_RE : regex::RegexSet = regex::RegexSet::new(CLANG_ARGUMENT_STRICT_WHITELIST).unwrap();
}

/// Returns true if the argument is not accepted by clang and should be ignored
/// when constructing clang invocations.
pub fn is_blacklisted_clang_argument(strict_bc: bool, a : &OsStr) -> bool {
    match a.to_str() {
        None => { false }
        Some(str_arg) => {
            CLANG_ARGUMENT_BLACKLIST_RE.is_match(str_arg) ||
            (!strict_bc && CLANG_ARGUMENT_STRICT_WHITELIST_RE.is_match(str_arg))
        }
    }
}
