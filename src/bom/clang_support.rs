use std::ffi::OsStr;

static COMPILE_COMMANDS: &'static [&str] =
    &[r"gcc",
      r"g\+\+",
      r"cc",
      r"c\+\+",
      r"clang",
      r"clang\+\+",
      r"clang-\d+(\.\d+)",
      r"clang\+\+-\d+(\.\d+)",
      r"gcc-\d+(\.\d+)",
      r"g\+\+-\d+(\.\d+)"
    ];

lazy_static::lazy_static! {
    static ref COMPILE_COMMAND_RE : regex::RegexSet = regex::RegexSet::new(COMPILE_COMMANDS).unwrap();
}

pub fn is_compile_command_name(cmd_name : &OsStr) -> bool {
    match cmd_name.to_str() {
        None => { false }
        Some(s) => { COMPILE_COMMAND_RE.is_match(s) }
    }
}

static SINGLE_ARG_OPTIONS : &'static [&str] =
    &[r"-o",
      r"--param",
      r"-aux-info",
      r"-A",
      r"-D",
      r"-U",
      r"-arch",
      r"-MF",
      r"-MT",
      r"-MQ",
      r"-I",
      r"-idirafter",
      r"-include",
      r"-imacros",
      r"-iprefix",
      r"-iwithprefix",
      r"-iwithprefixbefore",
      r"-isystem",
      r"-isysroot",
      r"-iquote",
      r"-imultilib",
      r"-target",
      r"-x",
      r"-Xclang",
      r"-Xpreprocessor",
      r"-Xassembler",
      r"-Xlinker",
      r"-l",
      r"-L",
      r"-T",
      r"-u",
      r"-e",
      r"-rpath",
      r"-current_version",
      r"-compatibility_version"
    ];

lazy_static::lazy_static! {
    static ref SINGLE_ARG_OPTION_RE : regex::RegexSet = regex::RegexSet::new(SINGLE_ARG_OPTIONS).unwrap();
}

pub fn is_unary_option(arg : &OsStr) -> bool {
    match arg.to_str() {
        None => { false }
        Some(arg_str) => {
            SINGLE_ARG_OPTION_RE.is_match(arg_str)
        }
    }
}

lazy_static::lazy_static! {
    static ref OTHER_ARG_PREFIX_RE : regex::Regex = regex::Regex::new(r"-.*").unwrap();
}

pub fn is_nullary_option(arg : &OsStr) -> bool {
    match arg.to_str() {
        None => { false }
        Some(arg_str) => {
            OTHER_ARG_PREFIX_RE.is_match(arg_str)
        }
    }
}

static CLANG_ARGUMENT_BLACKLIST : &'static [&str] =
    &[r"-fno-tree-loop-im",
      r"-Wmaybe-uninitialized",
      r"-Wno-maybe-uninitialized",
      r"-mindirect-branch-register",
      r"-mindirect-branch=.*",
      r"-mpreferred-stack-boundary=\d+",
      r"-Wframe-address",
      r"-Wno-frame-address",
      r"-Wno-format-truncation",
      r"-Wno-format-overflow",
      r"-Wformat-overflow",
      r"-Wformat-truncation",
      r"-Wpacked-not-aligned",
      r"-Wno-packed-not-aligned",
      r"-Werror=.*",
      r"-Wno-restrict",
      r"-Wrestrict",
      r"-Wno-unused-but-set-variable",
      r"-Wunused-but-set-variable",
      r"-Wno-stringop-truncation",
      r"-Wno-stringop-overflow",
      r"-Wstringop-truncation",
      r"-Wstringop-overflow",
      r"-Wzero-length-bounds",
      r"-Wno-zero-length-bounds",
      r"-fno-allow-store-data-races",
      r"-fno-var-tracking-assignments",
      r"-fmerge-constants",
      r"-fconserve-stack",
      r"-falign-jumps=\d+",
      r"-falign-loops=\d+",
      r"-mno-fp-ret-in-387",
      r"-mskip-rax-setup",
      r"--param=.*"
      ];

lazy_static::lazy_static! {
    // regex of original build arguments to completely remove when
    // generating bitcode via clang
    static ref CLANG_ARGUMENT_BLACKLIST_RE : regex::RegexSet = regex::RegexSet::new(CLANG_ARGUMENT_BLACKLIST).unwrap();

    // regex of original build arguments that may be removed when
    // generating bitcode via clang unless --flags-unchanged is
    // specified on the command line.
    static ref CLANG_PRESERVE_FLAGS_RE : regex::Regex = regex::Regex::new(r"^-O\d*$").unwrap();
}

/// Returns true if the argument is not accepted by clang and should be ignored
/// when constructing clang invocations.
pub fn is_blacklisted_clang_argument(a : &OsStr,
                                     keep_original_flags : &bool) -> bool {
    match a.to_str() {
        None => { false }
        Some(str_arg) => {
            CLANG_ARGUMENT_BLACKLIST_RE.is_match(str_arg) ||
                (!*keep_original_flags &&
                 CLANG_PRESERVE_FLAGS_RE.is_match(str_arg))
        }
    }
}
