use std::collections::BTreeMap;

const SYSCALLS: &'static str = include_str!("../../data/syscalls_x64.tsv");

/// Create a map of syscall numbers (for Linux x86_64) to their symbol names
pub fn load_syscalls() -> BTreeMap<u64, String> {
    let mut syscalls = BTreeMap::new();

    for line in SYSCALLS.split_terminator('\n') {
        let cols: Vec<_> = line.split('\t').collect();
        let callno: u64 = cols[0].parse().unwrap();
        let name = cols[1].to_owned();
        syscalls.insert(callno, name);
    }

    syscalls
}
