//! Thread Context (0x0011) assembly from the register files a backend reports.
//!
//! The backend hands over threads with raw `(name, "0x…")` register pairs; this
//! module turns them into [`ThreadContextPayload`]s following MSL 1.1 Tables
//! 19a/19b: lowercase register names, values in the file's byte order (little
//! endian) at the architecture's register width, role flags for pc/sp/fp/flags/
//! tls/lr, and the `CURRENT`/`PARTIAL` thread flags. Names are canonicalised
//! per MSL 1.1.1 Table 19g before the role lookup, so aliases are never written.

use libmsl::constants::{
    REG_ROLE_FLAGS, REG_ROLE_FP, REG_ROLE_LR, REG_ROLE_PC, REG_ROLE_SP, REG_ROLE_TLS,
    TC_FLAG_CURRENT, TC_FLAG_PARTIAL,
};
use libmsl::{ArchType, ThreadContextPayload, ThreadRegister, ThreadState};

use crate::backend::ThreadInfo;

/// Role bits of the x86 / x86_64 register names Frida reports.
const X86_ROLES: &[(&str, u16)] = &[
    ("eip", REG_ROLE_PC),
    ("rip", REG_ROLE_PC),
    ("esp", REG_ROLE_SP),
    ("rsp", REG_ROLE_SP),
    ("ebp", REG_ROLE_FP),
    ("rbp", REG_ROLE_FP),
    ("eflags", REG_ROLE_FLAGS),
    ("rflags", REG_ROLE_FLAGS),
    ("fs_base", REG_ROLE_TLS),
    ("gs_base", REG_ROLE_TLS),
];

/// Role bits of the arm / arm64 register names Frida reports.
const ARM_ROLES: &[(&str, u16)] = &[
    ("pc", REG_ROLE_PC),
    ("sp", REG_ROLE_SP),
    ("fp", REG_ROLE_FP),
    ("x29", REG_ROLE_FP),
    ("cpsr", REG_ROLE_FLAGS),
    ("pstate", REG_ROLE_FLAGS),
    ("nzcv", REG_ROLE_FLAGS),
    ("tpidr_el0", REG_ROLE_TLS),
    ("lr", REG_ROLE_LR),
    ("x30", REG_ROLE_LR),
];

/// Alias → Table 19g canonical name, per architecture. Frida reports `pc`/`sp`
/// next to `rip`/`rsp` (`eip`/`esp`) and `fp`/`lr` instead of `x29`/`x30`.
const X86_64_ALIASES: &[(&str, &str)] = &[("pc", "rip"), ("sp", "rsp")];
const X86_ALIASES: &[(&str, &str)] = &[("pc", "eip"), ("sp", "esp")];
const ARM64_ALIASES: &[(&str, &str)] = &[("fp", "x29"), ("lr", "x30")];
const ARM32_ALIASES: &[(&str, &str)] = &[("r13", "sp"), ("r14", "lr"), ("r15", "pc")];

/// CPSR T bit: set while an ARM32 thread executes Thumb code.
const CPSR_THUMB_BIT: u64 = 1 << 5;

/// Width in bytes of a general-purpose register on `arch`.
pub fn register_width(arch: ArchType) -> u8 {
    match arch {
        ArchType::X86 | ArchType::ARM32 | ArchType::MIPS32 | ArchType::RV32 | ArchType::PPC32 => 4,
        _ => 8,
    }
}

/// Table 19b role flags of the register called `name` (lowercase) on `arch`;
/// 0 when the register has no special role on that architecture.
pub fn register_role(name: &str, arch: ArchType) -> u16 {
    let tables: &[&[(&str, u16)]] = match arch {
        ArchType::X86 | ArchType::X86_64 => &[X86_ROLES],
        ArchType::ARM32 | ArchType::ARM64 => &[ARM_ROLES],
        _ => &[X86_ROLES, ARM_ROLES],
    };
    tables
        .iter()
        .flat_map(|table| table.iter())
        .find(|(candidate, _)| *candidate == name)
        .map_or(0, |(_, role)| *role)
}

/// Table 19g canonical name of the lowercase register `name` on `arch`; names
/// that are not aliases (including unlisted ones such as `nzcv`) pass through.
pub fn canonical_register_name(name: &str, arch: ArchType) -> &str {
    let aliases = match arch {
        ArchType::X86_64 => X86_64_ALIASES,
        ArchType::X86 => X86_ALIASES,
        ArchType::ARM64 => ARM64_ALIASES,
        ArchType::ARM32 => ARM32_ALIASES,
        _ => &[],
    };
    aliases
        .iter()
        .find(|(alias, _)| *alias == name)
        .map_or(name, |(_, canonical)| canonical)
}

/// Table 19g ARM32 frame pointer: `r7` in Thumb mode (CPSR T bit set), `r11`
/// in ARM mode or when no `cpsr` was reported.
pub fn arm32_frame_pointer(cpsr: Option<u64>) -> &'static str {
    match cpsr {
        Some(value) if value & CPSR_THUMB_BIT != 0 => "r7",
        _ => "r11",
    }
}

/// Encode `value` as `width` little-endian bytes (the file's byte order).
pub fn encode_register_value(value: u64, width: u8) -> Vec<u8> {
    value.to_le_bytes()[..usize::from(width)].to_vec()
}

/// Build one Thread Context per thread that reports both a pc and an sp.
///
/// The thread whose id equals `pid` is flagged `CURRENT`; when none does, the
/// first usable thread is. Threads are read live, so `SUSPENDED` is never set.
pub fn build_thread_contexts(
    threads: &[ThreadInfo],
    arch: ArchType,
    pid: u32,
) -> Vec<ThreadContextPayload> {
    let mut contexts: Vec<ThreadContextPayload> = threads
        .iter()
        .filter_map(|thread| build_context(thread, arch))
        .collect();
    if let Some(current) = current_thread_index(&contexts, pid) {
        contexts[current].flags |= TC_FLAG_CURRENT;
    }
    contexts
}

fn current_thread_index(contexts: &[ThreadContextPayload], pid: u32) -> Option<usize> {
    if contexts.is_empty() {
        return None;
    }
    let main_thread = contexts
        .iter()
        .position(|context| context.thread_id == u64::from(pid));
    Some(main_thread.unwrap_or(0))
}

fn build_context(thread: &ThreadInfo, arch: ArchType) -> Option<ThreadContextPayload> {
    let width = register_width(arch);
    let mut registers = Vec::with_capacity(thread.registers.len());
    let mut partial = false;
    for (name, hex_value) in canonical_registers(&thread.registers, arch) {
        match parse_hex_value(hex_value) {
            Some(value) => registers.push(thread_register(&name, value, width, arch)),
            None => partial = true,
        }
    }
    if arch == ArchType::ARM32 {
        mark_arm32_frame_pointer(&mut registers);
    }
    if !has_role(&registers, REG_ROLE_PC) || !has_role(&registers, REG_ROLE_SP) {
        return None;
    }
    Some(ThreadContextPayload {
        thread_id: thread.id,
        start_time_ns: 0,
        flags: if partial { TC_FLAG_PARTIAL } else { 0 },
        state: thread_state(&thread.state),
        arch: 0,
        name: thread.name.clone(),
        registers,
    })
}

/// Lowercase canonical name and raw value of every reported register. An alias
/// whose canonical register is reported as well (Frida's `pc` next to `rip`)
/// is dropped, so the canonical-named entry wins when the values differ.
fn canonical_registers(registers: &[(String, String)], arch: ArchType) -> Vec<(String, &str)> {
    let named: Vec<(String, bool, &str)> = registers
        .iter()
        .map(|(name, value)| {
            let lowercase = name.to_ascii_lowercase();
            let canonical = canonical_register_name(&lowercase, arch).to_string();
            let is_alias = canonical != lowercase;
            (canonical, is_alias, value.as_str())
        })
        .collect();
    let reported_canonically = |name: &str| {
        named
            .iter()
            .any(|(other, alias, _)| !alias && other == name)
    };
    named
        .iter()
        .filter(|(name, is_alias, _)| !is_alias || !reported_canonically(name))
        .map(|(name, _, value)| (name.clone(), *value))
        .collect()
}

/// Set the FP role on `r7` or `r11`, depending on the reported CPSR T bit.
fn mark_arm32_frame_pointer(registers: &mut [ThreadRegister]) {
    let cpsr = registers
        .iter()
        .find(|register| register.name == "cpsr")
        .map(|register| decode_register_value(&register.value));
    let frame_pointer = arm32_frame_pointer(cpsr);
    if let Some(register) = registers.iter_mut().find(|r| r.name == frame_pointer) {
        register.flags |= REG_ROLE_FP;
    }
}

fn decode_register_value(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0, |value, byte| value << 8 | u64::from(*byte))
}

fn thread_register(name: &str, value: u64, width: u8, arch: ArchType) -> ThreadRegister {
    let name = name.to_ascii_lowercase();
    ThreadRegister {
        flags: register_role(&name, arch),
        width,
        value: encode_register_value(value, width),
        name,
    }
}

fn has_role(registers: &[ThreadRegister], role: u16) -> bool {
    registers.iter().any(|register| register.flags & role != 0)
}

/// Map Frida's `ThreadState` words onto Table 19a `ThreadState` codes.
fn thread_state(state: &str) -> ThreadState {
    match state {
        "running" => ThreadState::Running,
        "stopped" => ThreadState::Stopped,
        "waiting" => ThreadState::Waiting,
        "uninterruptible" => ThreadState::Uninterruptible,
        "halted" => ThreadState::Halted,
        _ => ThreadState::Unknown,
    }
}

fn parse_hex_value(text: &str) -> Option<u64> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    u64::from_str_radix(digits, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thread(id: u64, registers: &[(&str, &str)]) -> ThreadInfo {
        ThreadInfo {
            id,
            name: format!("thread-{id}"),
            state: "running".to_string(),
            registers: registers
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
        }
    }

    fn x64_thread(id: u64) -> ThreadInfo {
        thread(
            id,
            &[
                ("rip", "0x401000"),
                ("rsp", "0x7ffd0000"),
                ("rbp", "0x7ffd0040"),
                ("rax", "0x1"),
            ],
        )
    }

    fn register<'a>(context: &'a ThreadContextPayload, name: &str) -> &'a ThreadRegister {
        context
            .registers
            .iter()
            .find(|register| register.name == name)
            .unwrap_or_else(|| panic!("register {name} missing"))
    }

    #[test]
    fn width_is_four_bytes_on_32_bit_and_eight_on_64_bit() {
        assert_eq!(register_width(ArchType::X86), 4);
        assert_eq!(register_width(ArchType::ARM32), 4);
        assert_eq!(register_width(ArchType::X86_64), 8);
        assert_eq!(register_width(ArchType::ARM64), 8);
    }

    #[test]
    fn roles_for_x86_names() {
        assert_eq!(register_role("rip", ArchType::X86_64), REG_ROLE_PC);
        assert_eq!(register_role("eip", ArchType::X86), REG_ROLE_PC);
        assert_eq!(register_role("rsp", ArchType::X86_64), REG_ROLE_SP);
        assert_eq!(register_role("esp", ArchType::X86), REG_ROLE_SP);
        assert_eq!(register_role("rbp", ArchType::X86_64), REG_ROLE_FP);
        assert_eq!(register_role("ebp", ArchType::X86), REG_ROLE_FP);
        assert_eq!(register_role("rflags", ArchType::X86_64), REG_ROLE_FLAGS);
        assert_eq!(register_role("eflags", ArchType::X86), REG_ROLE_FLAGS);
        assert_eq!(register_role("fs_base", ArchType::X86_64), REG_ROLE_TLS);
        assert_eq!(register_role("gs_base", ArchType::X86_64), REG_ROLE_TLS);
        assert_eq!(register_role("rax", ArchType::X86_64), 0);
    }

    #[test]
    fn roles_for_arm_names() {
        assert_eq!(register_role("pc", ArchType::ARM64), REG_ROLE_PC);
        assert_eq!(register_role("sp", ArchType::ARM32), REG_ROLE_SP);
        assert_eq!(register_role("fp", ArchType::ARM64), REG_ROLE_FP);
        assert_eq!(register_role("x29", ArchType::ARM64), REG_ROLE_FP);
        assert_eq!(register_role("pstate", ArchType::ARM64), REG_ROLE_FLAGS);
        assert_eq!(register_role("cpsr", ArchType::ARM32), REG_ROLE_FLAGS);
        assert_eq!(register_role("nzcv", ArchType::ARM64), REG_ROLE_FLAGS);
        assert_eq!(register_role("tpidr_el0", ArchType::ARM64), REG_ROLE_TLS);
        assert_eq!(register_role("lr", ArchType::ARM32), REG_ROLE_LR);
        assert_eq!(register_role("x30", ArchType::ARM64), REG_ROLE_LR);
        assert_eq!(register_role("x0", ArchType::ARM64), 0);
    }

    #[test]
    fn roles_are_scoped_to_the_register_family() {
        assert_eq!(register_role("pc", ArchType::X86_64), 0);
        assert_eq!(register_role("rip", ArchType::ARM64), 0);
        assert_eq!(register_role("rip", ArchType::MIPS64), REG_ROLE_PC);
        assert_eq!(register_role("pc", ArchType::MIPS64), REG_ROLE_PC);
    }

    #[test]
    fn register_values_are_little_endian_at_register_width() {
        assert_eq!(
            encode_register_value(0x0102030405060708, 8),
            vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(
            encode_register_value(0xAABBCCDD, 4),
            vec![0xDD, 0xCC, 0xBB, 0xAA]
        );
    }

    #[test]
    fn builds_context_with_lowercase_names_roles_and_width() {
        let contexts = build_thread_contexts(
            &[thread(7, &[("RIP", "0x401000"), ("Rsp", "0x7ffd0000")])],
            ArchType::X86_64,
            7,
        );
        assert_eq!(contexts.len(), 1);
        let context = &contexts[0];
        assert_eq!(context.thread_id, 7);
        assert_eq!(context.name, "thread-7");
        assert_eq!(context.state, ThreadState::Running);
        assert_eq!(context.arch, 0);
        let rip = register(context, "rip");
        assert_eq!(rip.flags, REG_ROLE_PC);
        assert_eq!(rip.width, 8);
        assert_eq!(rip.value, 0x401000u64.to_le_bytes().to_vec());
        assert_eq!(register(context, "rsp").flags, REG_ROLE_SP);
    }

    #[test]
    fn arm32_registers_are_four_bytes_wide() {
        let contexts = build_thread_contexts(
            &[thread(3, &[("pc", "0xb6f01000"), ("sp", "0xbefff000")])],
            ArchType::ARM32,
            3,
        );
        let pc = register(&contexts[0], "pc");
        assert_eq!(pc.width, 4);
        assert_eq!(pc.value, vec![0x00, 0x10, 0xf0, 0xb6]);
    }

    #[test]
    fn thread_matching_pid_is_current() {
        let contexts =
            build_thread_contexts(&[x64_thread(100), x64_thread(42)], ArchType::X86_64, 42);
        assert_eq!(contexts.len(), 2);
        assert_eq!(contexts[0].flags & TC_FLAG_CURRENT, 0);
        assert_eq!(contexts[1].flags & TC_FLAG_CURRENT, TC_FLAG_CURRENT);
    }

    #[test]
    fn first_thread_is_current_when_pid_has_no_thread() {
        let contexts =
            build_thread_contexts(&[x64_thread(100), x64_thread(101)], ArchType::X86_64, 42);
        assert_eq!(contexts[0].flags & TC_FLAG_CURRENT, TC_FLAG_CURRENT);
        assert_eq!(contexts[1].flags & TC_FLAG_CURRENT, 0);
    }

    #[test]
    fn unparseable_value_sets_partial_and_drops_register() {
        let contexts = build_thread_contexts(
            &[thread(
                1,
                &[("rip", "0x1"), ("rsp", "0x2"), ("rax", "not-hex")],
            )],
            ArchType::X86_64,
            1,
        );
        assert_eq!(contexts.len(), 1);
        assert_eq!(contexts[0].flags & TC_FLAG_PARTIAL, TC_FLAG_PARTIAL);
        assert_eq!(contexts[0].registers.len(), 2);
    }

    #[test]
    fn threads_without_pc_or_sp_are_skipped() {
        let contexts = build_thread_contexts(
            &[
                thread(1, &[("rip", "0x1"), ("rax", "0x2")]),
                thread(2, &[("rsp", "0x1")]),
                thread(3, &[]),
                x64_thread(4),
            ],
            ArchType::X86_64,
            9,
        );
        assert_eq!(contexts.len(), 1);
        assert_eq!(contexts[0].thread_id, 4);
        assert_eq!(contexts[0].flags & TC_FLAG_CURRENT, TC_FLAG_CURRENT);
    }

    #[test]
    fn suspended_flag_is_never_set() {
        let contexts = build_thread_contexts(&[x64_thread(1)], ArchType::X86_64, 1);
        assert_eq!(contexts[0].flags & libmsl::constants::TC_FLAG_SUSPENDED, 0);
    }

    #[test]
    fn canonical_names_replace_aliases_per_architecture() {
        assert_eq!(canonical_register_name("pc", ArchType::X86_64), "rip");
        assert_eq!(canonical_register_name("sp", ArchType::X86_64), "rsp");
        assert_eq!(canonical_register_name("pc", ArchType::X86), "eip");
        assert_eq!(canonical_register_name("sp", ArchType::X86), "esp");
        assert_eq!(canonical_register_name("fp", ArchType::ARM64), "x29");
        assert_eq!(canonical_register_name("lr", ArchType::ARM64), "x30");
        assert_eq!(canonical_register_name("nzcv", ArchType::ARM64), "nzcv");
        assert_eq!(canonical_register_name("pc", ArchType::ARM64), "pc");
        assert_eq!(canonical_register_name("r13", ArchType::ARM32), "sp");
        assert_eq!(canonical_register_name("r14", ArchType::ARM32), "lr");
        assert_eq!(canonical_register_name("r15", ArchType::ARM32), "pc");
        assert_eq!(canonical_register_name("pc", ArchType::MIPS64), "pc");
    }

    #[test]
    fn frida_x86_64_aliases_are_dropped_next_to_canonical_names() {
        let contexts = build_thread_contexts(
            &[thread(
                1,
                &[
                    ("pc", "0x999"),
                    ("sp", "0x888"),
                    ("rax", "0x1"),
                    ("rsp", "0x7ffd0000"),
                    ("rip", "0x401000"),
                ],
            )],
            ArchType::X86_64,
            1,
        );
        let context = &contexts[0];
        let names: Vec<&str> = context.registers.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["rax", "rsp", "rip"]);
        let rip = register(context, "rip");
        assert_eq!(rip.flags, REG_ROLE_PC);
        assert_eq!(rip.value, 0x401000u64.to_le_bytes().to_vec());
        assert_eq!(register(context, "rsp").flags, REG_ROLE_SP);
    }

    #[test]
    fn lone_x86_aliases_are_renamed() {
        let contexts = build_thread_contexts(
            &[thread(1, &[("pc", "0x8048000"), ("sp", "0xbfff0000")])],
            ArchType::X86,
            1,
        );
        assert_eq!(register(&contexts[0], "eip").flags, REG_ROLE_PC);
        assert_eq!(register(&contexts[0], "esp").flags, REG_ROLE_SP);
    }

    #[test]
    fn frida_arm64_fp_and_lr_become_x29_and_x30() {
        let contexts = build_thread_contexts(
            &[thread(
                1,
                &[
                    ("pc", "0x100003f00"),
                    ("sp", "0x16fdff000"),
                    ("nzcv", "0x60000000"),
                    ("x0", "0x0"),
                    ("fp", "0x16fdff010"),
                    ("lr", "0x100003e00"),
                ],
            )],
            ArchType::ARM64,
            1,
        );
        let context = &contexts[0];
        let names: Vec<&str> = context.registers.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["pc", "sp", "nzcv", "x0", "x29", "x30"]);
        assert_eq!(register(context, "x29").flags, REG_ROLE_FP);
        assert_eq!(register(context, "x30").flags, REG_ROLE_LR);
        assert_eq!(register(context, "nzcv").flags, REG_ROLE_FLAGS);
    }

    fn arm32_thread(cpsr: &str) -> ThreadInfo {
        thread(
            1,
            &[
                ("pc", "0x8000"),
                ("r13", "0xbefff000"),
                ("cpsr", cpsr),
                ("r7", "0x7"),
                ("r11", "0xb"),
                ("r14", "0x8100"),
            ],
        )
    }

    #[test]
    fn arm32_frame_pointer_is_r7_in_thumb_mode() {
        let contexts = build_thread_contexts(&[arm32_thread("0x60000030")], ArchType::ARM32, 1);
        assert_eq!(register(&contexts[0], "r7").flags, REG_ROLE_FP);
        assert_eq!(register(&contexts[0], "r11").flags, 0);
    }

    #[test]
    fn arm32_frame_pointer_is_r11_in_arm_mode() {
        let contexts = build_thread_contexts(&[arm32_thread("0x60000010")], ArchType::ARM32, 1);
        assert_eq!(register(&contexts[0], "r11").flags, REG_ROLE_FP);
        assert_eq!(register(&contexts[0], "r7").flags, 0);
        assert_eq!(arm32_frame_pointer(None), "r11");
    }

    #[test]
    fn arm32_r13_to_r15_aliases_become_sp_lr_pc() {
        let contexts = build_thread_contexts(&[arm32_thread("0x10")], ArchType::ARM32, 1);
        let context = &contexts[0];
        for alias in ["r13", "r14", "r15"] {
            assert!(context.registers.iter().all(|r| r.name != alias));
        }
        assert_eq!(register(context, "sp").flags, REG_ROLE_SP);
        assert_eq!(register(context, "lr").flags, REG_ROLE_LR);
        assert_eq!(register(context, "pc").flags, REG_ROLE_PC);
        assert_eq!(register(context, "cpsr").flags, REG_ROLE_FLAGS);
    }

    #[test]
    fn frida_thread_states_map_to_spec_codes() {
        assert_eq!(thread_state("running"), ThreadState::Running);
        assert_eq!(thread_state("stopped"), ThreadState::Stopped);
        assert_eq!(thread_state("waiting"), ThreadState::Waiting);
        assert_eq!(
            thread_state("uninterruptible"),
            ThreadState::Uninterruptible
        );
        assert_eq!(thread_state("halted"), ThreadState::Halted);
        assert_eq!(thread_state(""), ThreadState::Unknown);
    }

    #[test]
    fn hex_values_parse_with_and_without_prefix() {
        assert_eq!(parse_hex_value("0x1f"), Some(0x1f));
        assert_eq!(parse_hex_value("1F"), Some(0x1f));
        assert_eq!(parse_hex_value("0xzz"), None);
        assert_eq!(parse_hex_value(""), None);
    }
}
