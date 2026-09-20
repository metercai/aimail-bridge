//! 桥的进程生命周期契约（owner 定调 2026-09-20，P1-α）。
//!
//! 新增三个一次性操作（都不进 tokio 运行时、不 daemonize）：
//!   `--status [--json]`   只读报告桥是否在运行（供 CLI/脚本消费）
//!   `--stop`              优雅停止；**先做 PID 身份校验**，不是桥就拒绝，绝不误杀
//!   `--check-config`      只校验配置能否加载/通过语义校验（供 CLI/repair 写配置后自检）
//!
//! 退出码表（固定契约，CLI/SDK/脚本可依赖）：
//!   0 成功 / 正在运行      1 通用错误（含"拒绝：pid 不属于桥"）
//!   2 配置非法             3 未运行
//!
//! 与既有审计结论 AUDIT-1 A4 的关系：A4 说"pid 文件有意不删，因为 deploy_bridge 靠它杀陈旧进程"。
//! 本模块把"陈旧 pid 的处理"从"靠 pid 文件杀进程"改为**身份可验 + 状态可查**：
//! `--status` 能区分 无 pid 文件 / 陈旧 pid（进程已死）/ pid 属于别的程序；
//! 因此待 P2（CLI 改调本契约、删除自查杀进程逻辑）落地后，A4 的理由消失，
//! P1-β 才启用"优雅退出删除 pid 文件"。**`--stop` 明确停掉桥后删 pid 文件是安全的**（已验身份）。

use std::path::{Path, PathBuf};
#[allow(unused_imports)] // 仅非 linux 平台路径使用(ps/tasklist/taskkill)
use std::process::Command;

pub const EXIT_OK: i32 = 0;
pub const EXIT_GENERIC: i32 = 1;
pub const EXIT_BAD_CONFIG: i32 = 2;
pub const EXIT_NOT_RUNNING: i32 = 3;

const BRIDGE_BIN: &str = "aimail-bridge";

/// 读 pid 文件（容错：空白/非数字/多行取首个有效数字）。
pub fn read_pid(pid_file: &Path) -> Option<i32> {
    let s = std::fs::read_to_string(pid_file).ok()?;
    s.split_whitespace().next()?.parse::<i32>().ok()
}

/// 进程是否存活。Unix 用 kill(pid, 0)；Windows 用 tasklist 查询。
#[cfg(unix)]
pub fn pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    unsafe { libc::kill(pid, 0) == 0 }
}

/// 按 CSV 引号规则切分一行（纯函数 —— 供非 linux 路径在**任意平台**单测）。
/// tasklist 的 `--FO CSV` 里内存列含逗号（`"12,345 K"`），朴素 split(',') 会错位。
fn csv_fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for ch in line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => out.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    out.push(cur);
    out
}

/// 解析 `tasklist /FO CSV /NH` 的首行 → (pid, 可执行名)。
/// 纯函数：把 Windows 侧解析逻辑搬到能被本机测试覆盖的位置。
/// 无匹配时 tasklist 输出 `INFO: No tasks are running …`（无引号）⇒ None。
#[cfg_attr(unix, allow(dead_code))] // 仅非 unix 路径调用，但测试在所有平台跑
pub fn parse_tasklist_row(out: &str) -> Option<(i32, String)> {
    let line = out.lines().next()?.trim_end();
    if !line.starts_with('"') {
        return None;
    }
    let fields = csv_fields(line);
    let name = fields.first()?.trim().to_string();
    let pid: i32 = fields.get(1)?.trim().parse().ok()?;
    if name.is_empty() {
        return None;
    }
    Some((pid, name))
}

#[cfg(not(unix))]
pub fn pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    match Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
        .output()
    {
        // 精确比较 pid 字段（原实现用 substring，pid 1234 会被 12345 命中 ⇒ 假存活）
        Ok(o) => parse_tasklist_row(&String::from_utf8_lossy(&o.stdout))
            .map(|(p, _)| p == pid)
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// 取进程的"可执行文件名"（不含路径，Windows 去掉 .exe）。
/// Unix: Linux 读 /proc/<pid>/cmdline；其它 Unix 用 `ps -p <pid> -o comm=`。
#[cfg(target_os = "linux")]
fn proc_exe_name(pid: i32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{}/cmdline", pid)).ok()?;
    let first = raw.split(|b| *b == 0).next()?;
    let s = String::from_utf8_lossy(first).to_string();
    Some(exe_basename(&s))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn proc_exe_name(pid: i32) -> Option<String> {
    let o = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(exe_basename(&s))
    }
}

#[cfg(not(unix))]
fn proc_exe_name(pid: i32) -> Option<String> {
    let o = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
        .output()
        .ok()?;
    // tasklist 报告的是 "aimail-bridge.exe" ⇒ 必须经 exe_basename 去 .exe 并小写,
    // 否则 is_bridge 拿带后缀的名字比 "aimail-bridge" **恒不相等** ⇒ Windows 上
    // --status 会把在跑的桥报成 pid-not-bridge、--stop 直接拒绝(契约形同失效)。
    let (row_pid, name) = parse_tasklist_row(&String::from_utf8_lossy(&o.stdout))?;
    if row_pid != pid {
        return None;
    }
    let base = exe_basename(&name);
    if base.is_empty() {
        None
    } else {
        Some(base)
    }
}

/// 由路径/命令串取可执行文件名（纯函数，供单测）。
pub fn exe_basename(s: &str) -> String {
    let t = s.trim().trim_matches('"');
    let base = t.rsplit(['/', '\\']).next().unwrap_or(t);
    let base = base.strip_suffix(".exe").unwrap_or(base);
    base.to_ascii_lowercase()
}

/// 该 pid 是否是 aimail-bridge（严格比对可执行文件名，不匹配父目录/参数，避免误杀）。
pub fn is_bridge(pid: i32) -> bool {
    match proc_exe_name(pid) {
        Some(name) => name == BRIDGE_BIN,
        None => false,
    }
}

#[derive(Debug, PartialEq)]
pub enum State {
    Running { pid: i32 },
    NoPidFile,
    StalePid { pid: i32 },
    NotBridge { pid: i32 },
}

pub fn probe(pid_file: &Path) -> State {
    match read_pid(pid_file) {
        None => State::NoPidFile,
        Some(pid) => {
            if !pid_alive(pid) {
                State::StalePid { pid }
            } else if !is_bridge(pid) {
                State::NotBridge { pid }
            } else {
                State::Running { pid }
            }
        }
    }
}

fn print_status(pid_file: &Path, st: &State, json: bool) {
    let (running, reason, pid) = match st {
        State::Running { pid } => (true, "ok", Some(*pid)),
        State::NoPidFile => (false, "no-pid-file", None),
        State::StalePid { pid } => (false, "stale-pid", Some(*pid)),
        State::NotBridge { pid } => (false, "pid-not-bridge", Some(*pid)),
    };
    if json {
        let pid_field = pid.map(|p| p.to_string()).unwrap_or_else(|| "null".into());
        println!(
            "{{\"running\":{},\"reason\":\"{}\",\"pid\":{},\"pid_file\":\"{}\",\"version\":\"{}\"}}",
            running,
            reason,
            pid_field,
            pid_file.display(),
            env!("CARGO_PKG_VERSION")
        );
    } else if running {
        println!(
            "aimail-bridge running (pid {}) — pid file: {}",
            pid.unwrap(),
            pid_file.display()
        );
    } else {
        println!(
            "aimail-bridge not running ({}), pid file: {}",
            reason,
            pid_file.display()
        );
    }
}

/// `--status`：只读；退出码 0 运行中 / 3 未运行。绝不创建或删除 pid 文件。
pub fn status(pid_file: &Path, json: bool) -> i32 {
    let st = probe(pid_file);
    print_status(pid_file, &st, json);
    match st {
        State::Running { .. } => EXIT_OK,
        _ => EXIT_NOT_RUNNING,
    }
}

/// `--stop`：身份校验后优雅停止。未运行=幂等成功；pid 属于别的程序=拒绝(1)。
pub fn stop(pid_file: &Path, json: bool) -> i32 {
    match probe(pid_file) {
        State::NoPidFile => {
            print_status(pid_file, &State::NoPidFile, json);
            EXIT_OK
        }
        State::StalePid { pid } => {
            // 陈旧 pid：清掉文件即可（进程已死，无杀的必要）
            let _ = std::fs::remove_file(pid_file);
            print_status(pid_file, &State::StalePid { pid }, json);
            EXIT_OK
        }
        State::NotBridge { pid } => {
            eprintln!(
                "refusing to stop: pid {} from {} is not {}, not touching it",
                pid,
                pid_file.display(),
                BRIDGE_BIN
            );
            EXIT_GENERIC
        }
        State::Running { pid } => {
            if !terminate(pid) {
                eprintln!("failed to signal pid {}", pid);
                return EXIT_GENERIC;
            }
            // 最多等 10s 优雅退出，超时强杀
            let mut waited = 0;
            while pid_alive(pid) && waited < 100 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                waited += 1;
            }
            if pid_alive(pid) {
                kill9(pid);
                let mut w2 = 0;
                while pid_alive(pid) && w2 < 20 {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    w2 += 1;
                }
            }
            if pid_alive(pid) {
                eprintln!("pid {} still alive after SIGKILL", pid);
                return EXIT_GENERIC;
            }
            let _ = std::fs::remove_file(pid_file);
            if json {
                println!("{{\"stopped\":true,\"pid\":{}}}", pid);
            } else {
                println!("aimail-bridge stopped (pid {})", pid);
            }
            EXIT_OK
        }
    }
}

#[cfg(unix)]
fn terminate(pid: i32) -> bool {
    unsafe { libc::kill(pid, libc::SIGTERM) == 0 }
}

#[cfg(not(unix))]
fn terminate(pid: i32) -> bool {
    Command::new("taskkill")
        .args(["/PID", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(unix)]
fn kill9(pid: i32) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill9(pid: i32) {
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .status();
}

/// `--check-config`：只校验配置。0 合法 / 2 非法。
/// 先 load（解析+类型+文件缺失），再 validate（语义）；validate 若 panic 也按非法处理。
pub fn check_config(path: Option<&Path>, json: bool) -> i32 {
    match crate::config::BridgeConfig::load(path) {
        Err(e) => {
            if json {
                println!(
                    "{{\"valid\":false,\"error\":\"{}\"}}",
                    e.to_string().replace('"', "'")
                );
            } else {
                eprintln!("config invalid: {}", e);
            }
            EXIT_BAD_CONFIG
        }
        Ok(cfg) => {
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cfg.validate()));
            match res {
                Ok(()) => {
                    let shown = path
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "(default)".into());
                    if json {
                        println!(
                            "{{\"valid\":true,\"config\":\"{}\",\"mode\":\"{}\",\"bind\":\"{}\"}}",
                            shown, cfg.mode, cfg.bind
                        );
                    } else {
                        println!("config ok: {} (mode={} bind={})", shown, cfg.mode, cfg.bind);
                    }
                    EXIT_OK
                }
                Err(_) => {
                    if json {
                        println!("{{\"valid\":false,\"error\":\"validate() failed\"}}");
                    } else {
                        eprintln!("config invalid: semantic validate() failed");
                    }
                    EXIT_BAD_CONFIG
                }
            }
        }
    }
}

/// 默认 pid/log 路径（与 CLI 布局一致：~/.aimail/bridge/）。
pub fn default_paths() -> (PathBuf, PathBuf) {
    let root = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".aimail")
        .join("bridge");
    (root.join("bridge.pid"), root.join("bridge.log"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_is_strict() {
        assert_eq!(
            exe_basename("/home/u/aimail-bridge/target/debug/aimail-bridge"),
            "aimail-bridge"
        );
        assert_eq!(exe_basename("aimail-bridge.exe"), "aimail-bridge");
        assert_eq!(exe_basename("\"/opt/aimail-bridge\""), "aimail-bridge");
        // 关键：跑在仓库目录下的**测试二进制**/别的程序不得被判为桥（防误杀）
        assert_ne!(
            exe_basename("/home/u/aimail-bridge/target/debug/deps/aimail_bridge-abc123"),
            "aimail-bridge"
        );
        assert_ne!(
            exe_basename("/home/u/aimail-bridge/target/debug/deps/other-1"),
            "aimail-bridge"
        );
    }

    #[test]
    fn read_pid_tolerates_noise() {
        let d = std::env::temp_dir().join(format!("br-lifecycle-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("a.pid");
        std::fs::write(&f, "  4242\nextra\n").unwrap();
        assert_eq!(read_pid(&f), Some(4242));
        std::fs::write(&f, "not-a-pid\n").unwrap();
        assert_eq!(read_pid(&f), None);
        std::fs::remove_file(&f).unwrap();
        assert_eq!(read_pid(&f), None); // 文件不存在
    }

    #[test]
    fn status_reports_three_states() {
        let d = std::env::temp_dir().join(format!("br-lifecycle2-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("b.pid");
        // ① 无 pid 文件
        assert_eq!(status(&f, true), EXIT_NOT_RUNNING);
        assert_eq!(probe(&f), State::NoPidFile);
        // ② 陈旧 pid（本进程 pid 一定存活 ⇒ 用另一个已退出的子进程 pid）
        let mut child = Command::new(if cfg!(windows) { "cmd" } else { "true" })
            .args(if cfg!(windows) {
                vec!["/c", "exit 0"]
            } else {
                vec![]
            })
            .spawn()
            .unwrap();
        let dead = child.id() as i32;
        let _ = child.wait();
        std::fs::write(&f, dead.to_string()).unwrap();
        assert_eq!(status(&f, true), EXIT_NOT_RUNNING);
        assert!(matches!(probe(&f), State::StalePid { .. }));
        // ③ pid 属于别的程序（用测试进程自身）
        std::fs::write(&f, std::process::id().to_string()).unwrap();
        assert!(matches!(probe(&f), State::NotBridge { .. }));
        assert_eq!(status(&f, true), EXIT_NOT_RUNNING);
        std::fs::remove_file(&f).unwrap();
    }

    #[test]
    fn stop_refuses_foreign_pid() {
        let d = std::env::temp_dir().join(format!("br-lifecycle3-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("c.pid");
        // 未运行：幂等成功
        assert_eq!(stop(&f, true), EXIT_OK);
        // pid 属于别的程序：拒绝，且必须活得好好（本测试若被误杀就不会走到断言）
        std::fs::write(&f, std::process::id().to_string()).unwrap();
        assert_eq!(stop(&f, false), EXIT_GENERIC);
        assert!(
            std::fs::read_to_string(&f).is_ok(),
            "拒绝时不得删除 pid 文件"
        );
        std::fs::remove_file(&f).unwrap();
    }

    #[test]
    fn tasklist_row_parsing_is_exact() {
        // 真实形态：内存列含逗号（引号内）不得导致字段错位
        let row = "\"aimail-bridge.exe\",\"1234\",\"Console\",\"1\",\"12,345 K\"\r\n";
        assert_eq!(
            parse_tasklist_row(row),
            Some((1234, "aimail-bridge.exe".to_string()))
        );
        // 无匹配时 tasklist 输出 INFO 行（无引号）⇒ 不得当成存活
        assert_eq!(
            parse_tasklist_row(
                "INFO: No tasks are running which match the specified criteria.\r\n"
            ),
            None
        );
        assert_eq!(parse_tasklist_row(""), None);
        assert_eq!(parse_tasklist_row("\"name.exe\",\"not-a-pid\"\r\n"), None);
    }

    /// Windows 身份判定契约（纯逻辑，本机可跑）：tasklist 报 "aimail-bridge.exe"
    /// 必须判为桥（去 .exe + 小写）；别的程序不得判为桥（防误杀）。
    #[test]
    fn windows_identity_contract_uses_basename() {
        let row = "\"aimail-bridge.exe\",\"4242\",\"Console\",\"1\",\"9,000 K\"\r\n";
        let (pid, name) = parse_tasklist_row(row).unwrap();
        assert_eq!(pid, 4242);
        assert_eq!(exe_basename(&name), BRIDGE_BIN);

        let other = "\"aimail-bridge-helper.exe\",\"4243\",\"Console\",\"1\",\"9,000 K\"\r\n";
        let (_, other_name) = parse_tasklist_row(other).unwrap();
        assert_ne!(exe_basename(&other_name), BRIDGE_BIN);
    }

    /// pid 必须精确比较：原实现用 substring，pid 1234 会被 "12345" 命中（假存活）。
    #[test]
    fn pid_match_is_exact_not_substring() {
        let row = "\"aimail-bridge.exe\",\"12345\",\"Console\",\"1\",\"1 K\"\r\n";
        let (parsed, _) = parse_tasklist_row(row).unwrap();
        assert_eq!(parsed, 12345);
        assert_ne!(parsed, 1234);
    }
}
