//! main.rs —— 入口：参数解析 + 配置加载 + std::thread 并行调度 + GPG 加密落盘
//!
//! 并行模型（规格 performance_optimization）：
//! - `std::thread::scope` 派生 N 个 worker（N = config 或 available_parallelism）；
//! - worker 各自持有独立的 [`Generator`]（无锁竞争），循环"生成-检查"；
//! - 每次尝试通过 `AtomicU64` 领取全局序号，据此输出进度通知（取模判断，
//!   u64 语义下无溢出风险）；
//! - 命中后经 `crossbeam-channel`（unbounded）发送到主线程，
//!   主线程负责 GPG 加密与落盘，不阻塞计算线程；
//! - 达到 `count` 后主线程置位 `AtomicBool`，worker 检查后退出。

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use anyhow::Result;
use clap::Parser;
use crossbeam_channel::unbounded;

use vanity_generator::config::Config;
use vanity_generator::error::VanityError;
use vanity_generator::gpg::GpgEncryptor;
use vanity_generator::generator::Generator;
use vanity_generator::matcher::Matcher;

/// 命令行参数
#[derive(Debug, Parser)]
#[command(
    name = "vanity-generator",
    version,
    about = "以太坊靓号地址生成器（BIP39/BIP32 + OsRng + GPG 加密输出）"
)]
struct Cli {
    /// 指定 config.yaml 路径（默认：可执行文件同目录，或环境变量 VANITY_CONFIG 内容）
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// 仅校验配置与公钥并输出摘要（含期望尝试次数预估），不开始搜索
    #[arg(long)]
    check: bool,
}

/// 64 字节对齐的原子包装（消除伪共享）。
///
/// 硬件视角：相邻原子变量若落在同一缓存行，多核写入会造成缓存行在核间
/// 乒乓（MESI Invalidate）；长时间高并发下即使单次开销极小，累积效应
/// 可观。各自独占一个 64B 缓存行后写互不失效（参考 docs/perf-research.md
/// §8 硬件视角优化与《现代 CPU 性能》笔记 §4.6）。
#[repr(align(64))]
struct PadAtomic<T>(T);

impl<T> PadAtomic<T> {
    fn new(v: T) -> Self {
        Self(v)
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // VanityError 按统一双语格式输出；其余错误给出通用双语包装
            match err.downcast_ref::<VanityError>() {
                Some(v) => eprintln!("{v}"),
                None => eprintln!(
                    "[ERROR / 错误]\nEN: unexpected internal error: {err:?}\n\
                     CN: 发生未预期的内部错误：{err:?}"
                ),
            }
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let exe_dir = exe_dir()?;

    // 1. 配置与公钥（CLI > 环境变量 > 同目录文件）
    let gpg_env = std::env::var(vanity_generator::config::ENV_GPG_KEY).ok();
    let cfg = Config::load(cli.config.as_deref(), &exe_dir, gpg_env.as_deref())?;

    // 2. 启动前完成全部昂贵解析（匹配器预构建、公钥 Cert 解析）
    let matcher = Matcher::new(
        cfg.case_sensitive,
        cfg.front.clone(),
        cfg.middle.clone(),
        cfg.back.clone(),
    );
    let gpg_data = match (&cfg.gpg_key_inline, &cfg.gpg_key_path) {
        (Some(content), _) => content.clone().into_bytes(),
        (None, Some(p)) => std::fs::read(p).map_err(|e| {
            VanityError::io(
                format!("failed to read gpg key file {}: {e}", p.display()),
                format!("读取公钥文件 {} 失败：{e}", p.display()),
            )
        })?,
        (None, None) => unreachable!("config 层已保证公钥来源存在"),
    };
    let encryptor = GpgEncryptor::from_bytes(&gpg_data)?;

    // 工作线程数：config 指定优先；否则按 CPU 逻辑核心数自动分配
    // （available_parallelism 返回逻辑 CPU 数，即含超线程：4 核 8 线程 → 8）
    let threads = cfg
        .threads
        .map_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()), |n| n as usize);
    print_startup(&cfg, &matcher, &encryptor, threads, &cfg.output_dir);

    // --check：校验通过即退出（不开始搜索）
    if cli.check {
        println!("配置校验通过（--check）：config 与公钥均可用，未开始搜索。");
        return Ok(());
    }

    // 3. 并行调度
    let started = Instant::now();
    let stopped = AtomicBool::new(false);
    let failed = AtomicBool::new(false);
    // 共享原子各自独占缓存行（见 PadAtomic 文档）
    let attempts = PadAtomic::new(AtomicU64::new(0));
    let hits = PadAtomic::new(AtomicU32::new(0));
    let progress_lock = Mutex::new(()); // 进度行原子输出
    let (tx, rx) = unbounded::<vanity_generator::generator::HitRecord>();
    let seq = AtomicU32::new(0);
    let encrypt_err: Mutex<Option<VanityError>> = Mutex::new(None);
    // 上次进度通知的（全局序号, 毫秒时刻）：用于瞬时速率，长跑时宿主机
    // 波动/频率调整能被直接看到，累计均值不再误导（Docker 长跑实测教训）
    let last_prog_ticket = PadAtomic::new(AtomicU64::new(0));
    let last_prog_ms = PadAtomic::new(AtomicU64::new(0));

    // 调度架构：std::thread::scope 派生 N 个原生 OS 线程（非工作窃取池）。
    // 理由：本负载是 N 个粗粒度独立搜索循环，无细粒度可窃取任务，
    // rayon 的池注入/睡眠唤醒协议在单线程池下存在丢唤醒竞态
    // （rayon-core sleep/mod.rs 注释自认"特定竞态下可能无法唤醒"），
    // 实测 num_threads(1) 时注入任务永不执行 → 1 核机器死锁。
    // 原生 scope 线程语义确定：N 个 worker + 主线程收包，任意 N ≥ 1 均安全。
    {
        // 预先借用/复制跨线程共享的数据（避免 move 闭包逐值搬移）
        let matcher = &matcher;
        let cfg_path = &cfg.path;
        let cfg_indices = &cfg.path_indices;
        let cfg_wc = cfg.word_count;
        let cfg_cs = cfg.case_sensitive;
        let cfg_batch = cfg.derive_batch;
        let cfg_every = cfg.progress_every;
        std::thread::scope(|s| {
            for _ in 0..threads {
                let tx = tx.clone();
                let stopped = &stopped;
                let failed = &failed;
                let attempts = &attempts.0;
                let hits = &hits.0;
                let progress_lock = &progress_lock;
                let last_t = &last_prog_ticket.0;
                let last_ms = &last_prog_ms.0;
                s.spawn(move || {
                    // 每个 worker 独立持有生成器上下文（无锁竞争）
                    let mut gen = match Generator::new(cfg_wc, cfg_path, cfg_indices, cfg_cs) {
                        Ok(g) => g.with_derive_batch(cfg_batch),
                        Err(e) => {
                            eprintln!("{e}");
                            failed.store(true, Ordering::Relaxed);
                            stopped.store(true, Ordering::Relaxed);
                            return;
                        }
                    };
                    loop {
                        if stopped.load(Ordering::Relaxed) {
                            return;
                        }
                        // 一次"生成-检查"：checked = 本次检查的地址数
                        // （derive_batch > 1 时一个助记词派生多个地址，一次领取）
                        let (hit_vec, checked) = match gen.try_once(matcher) {
                            Ok(r) => r,
                            Err(e) => {
                                eprintln!("{e}");
                                failed.store(true, Ordering::Relaxed);
                                stopped.store(true, Ordering::Relaxed);
                                return;
                            }
                        };
                        // 全局尝试序号：u64 取模判断进度，无溢出风险
                        let before = attempts.fetch_add(checked as u64, Ordering::Relaxed);
                        let ticket = before + checked as u64;
                        if let Some(every) = cfg_every {
                            // 批量跨过阈值边界时输出进度行（batch 可能一次跨多级）
                            if ticket / every > before / every {
                                let _guard = progress_lock.lock().unwrap_or_else(|p| p.into_inner());
                                let elapsed = started.elapsed().as_secs_f64();
                                let now_ms = (elapsed * 1000.0) as u64;
                                let pt = last_t.load(Ordering::Relaxed);
                                let pms = last_ms.load(Ordering::Relaxed);
                                let inst = if now_ms > pms && ticket > pt {
                                    (ticket - pt) as f64 * 1000.0 / (now_ms - pms) as f64
                                } else {
                                    ticket as f64 / elapsed.max(f64::EPSILON)
                                };
                                last_t.store(ticket, Ordering::Relaxed);
                                last_ms.store(now_ms, Ordering::Relaxed);
                                println!(
                                    "进度：已尝试 {} | 命中 {} | 瞬时 {:.0}/s | 平均 {:.0}/s | 耗时 {:.0}s",
                                    ticket,
                                    hits.load(Ordering::Relaxed),
                                    inst,
                                    ticket as f64 / elapsed.max(f64::EPSILON),
                                    elapsed
                                );
                            }
                        }
                        for hit in hit_vec {
                            if tx.send(hit).is_err() {
                                // 主线程已退出（异常终止），停止工作
                                return;
                            }
                        }
                    }
                });
            }
            drop(tx); // 主线程不再发送，recv 在全部 worker 退出后返回 None

            // 主循环：接收命中 → 加密落盘 → 计数
            let mut encrypted_files: Vec<PathBuf> = Vec::new();
            for hit in rx {
                let n = seq.fetch_add(1, Ordering::Relaxed) + 1;
                match encryptor.encrypt_to_file(&hit, &cfg.output_dir, n) {
                    Ok(path) => {
                        hits.0.store(n, Ordering::Relaxed);
                        encrypted_files.push(path.clone());
                        println!(
                            "[命中 #{:03}] 地址 {} | 已加密 → {}",
                            n, hit.address, path.display()
                        );
                    }
                    Err(e) => {
                        // 加密失败为致命错误：停止所有 worker 并向主流程传播
                        encrypt_err.lock().unwrap_or_else(|p| p.into_inner()).replace(e);
                        stopped.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                if n >= cfg.count {
                    stopped.store(true, Ordering::Relaxed);
                    break;
                }
            }
            let _ = encrypted_files;
        });
    }

    // 4. 汇总
    let total = attempts.0.load(Ordering::Relaxed);
    let hit_n = hits.0.load(Ordering::Relaxed);
    let elapsed = started.elapsed().as_secs_f64();
    if let Some(e) = encrypt_err.into_inner().unwrap_or_else(|p| p.into_inner()) {
        return Err(e.into());
    }
    if failed.load(Ordering::Relaxed) && hit_n < cfg.count {
        // worker 层错误已在输出中打印双语信息；此处保证非零退出码
        return Err(VanityError::internal(
            "worker terminated abnormally; see the bilingual error above.",
            "工作线程异常终止，详见上方的双语错误信息。",
        )
        .into());
    }
    println!(
        "===== 完成 =====\n共尝试 {} 个地址，命中 {} 个，耗时 {:.1}s（平均 {:.0}/s）\n\
         加密文件已输出到 {}",
        total,
        hit_n,
        elapsed,
        total as f64 / elapsed.max(f64::EPSILON),
        cfg.output_dir.display()
    );
    // 进度提示：阈值高于总尝试数时用户会疑惑"为何没有进度行"，显式解释
    if let Some(every) = cfg.progress_every {
        if total < every {
            println!(
                "提示       : 本次总尝试数 {total} 低于 progress_every 阈值 {every}，\
                 故未输出任何进度行；短任务建议调低阈值（如 5000）。"
            );
        }
    }
    Ok(())
}

/// 可执行文件所在目录（config.yaml 与输出文件的默认位置）
fn exe_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe().map_err(|e| {
        VanityError::io(
            format!("failed to locate the running executable: {e}. Please run the binary directly."),
            format!("无法定位当前可执行文件：{e}。请直接运行本程序。"),
        )
    })?;
    Ok(exe
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".")))
}

/// 启动信息（中文；不输出任何敏感内容）
fn print_startup(
    cfg: &Config,
    matcher: &Matcher,
    encryptor: &GpgEncryptor,
    threads: usize,
    output_dir: &std::path::Path,
) {
    let entropy_bits = match cfg.word_count {
        12 => 128,
        18 => 192,
        _ => 256,
    };
    println!("===== vanity-generator 启动 =====");
    println!(
        "助记词长度 : {} 词（{} 位熵）",
        cfg.word_count, entropy_bits
    );
    println!(
        "靓号规则   : {}（大小写敏感：{}）",
        matcher.describe(),
        if cfg.case_sensitive { "是" } else { "否" }
    );
    // 期望尝试次数与参考耗时（单机速率按保守 400/s 估算，多核更快）
    let expected = matcher.expected_attempts();
    let est_secs = expected / 400.0;
    println!(
        "期望尝试   : 约 {}（参考耗时：单机约 {}）",
        fmt_count(expected),
        fmt_duration(est_secs)
    );
    if est_secs > 3600.0 * 24.0 {
        println!("提示       : 规则较难，单机预计超过一天；建议缩短规则或使用多机并行演示工作流。");
    }
    println!(
        "派生路径   : {}（{} 层，其中 hardened {} 层）",
        cfg.path,
        cfg.path_indices.len(),
        cfg.path_indices
            .iter()
            .filter(|i| (*i & 0x8000_0000) != 0)
            .count()
    );
    println!("目标数量   : {}", cfg.count);
    if cfg.derive_batch > 1 {
        println!(
            "批派生     : 每助记词派生 {} 个地址（末层连续索引，约 {}× 提速）",
            cfg.derive_batch, cfg.derive_batch
        );
    }
    println!(
        "进度通知   : {}",
        cfg.progress_every.map_or_else(
            || "已禁用".to_string(),
            |n| {
                // 按当前规则难度预估进度行数量，帮助用户设置合理阈值
                let est_lines = (expected / n as f64).ceil();
                format!("每 {n} 次尝试（按本规则难度预计输出约 {est_lines:.0} 行）")
            }
        )
    );
    let key_src = cfg
        .gpg_key_path
        .as_ref()
        .map_or_else(
            || format!("环境变量 {}", vanity_generator::config::ENV_GPG_KEY),
            |p| format!("文件 {}", p.display()),
        );
    println!(
        "GPG 公钥   : {}（可用加密子密钥 {} 个）",
        key_src,
        encryptor.usable_keys()
    );
    match cfg.threads {
        Some(n) => println!("工作线程   : {n}（config.yaml 指定）"),
        None => println!(
            "工作线程   : {threads}（自动 = CPU 逻辑核心数，含超线程）"
        ),
    }
    println!("输出目录   : {}", output_dir.display());
}

/// 人类可读的大数字（256 / 6.6万 / 43亿 / 1.2e15）
fn fmt_count(n: f64) -> String {
    if n < 1e4 {
        format!("{}", n.round() as u64)
    } else if n < 1e8 {
        format!("{:.1} 万", n / 1e4)
    } else if n < 1e12 {
        format!("{:.1} 亿", n / 1e8)
    } else {
        format!("{:.2e}", n)
    }
}

/// 人类可读的时长（秒/分/时/天）
fn fmt_duration(secs: f64) -> String {
    if secs < 60.0 {
        format!("{:.0} 秒", secs)
    } else if secs < 3600.0 {
        format!("{:.1} 分钟", secs / 60.0)
    } else if secs < 86_400.0 {
        format!("{:.1} 小时", secs / 3600.0)
    } else if secs < 86_400.0 * 365.0 {
        format!("{:.1} 天", secs / 86_400.0)
    } else {
        format!("{:.1} 年", secs / (86_400.0 * 365.0))
    }
}
