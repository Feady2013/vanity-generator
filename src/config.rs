//! config.rs —— config.yaml 的解析与严格校验
//!
//! 配置来源优先级：
//! 1. CLI `--config <FILE>` 指定的文件；
//! 2. 环境变量 `VANITY_CONFIG`（config.yaml 的完整内容，适合 CI/容器场景）；
//! 3. 可执行文件同目录的 `config.yaml`。
//!
//! GPG 公钥来源优先级：
//! 1. 环境变量 `VANITY_GPG_KEY`（ASCII armor 公钥的完整内容）；
//! 2. `gpg_key_file` 字段指定的文件（相对可执行文件目录，后缀名不限）。
//!
//! 校验规则（全部为 fatal error）：
//! - `word_count` 只允许 12 / 18 / 24；
//! - `front` / `middle` / `back` 至少定义一个，取值只能含 [0-9a-fA-F]，
//!   可带 `0x` 前缀（解析时归一化），front 与 back 总长 ≤ 40；
//! - `case_sensitive` 可选布尔（默认 false）：true 时按 EIP-55 校验和形式匹配；
//! - `progress_every`：数字（每 N 次尝试输出一次进度）或 false（禁用）；
//! - `path` 必须以 `m/` 开头，每层为合法 hardened（`'`/`h`/`H`）或 normal 索引；
//! - `count` 介于 1..=1000；
//! - 公钥必须可读且首行以 `-----BEGIN PGP PUBLIC KEY BLOCK-----` 开头；
//! - 任何字段类型错误同样是 fatal error。
//!
//! 错误信息只引用字段名与当前非法取值（规格示例风格），不回显整个文件。

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::VanityError;

/// 支持的助记词词数（BIP39：词数 ↔ 熵长）
pub const VALID_WORD_COUNTS: [u64; 3] = [12, 18, 24];

/// 默认 BIP32 派生路径（与 MetaMask 行为对齐）
pub const DEFAULT_PATH: &str = "m/44'/60'/0'/0/0";

/// 配置内容环境变量名
pub const ENV_CONFIG: &str = "VANITY_CONFIG";

/// GPG 公钥内容环境变量名
pub const ENV_GPG_KEY: &str = "VANITY_GPG_KEY";

/// GPG 公钥 ASCII armor 首行标记
const ARMOR_HEADER: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";

/// 地址 hex 长度（去掉 0x 后）
const ADDR_HEX_LEN: usize = 40;

/// front 与 back 的总长度上限
const FRONT_BACK_TOTAL_MAX: usize = 40;

/// count 取值范围
const COUNT_MIN: u64 = 1;
const COUNT_MAX: u64 = 1000;

/// BIP32 单层索引上限（2^31 - 1）
const BIP32_INDEX_MAX: u32 = 2_147_483_647;

/// 进度通知配置：数字 = 每 N 次尝试输出一次；false = 禁用
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ProgressEvery {
    /// false 显式禁用；true 无意义（报错）
    Disabled(bool),
    /// 每 N 次尝试通知一次
    Every(u64),
}

/// serde 反序列化的原始结构（类型即第一道校验）
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    word_count: u64,
    front: Option<String>,
    middle: Option<String>,
    back: Option<String>,
    case_sensitive: Option<bool>,
    progress_every: Option<ProgressEvery>,
    path: Option<String>,
    count: u64,
    gpg_key_file: Option<String>,
    /// 自定义工作线程数（1..=1024）；未定义时按 CPU 逻辑核心数自动分配
    threads: Option<u32>,
    /// 每个助记词派生的地址数（1..=1000，BIP32 末层连续索引）
    derive_batch: Option<u32>,
}

/// 校验完成后的最终配置（所有字段已归一化）
#[derive(Debug, Clone)]
pub struct Config {
    /// 助记词词数：12 / 18 / 24
    pub word_count: u8,
    /// 前缀 needle（已按大小写敏感语义归一：敏感=原样，不敏感=小写）
    pub front: Option<Vec<u8>>,
    /// 中缀 needle
    pub middle: Option<Vec<u8>>,
    /// 后缀 needle
    pub back: Option<Vec<u8>>,
    /// 是否大小写敏感（true 时按 EIP-55 校验和形式匹配）
    pub case_sensitive: bool,
    /// 每 N 次尝试输出一次进度；None = 禁用
    pub progress_every: Option<u64>,
    /// 原样保留的派生路径字符串（已验证合法性）
    pub path: String,
    /// 解析后的派生索引（hardened 位已置位）
    pub path_indices: Vec<u32>,
    /// 目标命中数量
    pub count: u32,
    /// 自定义工作线程数（1..=1024）；None = 按 CPU 逻辑核心数自动分配
    pub threads: Option<u32>,
    /// 每个助记词派生的地址数（默认 1 = 每地址独立助记词）
    pub derive_batch: u32,
    /// 输出目录：跟随 config.yaml 所在目录（env 注入时 = exe 目录）
    pub output_dir: PathBuf,
    /// GPG 公钥文件路径（env 提供时为 None）
    pub gpg_key_path: Option<PathBuf>,
    /// GPG 公钥内联内容（env 提供时为 Some）
    pub gpg_key_inline: Option<String>,
}

impl Config {
    /// 按优先级加载配置：CLI 路径 > `VANITY_CONFIG` 环境变量 > exe 同目录 config.yaml。
    /// `gpg_env` 为 `VANITY_GPG_KEY` 的内容（调用方读取环境变量后传入，便于测试）。
    pub fn load(cli_path: Option<&Path>, exe_dir: &Path, gpg_env: Option<&str>) -> Result<Self, VanityError> {
        let (text, source, cfg_dir) = match cli_path {
            Some(p) => (
                fs::read_to_string(p).map_err(|e| VanityError::config(
                    format!("failed to read config file {}: {e}. Please check the path and permissions.", p.display()),
                    format!("读取配置文件 {} 失败：{e}。请检查路径与读取权限。", p.display()),
                ))?,
                format!("文件 {}", p.display()),
                // 配置文件所在目录：输出与相对公钥路径的基准
                p.parent().filter(|d| !d.as_os_str().is_empty()).map_or_else(
                    || PathBuf::from("."),
                    |d| d.to_path_buf(),
                ),
            ),
            None => match std::env::var(ENV_CONFIG) {
                Ok(v) if !v.trim().is_empty() => (v, format!("环境变量 {ENV_CONFIG}"), exe_dir.to_path_buf()),
                _ => {
                    let p = exe_dir.join("config.yaml");
                    (
                        fs::read_to_string(&p).map_err(|_| VanityError::config(
                            format!(
                                "config.yaml not found next to the executable ({}). \
                                 Please create it (see config.example.yaml), pass --config <FILE>, \
                                 or set the {ENV_CONFIG} environment variable with the YAML content.",
                                p.display()
                            ),
                            format!(
                                "在可执行文件同目录（{}）未找到 config.yaml。请创建该文件（参考 config.example.yaml），\
                                 或通过 --config <FILE> 指定路径，或用 {ENV_CONFIG} 环境变量直接传入 YAML 内容。",
                                p.display()
                            ),
                        ))?,
                        format!("文件 {}", p.display()),
                        exe_dir.to_path_buf(),
                    )
                }
            },
        };
        Self::parse_and_validate(&text, &cfg_dir, gpg_env).map_err(|e| {
            // 附带配置来源，帮助用户定位（不回显内容）
            VanityError::config(
                format!("config source: {source}. {}", e.en),
                format!("配置来源：{source}。{}", e.cn),
            )
        })
    }

    /// 解析并校验 YAML 文本；`gpg_env` 为环境变量传入的公钥内容（可为 None）。
    pub fn parse_and_validate(
        text: &str,
        base_dir: &Path,
        gpg_env: Option<&str>,
    ) -> Result<Self, VanityError> {
        let raw: RawConfig = serde_yaml::from_str(text).map_err(|e| VanityError::config(
            format!("failed to parse config.yaml: {e}. Please fix the YAML syntax and field types, then restart."),
            format!("解析 config.yaml 失败：{e}。请修正 YAML 语法与字段类型后重新运行。"),
        ))?;

        // 1. word_count
        if !VALID_WORD_COUNTS.contains(&raw.word_count) {
            return Err(VanityError::config(
                format!(
                    "word_count must be one of [12, 18, 24], got \"{}\". \
                     Please edit config.yaml and restart.",
                    raw.word_count
                ),
                format!(
                    "word_count 只能为 [12, 18, 24] 其中之一，当前为 \"{}\"。\
                     请修改 config.yaml 后重新运行。",
                    raw.word_count
                ),
            ));
        }

        // 2. 靓号字段：归一化 + 字符校验（大小写敏感语义在 matcher 层处理）
        let case_sensitive = raw.case_sensitive.unwrap_or(false);
        let normalize = |field: &'static str, raw: Option<&String>| -> Result<Option<Vec<u8>>, VanityError> {
            match raw {
                None => Ok(None),
                Some(s) => normalize_vanity(field, s, case_sensitive).map(Some),
            }
        };
        let front = normalize("front", raw.front.as_ref())?;
        let middle = normalize("middle", raw.middle.as_ref())?;
        let back = normalize("back", raw.back.as_ref())?;

        if front.is_none() && middle.is_none() && back.is_none() {
            return Err(VanityError::config(
                "at least one of front/middle/back must be defined in config.yaml. Please add \
                 a vanity rule and restart.",
                "config.yaml 中 front/middle/back 至少需要定义一个。请添加靓号规则后重新运行。",
            ));
        }

        // 3. 前后缀总长度 ≤ 40（去掉 0x 后）
        let total = front.as_ref().map_or(0, Vec::len) + back.as_ref().map_or(0, Vec::len);
        if total > FRONT_BACK_TOTAL_MAX {
            return Err(VanityError::config(
                format!(
                    "total length of front + back must not exceed {FRONT_BACK_TOTAL_MAX} hex \
                     chars, got {total}. Please shorten the prefix/suffix."
                ),
                format!(
                    "front 与 back 的总长度不能超过 {FRONT_BACK_TOTAL_MAX} 个 hex 字符，当前为 \
                     {total}。请缩短前后缀。"
                ),
            ));
        }

        // middle 单独兜底：超过 40 必然无法命中
        if middle.as_ref().is_some_and(|m| m.len() > ADDR_HEX_LEN) {
            return Err(VanityError::config(
                format!(
                    "middle must not exceed {ADDR_HEX_LEN} hex chars; a longer substring can \
                     never match an address. Please shorten it."
                ),
                format!(
                    "middle 不能超过 {ADDR_HEX_LEN} 个 hex 字符，超长的子串永远无法命中地址。请缩短。"
                ),
            ));
        }

        // 4. progress_every 语义校验
        let progress_every = match raw.progress_every {
            None | Some(ProgressEvery::Disabled(false)) => None,
            Some(ProgressEvery::Disabled(true)) => {
                return Err(VanityError::config(
                    "progress_every: true is meaningless. Set a positive number of attempts \
                     per progress line, or false to disable.",
                    "progress_every: true 没有意义。请填写每次进度通知的尝试次数（正整数），\
                     或填 false 禁用。",
                ));
            }
            Some(ProgressEvery::Every(0)) => {
                return Err(VanityError::config(
                    "progress_every must be a positive integer (got 0). Zero would never (or \
                     always) trigger; use false to disable instead.",
                    "progress_every 必须为正整数（当前为 0）。0 会导致取模判断无意义；\
                     如需禁用请填 false。",
                ));
            }
            Some(ProgressEvery::Every(n)) => Some(n),
        };

        // 5. path
        let path = raw.path.as_deref().unwrap_or(DEFAULT_PATH).trim().to_string();
        let path_indices = parse_path(&path)?;

        // 6. count
        if !(COUNT_MIN..=COUNT_MAX).contains(&raw.count) {
            return Err(VanityError::config(
                format!(
                    "count must be between {COUNT_MIN} and {COUNT_MAX}, got \"{}\". \
                     Please edit config.yaml and restart.",
                    raw.count
                ),
                format!(
                    "count 必须介于 {COUNT_MIN} 到 {COUNT_MAX} 之间，当前为 \"{}\"。\
                     请修改 config.yaml 后重新运行。",
                    raw.count
                ),
            ));
        }

        // 7. GPG 公钥来源：环境变量优先，其次 gpg_key_file 文件
        let (gpg_key_path, gpg_key_inline) = match gpg_env {
            Some(content) if !content.trim().is_empty() => {
                validate_armor_first_line(
                    content.lines().next().unwrap_or(""),
                    &format!("{ENV_GPG_KEY} 环境变量"),
                )?;
                (None, Some(content.to_string()))
            }
            _ => match raw.gpg_key_file.as_deref() {
                Some(name) if !name.trim().is_empty() => {
                    let p = resolve_path(base_dir, name);
                    let content = fs::read_to_string(&p).map_err(|_| VanityError::config(
                        format!(
                            "cannot read gpg_key_file \"{name}\" at {}. Please put the public \
                             key file next to the executable and check the filename.",
                            p.display()
                        ),
                        format!(
                            "无法读取 gpg_key_file \"{name}\"（路径 {}）。请将公钥文件放在\
                             可执行文件同目录并核对文件名。",
                            p.display()
                        ),
                    ))?;
                    validate_armor_first_line(
                        content.lines().next().unwrap_or(""),
                        &format!("gpg_key_file \"{name}\""),
                    )?;
                    (Some(p), None)
                }
                _ => {
                    return Err(VanityError::config(
                        format!(
                            "no GPG public key source: set gpg_key_file in config.yaml or \
                             provide the armored public key via the {ENV_GPG_KEY} environment \
                             variable."
                        ),
                        format!(
                            "未提供 GPG 公钥：请在 config.yaml 中填写 gpg_key_file，\
                             或通过 {ENV_GPG_KEY} 环境变量直接传入 armor 公钥内容。"
                        ),
                    ));
                }
            },
        };

        // 8. derive_batch：每助记词派生地址数（1..=1000；>1 需路径含索引）
        let derive_batch = match raw.derive_batch {
            None | Some(1) => 1,
            Some(b) if !(2..=1000).contains(&b) => {
                return Err(VanityError::config(
                    format!(
                        "derive_batch must be between 1 and 1000, got {b}. \
                         Use 1 for an independent mnemonic per address (default)."
                    ),
                    format!(
                        "derive_batch 必须介于 1 到 1000 之间，当前为 {b}。\
                         默认 1 = 每个地址独立助记词。"
                    ),
                ));
            }
            Some(b) => b,
        };

        // 8.5 批派生需要路径含末层索引
        if derive_batch > 1 && path_indices.is_empty() {
            return Err(VanityError::config(
                "derive_batch > 1 requires the derivation path to contain at least one index \
                 (e.g. m/44'/60'/0'/0/0); the last level is expanded per address.",
                "derive_batch > 1 要求派生路径至少含一层索引（如 m/44'/60'/0'/0/0），\
                 末层索引将按 0,1,2… 连续派生。",
            ));
        }

        // 9. threads：可选工作线程数（1..=1024）
        if let Some(t) = raw.threads {
            if !(1..=1024).contains(&t) {
                return Err(VanityError::config(
                    format!(
                        "threads must be between 1 and 1024, got {t}. \
                         Leave it undefined to auto-match the CPU's logical core count."
                    ),
                    format!(
                        "threads 必须介于 1 到 1024 之间，当前为 {t}。\
                         不填则自动按 CPU 逻辑核心数分配。"
                    ),
                ));
            }
        }
        let threads = raw.threads;

        Ok(Self {
            word_count: raw.word_count as u8,
            front,
            middle,
            back,
            case_sensitive,
            progress_every,
            path,
            path_indices,
            count: raw.count as u32,
            gpg_key_path,
            gpg_key_inline,
            threads,
            derive_batch,
            output_dir: base_dir.to_path_buf(),
        })
    }
}

/// 归一化靓号字段：去掉 0x 前缀、校验 hex 字符；不敏感时转小写，敏感时保留原样
fn normalize_vanity(field: &'static str, raw: &str, case_sensitive: bool) -> Result<Vec<u8>, VanityError> {
    let s = raw.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.is_empty() {
        return Err(VanityError::config(
            format!(
                "{field} must not be empty. Remove the field if you do not want it to \
                 constrain matching."
            ),
            format!("{field} 不能为空。若不希望该字段参与匹配，请直接删除该字段。"),
        ));
    }
    if let Some(c) = s.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(VanityError::config(
            format!(
                "{field} may only contain hex characters [0-9a-fA-F]; found '{c}'. \
                 Please fix it and restart."
            ),
            format!(
                "{field} 只能包含 [0-9a-fA-F] 十六进制字符，发现非法字符 '{c}'。请修正后重新运行。"
            ),
        ));
    }
    Ok(if case_sensitive {
        s.as_bytes().to_vec()
    } else {
        s.to_ascii_lowercase().into_bytes()
    })
}

/// 解析 BIP32 派生路径，返回逐层索引（hardened 已置高位）。
/// 合法形式：`m/` 前缀 + 若干层 `数字` 或 `数字'`/`数字h`/`数字H`。
/// `m/`（仅主密钥，零层派生）视为合法。
fn parse_path(path: &str) -> Result<Vec<u32>, VanityError> {
    if !path.starts_with("m/") {
        return Err(VanityError::config(
            "path must start with \"m/\". Please use a standard form such as \
             \"m/44'/60'/0'/0/0\".",
            "path 必须以 \"m/\" 开头。请使用如 \"m/44'/60'/0'/0/0\" 的标准写法。",
        ));
    }
    let rest = &path["m/".len()..];
    if rest.is_empty() {
        // 仅主密钥：seed 直接派生 XPrv，零层派生（合法边界）
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(8);
    for seg in rest.split('/') {
        if seg.is_empty() {
            return Err(VanityError::config(
                "path contains an empty segment (\"//\"). Please check each level, e.g. \
                 \"m/44'/60'/0'/0/0\".",
                "path 中存在空层级（\"//\"）。请检查每一层写法，例如 \"m/44'/60'/0'/0/0\"。",
            ));
        }
        // hardened 标记：' / h / H
        let (num_str, hardened) = match seg.as_bytes()[seg.len() - 1] {
            b'\'' | b'h' | b'H' => (&seg[..seg.len() - 1], true),
            _ => (seg, false),
        };
        if num_str.is_empty() || !num_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(VanityError::config(
                format!(
                    "path segment \"{seg}\" is not a valid child index. Use digits optionally \
                     followed by ' or h, e.g. 44' or 0."
                ),
                format!(
                    "path 层级 \"{seg}\" 不是合法的子索引。应为纯数字并可带 ' 或 h 后缀，如 44' 或 0。"
                ),
            ));
        }
        // 数值解析（防溢出：先 u64 再判界）
        let num: u64 = num_str.parse().map_err(|_| {
            VanityError::config(
                format!("path index \"{num_str}\" is too large to parse. Please lower the index."),
                format!("path 索引 \"{num_str}\" 数值过大无法解析。请调小索引值。"),
            )
        })?;
        if num > BIP32_INDEX_MAX as u64 {
            return Err(VanityError::config(
                format!(
                    "path index {num} exceeds the BIP32 limit {BIP32_INDEX_MAX}. Please lower \
                     the index."
                ),
                format!("path 索引 {num} 超出 BIP32 上限 {BIP32_INDEX_MAX}。请调小索引值。"),
            ));
        }
        out.push(num as u32 | (u32::from(hardened) * 0x8000_0000));
    }
    Ok(out)
}

/// 解析 gpg_key_file：绝对路径原样，相对路径基于 base_dir
fn resolve_path(base: &Path, name: &str) -> PathBuf {
    let p = Path::new(name);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

/// 校验 armor 首行标记（来源描述用于错误信息：文件路径或环境变量名）
fn validate_armor_first_line(first_line: &str, source: &str) -> Result<(), VanityError> {
    let first = first_line.trim_start_matches('\u{feff}').trim();
    if !first.starts_with(ARMOR_HEADER) {
        return Err(VanityError::config(
            format!(
                "the first line of {source} must start with \"{ARMOR_HEADER}\". Make sure it \
                 is an ASCII-armored OpenPGP public key exported by GnuPG (any file extension \
                 is fine)."
            ),
            format!(
                "{source} 的首行必须以 \"{ARMOR_HEADER}\" 开头。请确认是 GnuPG 导出的 \
                 ASCII armor 公钥（后缀名不限）。"
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试基目录：仓库根（用于解析 tests/fixtures/fx1024.asc）
    fn base() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn key_yaml() -> String {
        String::from(
            "word_count: 24\nfront: \"0x8888\"\nback: \"8888\"\npath: \"m/44'/60'/0'/0/0\"\n\
             count: 5\ngpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        )
    }

    /// 替换 yaml 中的某个字段值，快速构造非法样例
    fn yaml_with(field: &str, value: &str) -> String {
        let mut yaml = key_yaml();
        if field == "path" {
            // 默认样例里有 path 行，整行替换
            let lines: Vec<String> = yaml
                .lines()
                .map(|l| {
                    if l.starts_with("path:") {
                        format!("path: {value}")
                    } else {
                        l.to_string()
                    }
                })
                .collect();
            yaml = lines.join("\n");
        } else {
            yaml.push_str(&format!("{field}: {value}\n"));
        }
        yaml
    }

    #[test]
    fn 合法配置_完整样例() {
        let cfg = Config::parse_and_validate(&key_yaml(), &base(), None).unwrap();
        assert_eq!(cfg.word_count, 24);
        assert_eq!(cfg.front.as_deref(), Some(&b"8888"[..]));
        assert_eq!(cfg.back.as_deref(), Some(&b"8888"[..]));
        assert!(cfg.middle.is_none());
        assert_eq!(cfg.path, "m/44'/60'/0'/0/0");
        assert_eq!(
            cfg.path_indices,
            vec![0x8000_002C, 0x8000_003C, 0x8000_0000, 0, 0]
        );
        assert_eq!(cfg.count, 5);
        assert!(cfg.gpg_key_path.unwrap().ends_with("tests/fixtures/fx1024.asc"));
        assert!(!cfg.case_sensitive);
        assert!(cfg.progress_every.is_none());
    }

    #[test]
    fn 合法配置_12_18_24_词数全路径() {
        for wc in [12u64, 18, 24] {
            let yaml = format!(
                "word_count: {wc}\nfront: \"ab\"\ncount: 1\n\
                 gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
            );
            let cfg = Config::parse_and_validate(&yaml, &base(), None).unwrap();
            assert_eq!(cfg.word_count as u64, wc);
        }
    }

    #[test]
    fn word_count_非法_13() {
        let yaml = String::from(
            "word_count: 13\nfront: \"ab\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
        assert!(err.en.contains("word_count must be one of [12, 18, 24], got \"13\""));
        assert!(err.cn.contains("当前为 \"13\""));
        assert!(err.en.contains("Please edit config.yaml"));
    }

    #[test]
    fn word_count_类型错误_字符串() {
        let yaml = String::from(
            "word_count: \"24\"\nfront: \"ab\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
        assert!(err.en.contains("failed to parse config.yaml"));
        assert!(err.cn.contains("解析 config.yaml 失败"));
    }

    #[test]
    fn front_非法字符_0xgggg() {
        let yaml = String::from(
            "word_count: 12\nfront: \"0xGGGG\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
        assert!(err.en.contains("front may only contain hex characters"));
        assert!(err.cn.contains("发现非法字符"));
    }

    #[test]
    fn front_为空字符串() {
        let yaml = String::from(
            "word_count: 12\nfront: \"\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
        assert!(err.en.contains("front must not be empty"));
    }

    #[test]
    fn 靓号字段_全部缺失() {
        let yaml = String::from(
            "word_count: 12\ncount: 1\ngpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
        assert!(err.en.contains("at least one of front/middle/back"));
        assert!(err.cn.contains("至少需要定义一个"));
    }

    #[test]
    fn 前后缀总长超限_41() {
        let yaml = format!(
            "word_count: 12\nfront: \"{}\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n",
            "a".repeat(41)
        );
        let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
        assert!(err.en.contains("must not exceed 40 hex chars, got 41"));
    }

    #[test]
    fn 前后缀总长边界_40_合法() {
        let yaml = format!(
            "word_count: 12\nfront: \"{}\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n",
            "a".repeat(40)
        );
        let cfg = Config::parse_and_validate(&yaml, &base(), None).unwrap();
        assert_eq!(cfg.front.unwrap().len(), 40);
    }

    #[test]
    fn middle_超长_报错() {
        let yaml = format!(
            "word_count: 12\nmiddle: \"{}\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n",
            "b".repeat(41)
        );
        let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
        assert!(err.en.contains("middle must not exceed 40"));
    }

    #[test]
    fn path_缺省_默认路径生效() {
        let yaml = String::from(
            "word_count: 12\nfront: \"ab\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let cfg = Config::parse_and_validate(&yaml, &base(), None).unwrap();
        assert_eq!(cfg.path, DEFAULT_PATH);
        assert_eq!(cfg.path_indices.len(), 5);
    }

    #[test]
    fn path_合法变体() {
        for (p, expect_last) in [
            ("m/44'/60'/0'/0/217", 217u32),
            ("m/44h/60H/0'/0/0", 0),
            ("m/44'/60'/0'/0/2147483647", 2_147_483_647),
        ] {
            let yaml = yaml_with("path", &format!("\"{p}\""));
            let cfg = Config::parse_and_validate(&yaml, &base(), None).unwrap();
            assert_eq!(*cfg.path_indices.last().unwrap(), expect_last);
        }
    }

    #[test]
    fn path_空层级_报错() {
        let yaml = yaml_with("path", "\"m//44'\"");
        let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
        assert!(err.en.contains("empty segment"));
        assert!(err.cn.contains("空层级"));
    }

    #[test]
    fn path_缺_m前缀_报错() {
        let yaml = yaml_with("path", "\"44'/60'\"");
        let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
        assert!(err.en.contains("must start with \"m/\""));
    }

    #[test]
    fn path_索引超限_报错() {
        let yaml = yaml_with("path", "\"m/44'/60'/0'/0/2147483648\"");
        let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
        assert!(err.en.contains("exceeds the BIP32 limit"));
    }

    #[test]
    fn path_仅主密钥_合法() {
        let yaml = yaml_with("path", "\"m/\"");
        let cfg = Config::parse_and_validate(&yaml, &base(), None).unwrap();
        assert!(cfg.path_indices.is_empty());
    }

    #[test]
    fn count_越界_0_与_1001() {
        for bad in [0u64, 1001] {
            let yaml = format!(
                "word_count: 12\nfront: \"ab\"\ncount: {bad}\n\
                 gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
            );
            let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
            assert!(err.en.contains("count must be between 1 and 1000"));
        }
    }

    #[test]
    fn count_边界_1_与_1000_合法() {
        for good in [1u64, 1000] {
            let yaml = format!(
                "word_count: 12\nfront: \"ab\"\ncount: {good}\n\
                 gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
            );
            let cfg = Config::parse_and_validate(&yaml, &base(), None).unwrap();
            assert_eq!(cfg.count as u64, good);
        }
    }

    /// derive_batch：默认/边界/非法值/路径要求
    #[test]
    fn derive_batch_校验() {
        let base_yaml = |b: &str| {
            format!(
                "word_count: 12\nfront: \"ab\"\ncount: 1\nderive_batch: {b}\n\
                 gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
            )
        };
        // 默认未定义 = 1
        let cfg = Config::parse_and_validate(&base_yaml("x").replace("derive_batch: x\n", ""), &base(), None).unwrap();
        assert_eq!(cfg.derive_batch, 1);
        // 合法：1 与 1000
        for good in ["1", "1000"] {
            let cfg = Config::parse_and_validate(&base_yaml(good), &base(), None).unwrap();
            assert_eq!(cfg.derive_batch, good.parse::<u32>().unwrap());
        }
        // 非法：0 与 1001
        for bad in ["0", "1001"] {
            let err = Config::parse_and_validate(&base_yaml(bad), &base(), None).unwrap_err();
            assert!(err.en.contains("derive_batch must be between"));
        }
    }

    /// threads 自定义线程数：边界与非法值
    #[test]
    fn threads_边界与非法值() {
        // 合法边界：1 与 1024
        for good in [1u32, 1024] {
            let yaml = format!(
                "word_count: 12\nfront: \"ab\"\ncount: 1\nthreads: {good}\n\
                 gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
            );
            let cfg = Config::parse_and_validate(&yaml, &base(), None).unwrap();
            assert_eq!(cfg.threads, Some(good));
        }
        // 非法：0 与 1025
        for bad in [0u32, 1025] {
            let yaml = format!(
                "word_count: 12\nfront: \"ab\"\ncount: 1\nthreads: {bad}\n\
                 gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
            );
            let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
            assert!(
                err.en.contains("threads must be between 1 and 1024"),
                "应包含英文错误说明：{}",
                err.en
            );
        }
        // 未定义：默认 None（自动分配）
        let yaml = String::from(
            "word_count: 12\nfront: \"ab\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n",
        );
        let cfg = Config::parse_and_validate(&yaml, &base(), None).unwrap();
        assert_eq!(cfg.threads, None);
    }

    #[test]
    fn gpg_文件不存在() {
        let yaml = String::from(
            "word_count: 12\nfront: \"ab\"\ncount: 1\n\
             gpg_key_file: \"definitely_missing_key.asc\"\n"
        );
        let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
        assert!(err.en.contains("cannot read gpg_key_file \"definitely_missing_key.asc\""));
        assert!(err.cn.contains("无法读取 gpg_key_file"));
    }

    #[test]
    fn gpg_首行不是_armor_头() {
        let bad = std::env::temp_dir().join(format!("vanity_bad_key_{}.txt", std::process::id()));
        std::fs::write(&bad, "hello not a pgp key\nsecond line\n").unwrap();
        let yaml = format!(
            "word_count: 12\nfront: \"ab\"\ncount: 1\ngpg_key_file: \"{}\"\n",
            bad.display()
        );
        let err = Config::parse_and_validate(&yaml, Path::new("/"), None).unwrap_err();
        assert!(err.en.contains(ARMOR_HEADER));
        let _ = std::fs::remove_file(&bad);
    }

    #[test]
    fn gpg_环境变量_优先于文件() {
        let yaml = key_yaml();
        let cfg =
            Config::parse_and_validate(&yaml, &base(), Some("-----BEGIN PGP PUBLIC KEY BLOCK-----\nxxx"))
                .unwrap();
        assert!(cfg.gpg_key_path.is_none());
        assert!(cfg.gpg_key_inline.is_some());
    }

    #[test]
    fn gpg_环境变量_首行非法_报错() {
        let err = Config::parse_and_validate(&key_yaml(), &base(), Some("not armor")).unwrap_err();
        assert!(err.en.contains(ARMOR_HEADER));
    }

    #[test]
    fn gpg_无任何来源_报错() {
        let yaml = String::from("word_count: 12\nfront: \"ab\"\ncount: 1\n");
        let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
        assert!(err.en.contains("no GPG public key source"));
        assert!(err.cn.contains("未提供 GPG 公钥"));
    }

    #[test]
    fn 大小写敏感_保留原样_不敏感_转小写() {
        let yaml = String::from(
            "word_count: 12\nfront: \"AaBb\"\ncase_sensitive: true\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let cfg = Config::parse_and_validate(&yaml, &base(), None).unwrap();
        assert!(cfg.case_sensitive);
        assert_eq!(cfg.front.as_deref(), Some(&b"AaBb"[..]));

        let yaml = String::from(
            "word_count: 12\nfront: \"AaBb\"\ncase_sensitive: false\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let cfg = Config::parse_and_validate(&yaml, &base(), None).unwrap();
        assert_eq!(cfg.front.as_deref(), Some(&b"aabb"[..]));
    }

    #[test]
    fn 大小写敏感_类型错误_报错() {
        let yaml = String::from(
            "word_count: 12\nfront: \"ab\"\ncase_sensitive: \"yes\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
        assert!(err.en.contains("failed to parse config.yaml"));
    }

    #[test]
    fn progress_every_语义() {
        // 数字合法
        let yaml = String::from(
            "word_count: 12\nfront: \"ab\"\nprogress_every: 1000\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let cfg = Config::parse_and_validate(&yaml, &base(), None).unwrap();
        assert_eq!(cfg.progress_every, Some(1000));

        // false 禁用
        let yaml = String::from(
            "word_count: 12\nfront: \"ab\"\nprogress_every: false\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let cfg = Config::parse_and_validate(&yaml, &base(), None).unwrap();
        assert!(cfg.progress_every.is_none());

        // true 无意义
        let yaml = String::from(
            "word_count: 12\nfront: \"ab\"\nprogress_every: true\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
        assert!(err.en.contains("progress_every: true is meaningless"));

        // 0 非法
        let yaml = String::from(
            "word_count: 12\nfront: \"ab\"\nprogress_every: 0\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
        assert!(err.en.contains("must be a positive integer"));
    }

    #[test]
    fn 未知字段_报错() {
        let yaml = String::from(
            "word_count: 12\nfront: \"ab\"\ncount: 1\nunknown_field: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let err = Config::parse_and_validate(&yaml, &base(), None).unwrap_err();
        assert!(err.en.contains("failed to parse config.yaml"));
    }

    #[test]
    fn 必填字段缺失() {
        for missing in ["word_count", "count"] {
            let yaml = key_yaml()
                .lines()
                .filter(|l| !l.starts_with(missing))
                .collect::<Vec<_>>()
                .join("\n");
            let err = Config::parse_and_validate(&format!("{yaml}\n"), &base(), None).unwrap_err();
            assert!(err.en.contains("failed to parse config.yaml"));
        }
    }
}
