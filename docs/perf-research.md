# 性能文章研读与采纳审核

> 依据项目规约：内容合理、科学、可复现、不引入冲突、原理可解释者才可采纳；
> 一切优化以安全为绝对前提，A/B 收益 < 2% 即回滚。本文件记录研读结论与采纳决策。

## 1. Itamar Turner-Trauring《更快六倍的二分搜索》
（pythonspeed.com/articles/branchless-binary-search，现题为 "8× faster binary search: from compiled code to mechanical sympathy"；早期版本即用户所指"六倍"）

**核心原理**（均可复现、原理清晰）：
- 二分搜索瓶颈不在比较次数而在**分支预测失败**（每次预测错误 ≈ 15-20 周期流水线冲刷）与**缓存行跳跃**（对数级访存看似少，但每次都落在新缓存行）。
- 方案：branchless 条件移动（cmov）、**Eytzinger（BFS 布局）数组**让连续访问落在相邻缓存行 + **软件预取**（prefetch 指令提前数层取数）。
- "mechanical sympathy"：为硬件执行模型（超标量、预取器、缓存层级）设计数据布局，而非为人类直觉设计。

**对本项目的审核结论：不采纳（无适用点），原理已吸收。**
- 热路径无二分搜索：BIP39 词表查找是 **11-bit 直接索引**（O(1)）；地址匹配用 memchr 的 SIMD 子串搜索。
- 排序数组建过：无。如果未来引入"已知地址去重表"或"前缀字典树"再重新评估此文章方案。
- 已应用的同族思想：匹配器 memmem 预构建（避免热循环重建）、进度计数 relaxed ordering。

## 2. Sylvain Kerkour《High-performance Rust: Understanding and eliminating heap fragmentation》（2026-07-01，kerkour.com）
（作者同期正在为 Rust 扩展标准库 stdx 实现 TLS——与用户描述一致）

**核心原理**（附可复现代码）：
- 长时运行 + 高频小分配 → 堆**碎片化**：RSS 高位 plateau（作者服务 75% 内存无法回收）。
- 治标：全局换成 jemalloc/mimalloc（两行 `#[global_allocator]`，内存减半）。
- 治本：**减少分配**——`heapless`（定容栈分配 Vec/String/Map）、`smallvec`（小容量栈内联）、`bytes`（引用计数切片）、arena 池化；no_std 嵌入式（<500KB RAM）的彻底零堆路线。

**对本项目的审核结论：部分采纳（"减少分配"原则），分配器替换不采纳。**
- 本进程是**短生命周期 CLI**（分钟级）而非常驻服务，RSS 峰值 ~15-20MB（实测见 docs/memory.md），碎片化 plateau 不构成风险。
- jemalloc/mimalloc 是 **C/C++ 依赖**：与"全依赖树纯 Rust + 任意目标交叉编译无 C 工具链"冲突（该属性刚为 aarch64-musl 发布立功），且在每秒数百次分配的量级下无收益可言。→ 拒绝。
- 采纳其"热路径减分配"思想：对每次尝试的助记词字符串构建做**缓冲复用**（见 A/B 记录：实验后收益 <2%，按规约回滚/不合并——最终以实测为准，记录于 docs/performance.md 增补）。
- `heapless` 引入决策：拒绝。公共 API 与错误处理路径不因此复杂化，且无 no_std 需求。

## 3. Sylvain Kerkour《Investigating why RustCrypto is slow: Deep dive into SIMD》（2026-07-08，kerkour.com）

**核心原理**：
- RustCrypto 哈希在部分后端慢的根因：portable 实现未向量化、SIMD 寄存器数量与目标 ISA（AVX2 8×32-bit lane / NEON 32×128-bit）需针对性展开。
- 纯 Rust SIMD 的正道是 `portable_simd`（`std::simd`）——**仍为 nightly-only**。
- 建议按目标硬件选型：消费级主战场是 AVX2+NEON，别再写 SSE2。

**对本项目的审核结论：不采纳（nightly 依赖违反稳定发布原则）。**
- 项目交付 stable Rust（三平台 Release 均在 stable 工具链），引入 nightly-only 特性直接冲突。
- 热路径 77% 耗时在 PBKDF2 的 2048×HMAC-SHA512——**BIP39 规定的协议固有成本**，任何"优化"不得改变迭代次数与构造（安全红线）。
- sha2 的 asm 后门（x86 SHA 扩展）此前已 A/B 实测 0% 收益并回滚（见 docs/performance.md）；memchr 的 SIMD 子串搜索已是现成权威实现。

## 4. 其他核查过的来源
- **algorithmica.org/en/eytzinger**：Eytzinger 布局的系统化分析与基准（支持来源 1 的原理复核）。
- **Rust Performance Book**（Blandy & Orendorff）：release profile、边界检查、分配减量等通用清单——本项目发布前已逐项核对（opt-level=3 + LTO + codegen-units=1）。
- **criterion 基准纪律**：全部性能主张须 A/B + 噪声控制（含本仓库 benches/，门禁 2%）。
- **memchr / memmem**：多项目验证的 SIMD 搜索权威库（ripgrep 等采用），已在匹配器使用。

## 总结表

| 来源 | 原理 | 可复现 | 冲突 | 决策 |
|---|---|---|---|---|
| Itamar 二分搜索 | 分支预测+缓存布局 | ✓ | 无适用点 | 不采纳，原理存档 |
| Kerkour 碎片文 | 碎片成因+减分配 | ✓ | 分配器=C 依赖 | 采纳"减分配"实验；分配器拒绝 |
| Kerkour SIMD 文 | 向量化路径 | ✓ | nightly-only | 不采纳 |
| algorithmica / perf book / criterion | 通用 | ✓ | 无 | 已在用 |

## 5. 视频笔记技法消化（2026-09-28 用户提供的 7 份转录笔记）

| 笔记 | 核心技法 | 本项目适用性审核 |
|---|---|---|
| SIMD 矩阵乘法 | Strassen、打包乘加 | 无矩阵负载；keccak/secp 内部已由权威库处理 |
| 延迟数字 | 量级估算框架 | 已用于 docs/memory.md 与瓶颈预判 |
| CPU 缓存/预取器 | 顺序布局、预取 | 词表 ~14KB 常驻 L1/L2 ✓；无指针追逐热路径 |
| 不增线程加速 | SIMD 向量化 | 匹配已用 memchr SIMD；sha512 多缓冲需 nightly（拒） |
| 冯诺依曼→现代特性 | 机械同情三层次 | 分层剪枝+栈缓冲已是该思想的落地 |
| Rust 四技巧 | 消灭不必要堆分配 | 热路径 ~10³ 次/s 的 KB 级分配 <0.1%（低于 2% 门禁，不立项） |
| Rust 终极指南 | 测量-隔离-优化循环 | 与本项目 A/B 纪律一致（criterion + 记录） |

## 6. 实际采纳的性能优化（2026-09-28）

1. **LICM 外提**：`ChildNumber` 预解析移入 `Generator::new`（每轮省 5 次
   重复解析；确定性向量证明派生结果不变）。库层证据：vendored bip39 的
   pbkdf2 已用 `prf.clone()` 把 HMAC 密钥状态外提（循环不变量在库内已做）。
2. **derive_batch 批派生（重大）**：算法级优化——一次昂贵的 BIP39 种子派生
   （2048 轮 PBKDF2）摊薄到 N 个地址（BIP32 末层连续派生，MetaMask 多账户
   同构）。实测 A/B：433/s → 2457/s（**5.7×**，N=8）。安全论证见
   docs/security-audit.md 第三节。
3. **调度架构修复**：rayon 单线程池丢唤醒竞态（1 核机器死锁）→ 改用
   `std::thread::scope` 原生线程并移除 rayon 依赖。
4. **库补丁（2026-10-02 确认有效）**：§7 的补丁实测 **+6.5%**（首轮 0%
   为本地指纹缓存的假阴性，已修正），与 derive_batch 叠加使用。
5. **PGO 验证通道**：`pgo.yml`（CI 实机：插桩→5 分钟训练→重建→对比），
   README 提供"生产环境 PGO"三步教程。

## 7. vendored 库代码直改审计与 A/B（2026-10-01，"能直接改库代码吗"的完整答案）

按安全方式（改源码 + 清空 .cargo-checksum.json 的 files 映射 + 差分测试）实施并实测：

| 优化点 | 改动 | 实测 A/B（同机单线程 3 次） | 结论 |
|---|---|---|---|
| bip39 pbkdf2 热循环：引擎克隆/分支/字节序转换 → 直驱 compress_block + 尾块 LICM | 完整实现并通过全部差分（RustCrypto 参考 12/18/24 词×4 口令逐位一致 + BIP39 官方向量） | **433 → 460/466/467/s = +6.5%**（强制重编译后实测） | **保留**（>2% 门禁）|
| bitcoin_hashes sha512：新增 compress_block 公共原语 | 同上验证 | 同上（同一 A/B） | 随上保留 |

> **⚠️ 测量方法论教训（2026-10-02 修正）**：首轮曾误报"0% 并回滚"——vendored
> crate 的 cargo 指纹不跟踪源码改动，本地"打补丁后构建"复用了未打补丁的
> 缓存产物，A/B 测的是基线对自己。修正流程：改 vendored 库后必须
> `cargo clean -p <crate>` + 删除 target 下对应 .fingerprint 目录强制重编译，
> 并以 CI 全新编译为准（正是 PGO CI 的编译错误暴露了本地缓存假象）。
| k256 公钥派生（管线 ~13%） | 审计未改动 | —— | 已用 GLV 自同态 + Radix-16 有符号分解（纯 Rust 最优实现）；进一步优化 = 手写密码学数学，红线拒绝 |
| bip32 层 HMAC（6 次/attempt） | 审计未改动 | —— | 引擎开销 ×6/attempt ≈ 0.1%，低于门禁不立项 |

**差分测试（tests/pbkdf2_differential.rs）保留**：RustCrypto hmac+sha2 独立参考实现 vs
vendored bip39 逐位一致（12/18/24 词 + 口令分支 + BIP39 官方黄金向量）——即使不改库，
它也是供应链级的行为锚（库被上游静默篡改时 CI 会报警）。

**CI 实机对比**：`bench.yml`（手动触发）在同一 runner 上对比基线提交（e9e24f0，
derive_batch 之前）vs 当前 HEAD 的单线程速率，并测 derive_batch=8 的增益，输出结论表。

**性能优化的边界（本项目不变约束）**：BIP39/BIP32/EIP-55 标准构造不可改动；熵源不可缓存或预测；stable 工具链；纯 Rust 依赖树；A/B < 2% 回滚。


## 8. 硬件视角优化（2026-10-04，依《现代 CPU 性能》笔记对照实施）

用户实测（同一单核 Docker 容器、同规则 0000+1234）：旧版 254-267/s →
补丁版 333-344/s（**+28.8%**，含调度修复与库补丁的跨版本累计），且瞬时
速率 8.5 小时稳定无漂移。

| 项 | 决策 | 依据 |
|---|---|---|
| 共享计数器伪共享 | **已修**：attempts/hits/进度原子各独占 64B 缓存行（`PadAtomic`） | 笔记 §4.6：相邻原子同行 → MESI 失效乒乓；长跑累积 |
| Matcher | **不动** | 已是栈缓冲 + memcmp 剪枝 + memmem SIMD + 命中才算校验和 |
| 进程亲和（sched_setaffinity） | **不做**，README 教 `taskset`/`numactl` | 库调用需 unsafe（红线禁）；OS 层等价零风险 |
| per-NUMA-node 计数器 | **不做** | 当前计数频率 ~232 次/s（每批一次），真共享开销 <0.001%，分层计数器属过度设计 |
| bip32 层 HMAC 直驱 | **不做** | 6 次/attempt × ~74ns ≈ 0.02%，低于测量分辨率 |
| 大页（THP） | **不做** | 工作集 4.2MB 常驻 L1/L2，TLB 压力极小 |
| 超线程感知线程数 | **文档建议**（threads 可配置） | ALU 密集负载 HT 收益架构相关，留给用户 A/B |
| PGO | **CI 两轮实测均噪声级**（+1.1% / -0.4%~+0.4%），不采用 | SHA-512 压缩为紧凑直线代码、分支行为极稳定（99.99% 未命中），PGO 布局/倾斜无用武之地；README 教程保留为通用方法论 |

单路径性能地板声明：~1.9ms/attempt 为 BIP39 协议锁定的 4096 次
SHA-512 压缩（77%），软件层面已无安全优化空间；批量场景请用
`derive_batch`（5.7×），生产叠加 PGO。


## 9. 优化点全面盘点与逐项实施（2026-10-07，用户主用途=单路径 m/44'/60'/0'/0/0）

### 已实施（本节）
| # | 项 | 收益（实测/推算） | 状态 |
|---|---|---|---|
| 1 | derive_children：消除 derive_child 同父双重父公钥乘（tweak 输入+fingerprint 各算一次 k256 乘） | 单路径 +2×乘法消除（噪声内）、批模式显著（CI bench 量化中）；bit-exact 差分门禁 2 项 | ✅ ce370f7 |

### 量化后拒绝（改动/风险 > 收益）
| 项 | 量化 | 拒绝理由 |
|---|---|---|
| pbkdf2 ipad/opad 预计算 | 0 | **HMAC key=助记词（每 attempt 变）**，非空口令——读码后推翻假设，协议本质不可缓存 |
| XPrv::new "Bitcoin seed" 常量 midstate 直驱 | +0.02%（省 2 compress/attempt） | 见 §10：已实施 |
| 中间层 fingerprint 豁免（parent_fingerprint 仅序列化消费） | +0.14% | attrs.parent_fingerprint 是公开数据语义，填假值破坏 bit-exact；序列化路径将输出错误 |
| 批模式 Montgomery batch inversion（N 点共享 1 次模逆） | 批模式 ~+2% | 需收集整批 projective 点改 k256 输出流程；主用途单路径无批可逆 |
| OsRng 批量/缓存 | — | 密码学红线：OsRng 唯一熵源，禁缓存/预测 |
| fingerprint 的 SHA256+RIPEMD | 0.14%/层 | RustCrypto 已最优；无法跳过（语义） |
| target-cpu=x86-64-v2 | ~0 | SHA-512 无对应 SIMD 加速（SHA-NI 仅 SHA-256），发布兼容性优先 |
| derive_tweak HMAC 引擎重建 | 不可缓存 | key=父链码每 attempt 变 |
| child_xprvs Vec（batch=1 时 1 元素堆分配） | 0.001% | SmallVec 需新依赖（红线） |

### 单路径成本地板（重申）
每 attempt ~2.155ms：pbkdf2 4096 compress ≈1.78ms（82%，协议锁定）+
bip32 链 5 层 + k256 乘 ×(3-8 次) + keccak + 杂项。软件侧全部可做的
摊销/消除项已做完；剩余项合计 <0.2% 且多为协议/语义锁定。


## 10. XPrv::new 常量 midstate 直驱（2026-10-07，§9 待做项落地）

实施（8e7d390）：HMAC key "Bitcoin seed" 编译期常量 → ipad/opad keyed
midstate 进程级 OnceLock 缓存；64B seed（BIP39 to_seed 唯一输出）直驱
压缩，终块布局（0x80 + BE128(1536)）与 bip39 pbkdf2 直驱同构复用。
每 attempt 省 2 compress（~0.43µs）。16/32B fallback 原引擎。

差分门禁（新增 2 项，总数 70 全绿）：64B 快路径 10 种子 vs RustCrypto
原引擎私钥+链码 bit-exact；16/32B（含官方向量 1 seed）bit-exact。
本地实测 465/467/467 中位 467/s——数学收益 +0.02% 在噪声带内，如实
留档（用户政策：原理正确 + 功能正常的小优化保留）。

### CI bench 最终数字（3fd8d78，同 runner A/B）
- 单路径：基线 1031 → 当前 1166/s（**+13.1% 累计**，两台 runner 分别
  +13.1%/+14.2%，超 ±5% 噪声带，为真实增益）
- 批派生(8)：6405/s = 单路径 +449.3%；另一台 8220/s（+37% vs 优化前
  批模式 5986/s）
- 批测量规则已修 ffff→ffffff（提速后旧规则秒命中无进度行——测量口径
  必须随吞吐调整的教训留档）

### 全链路累计（容器实测口径）
用户单核容器同规则：254-267 → 333-344/s（+28.8%，含调度修复与全部
库补丁）；本轮库补丁后 CI 全核再 +13-14%。软件侧优化点已穷尽（§9
盘点），剩余为协议锁定地板（pbkdf2 82%）与硬件/调度层（README 调优
章节：taskset/numactl/超线程 A/B）。
