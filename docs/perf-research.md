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

**性能优化的边界（本项目不变约束）**：BIP39/BIP32/EIP-55 标准构造不可改动；熵源不可缓存或预测；stable 工具链；纯 Rust 依赖树；A/B < 2% 回滚。
