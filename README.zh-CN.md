# 抗量子签名验签性能测试（A 层）

[English](README.md) | 简体中文

本工具是独立的 Rust 命令行程序，基于 **liboqs 0.16.0**，固定源码提交为
`5a1a854b0dc9f2141bdc771c555ee60c37950183`。测试范围是完整的原生验签 API，
包括算法库内部的编码解析和哈希计算。密钥生成、签名生成、文件读写不计入验签耗时。
SLH-DSA-SHA2-128s 另用 BoringSSL（固定提交 `af41e135bc1714981fb8a791e9dda4fc6ff140c3`）测一份，
作为使用硬件 SHA-256 的对照实现。

本工具为 NewL1 账户验签方案的调研而写，但不依赖 NewL1 的任何代码；NewL1 的交易格式、
执行逻辑和预编译合约不在测试范围内。Cargo workspace 没有 crates.io 依赖。liboqs 仅作为实验性的测试依赖，通过 CMake 构建为
静态 C 库，关闭 OpenSSL。C 桥接代码通过固定版本的头文件读取元数据，避免在 Rust 中
重复定义 liboqs 的结构体布局。选用它作为测试框架不代表已经确定生产账户的验签实现。

## 1. 构建与快速验证

依赖：Rust 1.93+、Git、CMake 3.24+、C11 和 C++17 编译器、`ar`、Make（或其他 CMake 构建工具），
以及 `sha256sum` 或 `shasum`。支持 Linux 和 macOS 本机构建。

首次构建会下载固定版本的 liboqs 和 BoringSSL，不需要安装到系统目录。在仓库根目录执行：

```bash
bash build.sh optimized
./target/pq-verify-optimized --list
./target/pq-verify-optimized \
  --algorithms tier1 --cases all \
  --keys 2 --messages-per-key 2 --message-bytes 32 \
  --rounds 2 --warmup-ms 10 --duration-ms 100 --latency-samples 100 \
  --raw-latency --out results/smoke
```

这组短参数用于验证程序能否正常工作，**不能据此得出稳定的性能结论**。
在 CPU 特性探测被屏蔽的受限环境中，优化构建会拒绝运行（见第 4 节），
仅做功能验证时可加 `--allow-fallback`。
输出目录必须尚不存在，以防覆盖已有测试结果。重复运行时需要换一个输出目录。
不传参数或传入 `--help` 会显示帮助；`--list` 列出全部 18 项（17 个 liboqs 参数集，
加 `SLH_DSA_PURE_SHA2_128S@boringssl`）。

如果已有处于固定提交、且工作区干净的 liboqs 或 BoringSSL 源码，可复用该目录：

```bash
PQ_OQS_SOURCE=/absolute/path/to/liboqs PQ_BSSL_SOURCE=/absolute/path/to/boringssl \
  bash build.sh optimized
```

`PQ_BUILD_JOBS` 控制原生库构建并发数，默认是 4；`CC`、`CXX`、`AR` 可指定编译和归档工具。
进行对比时，应保持工具链和编译选项一致。

## 2. 算法与参数集

| `--algorithms` 取值 | 包含的参数集 | NIST 安全类别 |
| --- | --- | --- |
| `tier1`（默认） | ML-DSA-44；Falcon-512；SLH-DSA 的 SHA2/SHAKE × 128s/128f；`SLH_DSA_PURE_SHA2_128S@boringssl`，共 7 项 | 分别为 2、1、1 |
| `all` | ML-DSA-44/65/87；Falcon-512/1024；SLH-DSA 的 SHA2/SHAKE × 128/192/256 × s/f，加 BoringSSL 实现，共 18 项 | ML-DSA：2/3/5；Falcon：1/5；SLH-DSA：1/3/5 |
| 逗号分隔的算法名 | 使用 `--list` 输出的完整名称 | 由具体参数集决定 |

例如，只测试三个指定参数集：

```bash
./target/pq-verify-optimized \
  --algorithms ML-DSA-44,Falcon-512,SLH_DSA_PURE_SHA2_128F \
  --cases valid --out results/selected
```

`tier1` 表示各算法族的较低参数组，**不表示相同安全等级**。如果要在同一安全类别下
比较三个算法族，应选择 Category 5 的参数。

Falcon 使用原始可变长度签名编码，不是 `Falcon-padded` 或未来的 FN-DSA 格式。
结果记录实际签名长度，避免把缓冲区最大容量当作每条签名的长度。

ML-DSA 和 SLH-DSA 使用完整的 **pure** 接口，context 为空。输入 32 字节消息不会自动
切换到 HashML-DSA/HashSLH-DSA，也不会跳过算法内部哈希。是否将这 32 字节视为交易摘要，
属于协议层设计；本测试不证明该摘要满足某个安全类别。

## 3. 输入分布与无效签名

| 参数组合 | 模拟场景 |
| --- | --- |
| `--keys 1 --messages-per-key 1` | 重复验证同一条输入，作为热缓存参考 |
| `--keys 1 --messages-per-key 1024` | 同一个账户的多条消息 |
| `--keys 64 --messages-per-key 16` | 多账户、多消息，建议作为主要负载 |
| 更大的账户或消息数量 | 更大的工作集；应结合数据总字节数和 CPU 末级缓存容量判断 |

默认参数是：8 个账户、每账户 8 条消息、消息长度 32 字节、有效输入、5 轮，
每个测试项每轮预热 1 秒、吞吐测试 3 秒、延迟采样 10,000 次。
消息长度必须大于 0，可通过 `--message-bytes` 分别测试 32、64、256、1024、4096 字节。

`--cases` 可以指定单个场景、逗号分隔的多个场景，或使用 `all`：

| 场景 | 构造方式 | 关注点 |
| --- | --- | --- |
| `valid` | 正确公钥、消息和签名 | 正常验签成本 |
| `wrong-message` | 保留合法签名，翻转消息的一个比特 | 进入密码学计算后的拒绝成本 |
| `wrong-key` | 换成下一个账户的公钥；只有 1 个账户时使用额外生成的公钥 | 签名对应错误账户时的拒绝成本 |
| `corrupt-head` | 翻转签名第一个字节的一个比特 | 签名首部损坏 |
| `corrupt-mid` | 翻转签名中间字节的一个比特 | 签名主体损坏 |
| `corrupt-tail` | 翻转签名最后一个字节的一个比特 | 签名末尾损坏 |
| `truncated` | 删除签名最后一个字节 | 截断输入的处理成本 |
| `extended` | 在签名末尾追加一个非零字节（`0xff`）；Falcon 允许用零字节把签名补到固定的 padded 长度，追加零字节有时会得到合法签名 | 超出原始长度的输入处理成本 |

所有负例都保留正确的公钥长度，因为 liboqs 的验签 API 没有公钥长度参数。
`wrong-key` 轮换使用其他账户的公钥，因此公钥工作集与 `valid` 相同。
不同失败原因的耗时可能相差很大，因此各场景分别统计，不合并成一个“无效签名性能”。
签名损坏位置的差异尤其明显：例如 Falcon-512 解析首字节时就会拒绝（低于 100 ns），
末尾字节约 3 µs 被拒绝，中间字节则要完整验证后才拒绝（约 25 µs）。

## 4. 正式测试

使用与目标验证节点相近、负载较低的机器。Linux 上可选择一个可用物理核，通过
`taskset -c CPU` 绑定运行。额外记录频率策略、SMT、电源限制、后台负载和温度。
工具会记录 CPU 信息及 Linux 的 CPU/内存亲和性，但不会修改系统配置，
也不会在 macOS 上自动绑定 CPU 核心。

完整有效签名测试示例：

```bash
./target/pq-verify-optimized \
  --algorithms all --cases valid \
  --keys 64 --messages-per-key 16 --message-bytes 32 \
  --rounds 10 --warmup-ms 3000 --duration-ms 10000 \
  --latency-samples 100000 --latency-max-ms 20000 --seed 42 \
  --corpus-dir corpus --out results/all-valid-32
```

`--latency-max-ms` 给每次延迟测量设置时间上限：采满 `--latency-samples` 次或用完时间，
以先到者为准，实际采样数记录在 `latency_samples` 列。如果不设上限，SLH-DSA 单次验签
需要 0.4–2.2 ms，100,000 次采样会让上面的命令在 Apple M 系列开发机上每轮约 29 分钟、
10 轮约 5 小时；设为 20 秒后约每轮 8 分钟。此时 SLH-DSA 仍有约 9,000–46,000 次采样，
足以估计 P99。格签名不受影响，仍能采满 100,000 次。

SLH-DSA 签名生成很慢：`s` 系列每个签名约 0.5–1 秒，64×16 的全部 17 个参数集
依次生成要一个多小时。这部分完全不计入验签耗时，但建议先用 `--prepare-only`
单独生成一次。该模式只生成并校验样本，把 `sha256sum` 格式的清单打印到标准输出，
不计时，也不创建 `--out` 目录。各参数集的样本互相独立，可以并行生成。
`@boringssl` 一项读写的是 liboqs 同名参数集的样本文件，并行生成时要排除它，
否则两个进程会同时写同一个文件：

```bash
mkdir -p corpus && ./target/pq-verify-optimized --list | grep -v @ | xargs -P 8 -n 1 \
  ./target/pq-verify-optimized --prepare-only \
  --keys 64 --messages-per-key 16 --message-bytes 32 --corpus-dir corpus \
  --algorithms > corpus/SHA256SUMS
```

之后的运行、更换构建模式或换机器时都复用这份样本。复制到其他机器后先执行
`(cd corpus && shasum -a 256 -c SHA256SUMS)` 确认内容一致。样本加载时还会重新校验
全部正例和负例。

负例可分组运行，例如 `--cases wrong-message,wrong-key`，以及
`--cases corrupt-head,corrupt-mid,corrupt-tail,truncated,extended`，每次使用新的输出目录。

使用**相同样本**比较可移植构建：

```bash
bash build.sh portable
./target/pq-verify-portable \
  --algorithms tier1 --cases valid --keys 64 --messages-per-key 16 \
  --rounds 10 --warmup-ms 3000 --duration-ms 10000 --latency-samples 100000 \
  --latency-max-ms 20000 --corpus-dir corpus --out results/portable-valid-32
```

两种构建方式的区别：

- `optimized`：Release 构建，基础代码面向通用 CPU，通过 liboqs 运行时特性探测选择
  支持的优化实现，即 `OQS_DIST_BUILD=ON`。
- `portable`：Release 构建，关闭运行时分发和 liboqs 的 CPU 扩展开关，并检查没有启用
  架构专用的签名后端。编译器自身的自动向量化仍被允许。

每行结果中的 `backend`（签名实现）和 `hash_backend`（哈希实现）按固定版本的实际分发规则
确定；构建配置和 CMake 缓存也保存在元数据中。测试结果反映的是这些实现及其优化程度，
不是算法在所有实现中的性能上限。

**跨算法族比较时，SLH-DSA 处于明显劣势。** 此版本的 SLH-DSA 在两种模式下均使用
slhdsa-c 的可移植实现，并且它自带纯 C 的 SHA-2 和 Keccak，不经过 liboqs 的哈希分发，
用不上 SHA-NI、ARMv8 SHA2 等硬件指令。因此优化构建和可移植构建的 SLH-DSA 结果
基本相同，而 ML-DSA 和 Falcon 在优化构建中使用 SIMD 实现。生产级 SLH-DSA 实现
（硬件 SHA-2、AVX2 多路并行哈希）可能快数倍。同一构建下的跨族耗时比，
反映的是算法与实现成熟度的叠加，不能只归因于算法本身。

**怎样得到公平对比。** 比较算法本身，用可移植构建：三个算法族都是纯 C，BoringSSL 也以
`OPENSSL_NO_ASM` 构建。比较上线成本，用优化构建中的 `SLH_DSA_PURE_SHA2_128S@boringssl`：
它使用 SHA-256 硬件指令，与 liboqs 的 `SLH_DSA_PURE_SHA2_128S` 共用同一份样本文件，
每次运行开始时会用 BoringSSL 重新校验全部正例和负例，两个库判定不一致时直接报错。
在 Apple M 系列开发机上，它的验签耗时约为 liboqs 同参数集的 1/6。BoringSSL 的
SHAKE-256f 同样是纯 C Keccak，实测比 liboqs 慢约 15%，因此没有接入。

**优化构建会拒绝静默回退。** 受限环境可能屏蔽 CPU 特性探测，例如阻止 macOS 的
`sysctl`，使运行时分发选中通用 C 实现。此时只要任一 ML-DSA 或 Falcon 参数集解析到
`mldsa-native/C` 或 `PQClean/clean`，或 BoringSSL 的 SHA-256 解析到
`boringssl-sha256/nohw`，程序会在创建输出目录前报错退出。
如确需记录这种情况（例如 CPU 本身不支持相应扩展），可加 `--allow-fallback`，
结果中的 `backend` 会如实显示 C 实现，元数据记录 `dist_build=true`。
正式测试应在 CPU 特性可以正常探测的环境中进行。

## 5. 计时口径与复现

- 密钥、消息和签名使用 liboqs 默认的系统随机源生成。样本只保存公钥、消息和签名，
  包括用于错误公钥测试的额外公钥。私钥释放前会被清零，不写入文件。
- 在开始测量前加载或生成全部样本，并校验所有正例和负例。损坏或与参数不匹配的样本
  会导致报错，不会自动替换。每次计时调用的返回值都必须符合预期。
- 保存样本文件的 SHA-256。`--seed` 只控制样本和测试项的遍历顺序，**不控制密钥或签名
  的随机性**。要复现完全相同的输入，应复制样本文件。
- 每轮打乱算法/场景顺序，预热前打乱样本顺序。遍历一轮样本后才开始重复。
  不启用验签结果缓存或公钥预解析缓存。
- **延迟**：预分配采样数组，对每次验签独立计时；停止计时后再检查返回值并保存耗时。
  mean、P50/P95/P99 来自单次调用样本，分位数采用最近秩法。调度中断造成的延迟保留在
  分布中。设置 `--latency-max-ms` 时，时间到就停止采样（至少保留 1 次），
  检查时间的操作在单次计时区间之外。另行记录空计时探针，但不从结果中扣除；
  快速拒绝场景尤其需要关注计时开销。
- **计时精度**：Apple Silicon 上的计时器粒度约 41.7 ns（探针 p50 为 0、p99 约 42 ns）。
  `truncated`、`extended`、Falcon 的 `corrupt-head` 等百纳秒级场景，延迟分位数会被量化成
  0 或 42 ns 的整数倍，这类场景应以 `verify_per_second` 为准。macOS 也无法限制进程
  只在性能核上运行，正式数据应在 Linux 上测量。
- **吞吐**：独立计时循环，每 64 次调用检查一次是否达到时长。统计所有调用和实际总耗时，
  包括超出设定时长的部分，以及少量遍历和返回值检查开销。
  `verify_per_second = 调用次数 / 实际秒数`。负例的该指标表示每秒拒绝次数。
- 奇偶轮交替执行延迟和吞吐测量。样本读写、随机数生成、签名、排序、进度日志及 CSV
  写入都不在计时区间内。

## 6. 输出文件与指标

| 文件 | 内容 |
| --- | --- |
| `rounds.csv` | 每个参数集、场景、轮次的签名/哈希后端、安全类别、样本哈希、长度、延迟统计和吞吐 |
| `latency.csv` | 加上 `--raw-latency` 后输出；记录单次调用耗时，索引按测量顺序排列，不是原始样本索引 |
| `metadata.txt` | 运行参数、liboqs 提交/编译配置、Rust 版本/选项、可执行文件哈希、CPU/系统/亲和性、样本哈希和计时探针 |
| `COMPLETE` | 所有请求的测量和输出刷新都成功后才生成的完成标记 |

主要 CSV 指标：

| 字段 | 含义 |
| --- | --- |
| `backend` | 实际执行的签名实现，例如 `mldsa-native/aarch64`、`PQClean/clean` |
| `hash_backend` | ML-DSA/Falcon 使用的 liboqs Keccak 实现；liboqs SLH-DSA 为 `slhdsa-c/internal`；BoringSSL 为 `boringssl-sha256/{hw,avx,ssse3,neon,nohw,c}` |
| `latency_samples` | 本轮实际延迟采样数；受 `--latency-max-ms` 限制时可能少于请求值 |
| `mean_ns`、`p50_ns`、`p95_ns`、`p99_ns` | 单次调用延迟，单位纳秒；除以 1,000 可换算为微秒 |
| `throughput_calls` | 吞吐测量期间实际完成的调用次数 |
| `throughput_elapsed_ns` | 吞吐测量实际耗时，单位纳秒 |
| `verify_per_second` | 独立测得的每秒调用次数，不是直接用延迟分位数取倒数 |
| `pk_bytes` | 公钥长度，单位字节 |
| `input_sig_min_bytes`、`input_sig_mean_bytes`、`input_sig_max_bytes` | 当前场景中实际输入签名的最小、平均、最大长度 |
| `corpus_sha256` | 基础样本文件的 SHA-256，用于确认跨构建、跨机器使用同一组输入 |

`corpus/*.bin` 使用带版本号、字段长度上限及长度前缀的小端格式。
中断的运行可能留下部分输出；没有 `COMPLETE` 表示不是完整结果。
如果样本文件在写入时中断，需要明确删除该不完整文件后再重新生成。
生成的样本、结果及构建产物均已加入 Git 忽略规则。

推导置信区间时应保留各轮数据，不能将单轮中重复执行的 100,000 次调用当作
100,000 次独立实验。工具提供原始测量结果，不自动选择跨轮统计模型。

### 跨轮汇总

`summarize.py` 把一个或多个已完成的结果目录合并成一张表，每个（构建、算法、后端、场景、负载）
组合一行。各项取多轮的中位数，并给出 p50 的最小/最大值和 `verify_per_second` 的变异系数
（`verify_per_second_cv`，标准差除以均值）。`throughput_vs_baseline` 是相对基准算法
（默认 ML-DSA-44）的吞吐倍数，只在同一构建、同一场景、同一负载内计算。
没有 `COMPLETE` 的目录，或同一参数集在不同目录中用了不同样本，都会直接报错。

```bash
python3 summarize.py --baseline ML-DSA-44 \
  results/portable-valid-32 results/optimized-valid-32 > results/summary.csv
```

## 7. 代码检查与回归测试

完成优化构建后执行：

```bash
export PQ_OQS_BUILD="$PWD/target/oqs-optimized"
cargo fmt --all -- --check
cargo clippy --release --all-targets --offline -- -D warnings
cargo test --release --offline
python3 -m unittest test_summarize
python3 smoke_test.py ./target/pq-verify-optimized
```

测试覆盖全部 18 项的真实有效/无效签名、`wrong-key` 的公钥轮换、
样本序列化重放和损坏拒绝、BoringSSL 与 liboqs 双向互验样本、验签返回异常时中止测量、
延迟时间上限、回退后端判定、遍历顺序和分位数计算。
CLI 冒烟测试覆盖 18 项 × 8 个场景，核对 CSV 统计值与单次原始耗时是否一致，
以及 `--prepare-only` 的清单与文件一致、重复执行不重新生成、测量运行使用同一份样本，
还有样本复用、延迟时间上限和失败处理。冒烟测试本身带 `--allow-fallback` 运行，
因此在受限环境中也能通过；如果检测到回退，它会额外确认不带该参数时程序拒绝运行。

## 8. 当前范围

当前只实现三个抗量子签名算法族的**单线程 A 层测试**。尚不包含有效/无效输入混合负载、
多核扩展、secp256k1 基线、账户身份绑定、EVM/预编译开销、区块处理吞吐或 gas 定价。
SLH-DSA 只有 SHA2-128s 有第二种（BoringSSL）实现，其余参数集都是 liboqs 的标量实现（见第 4 节）。**验签次数/秒不等于链的 TPS。**

参考资料：[liboqs 0.16.0](https://github.com/open-quantum-safe/liboqs/tree/0.16.0)、
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)、
[FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)。
