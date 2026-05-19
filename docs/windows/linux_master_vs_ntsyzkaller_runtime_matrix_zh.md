# Linux master 与 NTsyzkaller 运行时架构对照矩阵

范围说明：

- 语义基线使用本地 `syzkaller` 仓库中的 `master` 分支；
- 对照目标使用当前工作区中的 `NTsyzkaller` 分支；
- 只统计当前分支里已经真正接上线、会影响运行时行为的符号；
- 任何已经在 `prog.Target` 中声明、但没有被 `sys/windows/init.go` 实际赋值的 hook，
  都按“未实现”处理，而不是按“Windows 已具备该能力”处理；
- `syz-nyx-runner` 被视为透明兼容边界，而不是另一套上层架构。

## 1. 配置与目标装配层

| Linux 模块/职责 | Linux 核心结构体 | Linux 核心函数 | NT 当前对应物 | 当前状态 | 主要实现差异 | 后续建议 |
|---|---|---|---|---|---|---|
| 目标解析、启用 syscall、传递闭包装配 | `mgrconfig.Config`、`Experimental`、`prog.Target`、`SyscallAttrs` | `SetTargets`、`SplitTarget`、`ParseEnabledSyscalls`、`prog.Target.TransitivelyEnabledCalls` | `pkg/mgrconfig/load.go` 已在解析阶段调用 `Target.ExpandEnabledCalls`；`sys/windows/init.go` 把 `ExpandEnabledCalls` 绑定为 `expandWindowsEnabledCalls` | `target 建模实现` | NT 让 Windows target 在装配期自动补齐 `VirtualAlloc`、socket/file scaffold，而不是要求配置文件显式列出所有 helper | 继续把“自动补 scaffold”的规则留在 `sys/windows/init.go`，不要把 Windows 规则散落到 manager 或 runner |
| 运行时/实验参数装配 | `mgrconfig.Config`、`pkg/manager/seeds.go` | `LoadSeeds`、`readInputs` | `pkg/mgrconfig/config.go` 新增 `SeedPrefix`、`BorrowingSeedPrefix`、`MaxCallsPerProg`、`ForceGenerateEveryN`、兼容字段 `WindowsVMLessCollide`；`pkg/manager.LoadBorrowingSeeds` 复用通用 seed 读取路径加载 borrowing-only seeds | `通用 loader 已接线` | Windows Nyx 仍可通过配置收紧 seed 来源和请求长度，但 seed 前缀读取已经从 `syz-manager` 收敛到 `pkg/manager`，不再是 manager-local Windows 补丁 | 若后续保留这些前缀过滤，应继续把语义放在通用 corpus bootstrap 层；`WindowsVMLessCollide` 只作为旧配置兼容字段 |
| 当前缺口 | `prog.Target` 扩展面 | `Clone`、`CallRelevance`、`TriageRelevance`、`CallEligible*` helpers | `sys/windows/init.go` 当前只接了 helper 分类和 scaffold expansion；大部分 score/runtime hooks 仍然是 `nil` | `缺失` | NT 现在已经把 hook surface 扩出来了，但 Windows profile 还没有真正提供 relevance / collide / triage 策略 | 应把最小可用的 Windows policy 收束到 `sys/windows/init.go`，先补少量关键 hook，再决定是否需要更细的 profile 分层 |

## 2. 管理与调度入口层

| Linux 模块/职责 | Linux 核心结构体 | Linux 核心函数 | NT 当前对应物 | 当前状态 | 主要实现差异 | 后续建议 |
|---|---|---|---|---|---|---|
| manager 启动、machine check、corpus preload | `syz-manager.Manager`、`Mode`、`corpusRunner` | `MachineChecked`、`preloadCorpus`、`corpusRunner.Next`、`loadCorpus` | `MachineChecked` 现在通过 `pkg/manager.LoadBorrowingSeeds` 传入 `BorrowingCorpus`，并把 `MaxCallsPerProg`、`ForceGenerateEveryN` 传给 `fuzzer.Config`；collide 默认恢复为 target-neutral 开启 | `runner 兼容实现` | Windows Nyx 不再通过 manager 里的 Windows VMLess 默认禁用分支回避 collide，manager 只传递通用 borrowing corpus 与调度配置 | 队列策略本身仍应保持 generic；真正的后端限制应尽量往 runner handshake 或 backend 能力层收 |
| fuzzer 请求源组合 | `pkg/fuzzer.queue.Source`、`DynamicOrderer`、`DefaultOpts` | `queue.Order`、`queue.Alternate`、`queue.DefaultOpts` | `pkg/fuzzer/queue/queue.go` 新增 `Interleave`、`Origin`、`TraceID`、`ExtraStats`；`pkg/fuzzer/fuzzer.go` 引入 `ForceGenerateEveryN` 和 `immediateCollideQueue` | `runner 兼容实现` | NT 需要显式的 fresh generation 交错机制和请求追踪信息，才能保证抢占与 collide/triage/corpus 流程可回溯 | 一旦 Nyx 行为足够接近 Linux executor 边界，就应尽量收缩 generic 调度层里对 Windows 的隐式认知 |
| 当前可见缺口 | `queue.Request`、`queue.Result` | `Request.Done`、`Request.Validate`、`Result.Stop` | `queue.DefaultOpts` 仍然会在 Windows VMLess 路线的 hints 请求上主动剥掉 `CollectSignal|CollectCover` | `偏离` | generic queue 层正在替 runner 的能力不对称兜底，而不只是做请求传输 | 把 collect-mode 归一化尽量移回 runner 边界，然后让 generic queue 默认值重新保持 OS 无关 |

## 3. 执行协议与能力协商层

| Linux 模块/职责 | Linux 核心结构体 | Linux 核心函数 | NT 当前对应物 | 当前状态 | 主要实现差异 | 后续建议 |
|---|---|---|---|---|---|---|
| executor/runner 到 generic 层的最小协议 | `flatrpc.ExecRequest`、`ExecResult`、`ProgInfo`、`CallInfo`、`FeatureInfo` | `flatrpc.Send/Recv`、`ProgInfo.Clone`、`EmptyProgInfo` | `tools/syz-nyx-runner/main.go` 使用 `SnapshotHandshakeT`、`SnapshotRequestT`、`parseExecResult`、`synthesizeHangedResult`，最后再回填成 `flatrpc.ExecutorMessage` | `runner 兼容实现` | Windows Nyx 原生并不像 Linux executor IPC 路径；`syz-nyx-runner` 负责重编码请求、回放 hang 语义、合成 `ExecResult.Info` | 所有协议翻译都应留在 runner 边界完成，不要让上层 generic 模块理解 Nyx 专用载荷格式 |
| feature probe 与按请求执行语义 | `vminfo.Feature`、`Features` | `featureToFlags`、`featureSucceeded`、`rpcserver.Runner.handleExecResult`、`convertCallInfo` | `tools/syz-nyx-runner/main.go` 新增 `normalizeWindowsNyxEnvFlags`、`ensureHandshake`、`executeRequestOnce`、`injectCoverage`、`parseCoverageDump`；`pkg/vminfo/features.go` 允许 Windows 在 cover/comps 为空时继续通过 | `runner 兼容实现` | Linux 语义期待 feature probe 真正证明 coverage/comparisons 能工作；NT 当前是在执行后注入 PT 结果，所以不得不放宽 `featureSucceeded` | 应让 runner 返回的语义足够稳定，这样 Windows 也能重新使用严格的 `featureSucceeded` |
| 当前可见缺口 | `rpcserver.Runner`、`vminfo.checkContext` | `ConnectionLoop`、`handleExecResult`、`featureSucceeded` | `pkg/rpcserver/runner.go` 在存在 `ReturnAllSignal` 请求时把总 in-flight 数量收紧到 `1`；还加了 Windows 专用 raw/post signal 日志 | `偏离` | generic RPC runner 已经开始显式感知 Windows/Nyx 在 deflake/triage 阶段的饥饿模式，说明兼容边界还不够透明 | 先在 runner/backend 层修掉饥饿与排队问题，再回头移除 `pkg/rpcserver` 里由 Windows 逼出来的执行形状假设 |

## 4. Fuzzer 主循环与任务层

| Linux 模块/职责 | Linux 核心结构体 | Linux 核心函数 | NT 当前对应物 | 当前状态 | 主要实现差异 | 后续建议 |
|---|---|---|---|---|---|---|
| triage / smash / hints / collide 主循环 | `pkg/fuzzer.Fuzzer`、`Config`、`triageJob`、`smashJob`、`faultInjectionJob`、`hintsJob` | `processResult`、`triageProgCall`、`genFuzz`、`Next`、`triageJob.deflake`、`randomCollide` | `pkg/fuzzer/fuzzer.go` 与 `job.go` 新增 `Origin`、`TraceID`、`ready`、`immediateCollideQueue`、`shouldPersistCall`、`shouldStartHints`、`maybeScheduleImmediateCollide`、`collideChanceForProg` | `runner 兼容实现` | NT 额外加入了请求可追踪性和队列同步，以免 deflake / collide 工作被已经发出的请求拖住；这主要是为了适配 Nyx 路线，而不是 Linux executor 风格 | 如果 trace ID 和额外统计后续仍然有用，可以保留；否则当 runner 更透明后再把这些诊断噪音收缩掉 |
| helper 过滤与运行时门控 | `prog.Target` 的运行时辅助能力 | `CallEligibleForTriage`、`CallEligibleForHints`、`CallEligibleForMutation`、`CallEligibleForCollide` | `mergeTargetNoMutateCalls` 会尊重 `Helpers.NoMutateAutomaticHelpers`；`triageProgCall` 通过 `CallEligibleForTriage` 跳过 helper-owned triage；`job.shouldPersistCall` 会跳过 helper-owned corpus entry | `target 建模实现` | 这是当前 `sys/windows/init.go` 真的接上的部分：Windows 的 helper syscall 不再主导 triage、hints、mutation 或 corpus ownership | helper 语义应继续留在 target 层，不要搬到 runner 或 manager 里做判断 |
| 当前可见缺口 | `RuntimePolicy`、`CallRelevanceScore`、`TriageCallScore` | `triageProgCall`、`pruneLessRelevantTriage`、`maybeScheduleImmediateCollide`、`collideChanceForProg` | generic fuzzer 已支持深 owner 的评分、强制 triage / persistence hook，但当前 `sys/windows/init.go` 还没有填这些策略 | `缺失` | 运行时层已经准备好接收 Windows 的深 owner steering，但当前 Windows policy 基本还是空的，所以现在只有 helper 过滤真正生效 | 如果确实需要深 owner steering，就把最小 policy 接到 `sys/windows/init.go`；否则 generic 路径应尽量保持接近 Linux 默认行为 |

## 5. 程序模型、资源模型、生成与变异

| Linux 模块/职责 | Linux 核心结构体 | Linux 核心函数 | NT 当前对应物 | 当前状态 | 主要实现差异 | 后续建议 |
|---|---|---|---|---|---|---|
| generic prog 核心：target / state / choice table / resource ctor 闭包 | `prog.Target`、`Syscall`、`Prog`、`state`、`ChoiceTable` | `BuildChoiceTable`、`TransitivelyEnabledCalls`、`Generate`、`existingResource`、`resourceCentric`、`createResource` | `prog/target.go` 暴露了 `Helpers`、`Bias`、`RuntimePolicy`、`ResourceUseScore`、`ResourceReuseScore`、`CorpusResourceScore`、`PreferResourceCentricBorrowing`、`SelectResourceCtor`、`ObserveTemplateHook`；`prog/rand.go` 还把 `currentMeta/currentProg/currentInsertionPoint` 传进了生成路径 | `偏离` | NT 把 `prog.Target` 的扩展面拉大了很多，目的是让 Windows 以后能 steer generation / reuse / collide，但目前真正被 Windows 代码消费的 hook 仍然很少 | 只有在这些扩展点仍然保持 target-agnostic 的前提下才继续保留；否则不要再往 `prog.Target` 里继续堆 Windows 专用字段 |
| 生成期 corpus borrowing 与 mutation / collide shaping | `Prog`、`randGen`、`mutator` | `Generate`、`MutateWithOpts`、`chooseCall`、`AssignRandomAsync`、`DupCallCollide`、`DoubleExecCollide` | `GenerateWithCorpus`、`chooseCall` 现在尊重 `CallEligibleForMutation`、`preferredCollideIndices`；`BuildChoiceTable` 还多了 `biasCalls`；`analysis.go` 会记录 `resourceScores` 供后续复用 | `target 建模实现` | 这条分支已经能按 target 提供的 relevance / resource score 去塑造生成与 collide，但 Windows 目前几乎没有填这些 score hook | 只给那些已经被运行日志证明有效的 Windows hook 写策略，其余的先保持 generic 默认，避免 policy 膨胀 |
| 当前可见缺口 | `Target.Bias.*`、`SelectCollideCallIndices`、`CallRelevanceScore`、`ResourceUseScore`、`ResourceReuseScore`、`CorpusResourceScore`、`SelectResourceCtor` | `generateCall`、`resourceCentric`、`existingResource`、`bestRelevanceCallIndices` | 这些符号都已经存在于 `prog/*`，但当前 `sys/windows/init.go` 并没有给它们赋值；分支中的证据更多是测试和注释，不是活跃的 Windows 策略 | `缺失` | generic 引擎已经准备好 Linux 风格的 staged-state heuristics，但 Windows target 还没有把这些 heuristics 用代码明确描述出来 | 应把具体 policy 放到 `sys/windows/init.go` 或一个专门的 Windows policy 文件里，不要塞回 manager、runner 或更泛的 `if windows` 分支 |

## 6. OS target 语义层

| Linux 模块/职责 | Linux 核心结构体 | Linux 核心函数 | NT 当前对应物 | 当前状态 | 主要实现差异 | 后续建议 |
|---|---|---|---|---|---|---|
| Linux target-local 语义 | Linux `arch`、`prog.Target` 的本地字段 | `sys/linux.InitTarget`、`MakeDataMmap`、`Neutralize`、`SpecialTypes`、`AuxResources`、`SpecialPointers` | `sys/windows.InitTarget`、`configureWindowsHelpers`、`expandWindowsEnabledCalls`、`makeMmap`、`neutralize`；`sys/windows/sys.txt`、`socket_nyx.txt`、`nt_demo.txt` 定义了 `HANDLE`、`FILE_HANDLE`、`SOCKET*` 这些资源和基础 NT/file/socket surface | `target 建模实现` | Windows 已经有显式的 file handle 和 socket 角色资源，也有 target-side scaffold expansion，但 target-local 行为仍明显少于 Linux | 资源和状态语义应继续放在 `sys/windows/*.txt` 与 `sys/windows/init.go` 中，这才是 OS 语义该在的层 |
| Linux 风格的本地安全 shaping | Linux `arch` 的局部规则、`SpecialFileLengths`、`SpecialTypes` | `neutralize`、`generateTimespec`、`generateSockaddrAlg` 等 | Windows 现在只设置了 `AuxResources = {HANDLE, SOCKET}`、少量 `SpecialPointers`，以及一个很小的 `neutralize`，只处理 `ExitProcess` / `TerminateProcess` / `Sleep` | `缺失` | 相比 Linux，Windows 的 target-local 语义塑形还停留在 bring-up 级别：没有 `SpecialTypes`，也没有 file-length 规则 | 只有在真实 Windows 资源或安全问题需要时，才增加 target-local 语义，不要机械地照搬 Linux hook |
| 当前可见缺口 | Linux target 内部已经形成稳定的资源状态惯例 | `InitTarget`、`Neutralize`、`SpecialTypes`、`MakeDataMmap` | 当前 Windows surface 仍然更像 demo 级 NT/file/socket 家族，没有更深层的对象状态模型 | `缺失` | Windows target modeling 已经不是“完全跑不起来”的阶段了，但还没到 Linux 那种成熟状态机级别 | 先在 `sys/windows/*.txt` 里继续演进；只有在纯 syzlang / resource layering 不够时，才补 `prog.Target` hook |

## 缺口清单

优先级顺序：

1. 先修 generic 上层正确性
2. 再提升 Windows 资源状态建模质量
3. 最后才是调度和策略增强

### 1. feature 协商仍然在接受更弱的 Windows 语义

- 缺什么能力：`FeatureCoverage` 和 `FeatureComparisons` 在 Windows 上还没有被 feature probe 严格证明；`pkg/vminfo/features.go:featureSucceeded` 现在明确允许 cover / comps 为空也算成功。
- Linux 原本在哪一层完成：`pkg/vminfo` 和 `pkg/rpcserver` 期望 executor/runner 返回真实的 `CallInfo.Cover`、`CallInfo.Signal`、`CallInfo.Comps`。
- NT 当前卡在哪一层：`tools/syz-nyx-runner/main.go` 先跑 Nyx，再通过 `injectCoverage` 把 PT 结果补回去；generic 层只能放宽判断。
- 推荐放到哪里实现：`tools/syz-nyx-runner` + `pkg/rpcserver/runner.go`。
- 为什么不能放到别层：generic 的 feature check 应该保持 Linux 语义；把“Windows 即使没 cover 也算成功”留在 `pkg/vminfo`，会持续污染上层判断。

### 2. Windows 的 deep-owner / relevance 策略还没有真正落地

- 缺什么能力：Windows 还没有把 `CallRelevanceScore`、`TriageCallScore`、`SelectCollideCallIndices`、`SelectGeneratedCall`、`ResourceUseScore`、`ResourceReuseScore` 这些 hook 绑定成真实策略。
- Linux 原本在哪一层完成：Linux 主要依靠成熟的 target 语义、resource closure、choice table 和 corpus 动态优先级，自然形成深状态偏好。
- NT 当前卡在哪一层：`prog` 已经扩出了 hook surface，但 `sys/windows/init.go` 只接了 helper 过滤和 scaffold expansion。
- 推荐放到哪里实现：`sys/windows/init.go`，必要时再拆出专门的 Windows target policy 文件。
- 为什么不能放到别层：这些决策依赖 syscall / resource 语义；runner 不知道语义，manager 只知道配置，generic `prog` 不该继续堆 Windows 常量分支。

### 3. Windows VMLess / Nyx 的 collide 默认策略已恢复

- 当前状态：Windows `type=none` 路线不再由 manager 默认禁用 collide，`experimental.windows_vmless_collide` 只作为旧配置兼容字段保留。
- Linux 原本在哪一层完成：Linux 在 `pkg/fuzzer` / `prog/collide.go` 里直接启用 `AssignRandomAsync`、`DupCallCollide`、`DoubleExecCollide`。
- NT 当前进展：`syz-nyx-runner` 合成 hang 结果时保留原请求 id，并在请求级错误 / hang 后安排 VM 重启；standalone threaded 两轮验证已证明 async 程序能完成并返回覆盖。
- 后续建议：继续用真实 Nyx 运行观察 double-exec / collide 长时间稳定性；若再次需要背压，应表达为 runner/backend 能力，而不是恢复 manager 的 Windows 分支。
- 为什么不能放到别层：这是执行后端承载能力问题，不是 target 描述问题；继续在 manager 里硬关，只会扩大 generic 泄漏。

### 4. 默认 exec options 仍然带着 Windows / Nyx 特判

- 缺什么能力：`pkg/fuzzer/DefaultExecOpts` 只有在 `cfg.TargetOS == "windows" && cfg.VMLess` 时才默认补 `CollectSignal|CollectCover`；`queue.DefaultOpts` 还要在 hints 路径里手工剥掉这些 flags。
- Linux 原本在哪一层完成：Linux executor 的能力和默认执行模式天然匹配，generic queue 不需要修补 collect mode。
- NT 当前卡在哪一层：Windows Nyx 依赖“每个请求都能拿到 PT 结果”的通道，导致 generic default opts 不能直接照用。
- 推荐放到哪里实现：放回 runner 的 capability normalization / handshake。
- 为什么不能放到别层：`pkg/fuzzer` 和 `pkg/fuzzer/queue` 只应描述“想收什么结果”，不应该知道某个 OS 的 collect mode 互斥规则。

### 5. Borrowing-only seed 目前还只是生成期补丁

- 当前状态：`BorrowingSeedPrefix` 通过 `pkg/manager.LoadBorrowingSeeds` 读入一份只供 `GenerateWithCorpus` 使用的 borrowing corpus；它不会进入正常的 candidate / triage / corpus 生命周期。
- Linux 原本在哪一层完成：Linux 主路径主要靠 `manager.LoadSeeds`、persistent corpus、choice table 和 runtime triage 自然收敛。
- NT 当前进展：`SeedPrefix` 与 `BorrowingSeedPrefix` 已收敛到同一个 seed 读取 helper；`prog.resourceCentric` 补了 target-agnostic borrowing corpus 回归测试，并修复了裁剪 borrowing calls 时的悬空资源问题。
- 推荐放到哪里实现：`pkg/manager/seeds.go` + `prog.GenerateWithCorpus` 继续演进，而不是塞进 runner。
- 为什么不能放到别层：这是 program synthesis / corpus bootstrap 语义，不是 executor compatibility 语义。

### 6. Windows resource model 还是“typed alias + 手写闭包”，还没到 Linux 级状态机

- 缺什么能力：现在只有 `HANDLE` / `FILE_HANDLE` / `SOCKET_TCP` / `SOCKET_UDP` / `SOCKET_LISTENER` / `SOCKET_CONNECTED` / `SOCKET_ACCEPT` 这些 typed aliases，缺少更稳定的深对象状态建模。
- Linux 原本在哪一层完成：`sys/linux/init.go` + syzlang 描述 + 成熟的 resource ctor closure。
- NT 当前卡在哪一层：`sys/windows/socket_nyx.txt`、`nt_demo.txt`、`sys.txt` 已经能把 basic AFD/file/NT paths 跑起来，但深状态仍主要靠 helper expansion 和人为 seed shaping。
- 推荐放到哪里实现：优先放到 `sys/windows/*.txt`，必要时再补少量 `prog.Target` score hook。
- 为什么不能放到别层：资源类型和状态转移本质上是 target 语义；放进 manager/fuzzer 只会让 generic 层背 Windows 对象知识。

### 7. Windows target-local 的 neutralization 还太薄

- 缺什么能力：Linux target 会在 `Neutralize` / `SpecialTypes` 里处理大量危险或结构敏感路径；Windows 目前只 neutralize 了 `ExitProcess` / `TerminateProcess` / `TerminateJobObject` / `Sleep` / `SleepEx`。
- Linux 原本在哪一层完成：`sys/linux.InitTarget` 的本地 target 语义层。
- NT 当前卡在哪一层：`sys/windows/init.go` 仍然更像 demo-safe bring-up 级别。
- 推荐放到哪里实现：`sys/windows/init.go`。
- 为什么不能放到别层：哪些调用危险、该如何降级，完全是 OS-specific 语义，不应该让 runner 或 generic fuzzer 去猜。
