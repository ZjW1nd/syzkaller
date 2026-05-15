# Windows NT Target Adaptation

This note describes the current target-level adaptation strategy for fuzzing
Windows NT paths with syzkaller, with special attention to the Nyx/Windows
pipeline and the AFD/Winsock-oriented surface.

The goal is not just to "make Windows syscalls executable", but to gradually
move syzkaller's internal heuristics closer to the way it already reasons about
deep Linux kernel state machines:

- helper syscalls should build state instead of dominating exploration;
- deeper state transitions should be preferred over shallow scaffolding;
- resource reuse should prefer objects that have already reached a more
  interesting state;
- concurrency should be focused on deeper target operations instead of generic
  setup calls;
- manager configs should declare deep target operations while the target fills
  in the minimum required scaffolding automatically.

## 0. Current Runtime Status

At the current stage, Windows/AFD fuzzing is no longer in pure bring-up mode.
The main target-level strategies have now all appeared in real Nyx/Windows runs:

- template-guided generation
- template-guided corpus borrowing
- template-guided collide selection
- resource-centric borrowing

The remaining problems are therefore less about "can the mechanism ever fire"
and more about:

- how stable each mechanism is across runs;
- which syscall families dominate real collide/race attempts;
- how much time is still spent in candidate/triage versus fresh gen/fuzz/collide;
- how close the resulting program shapes are to the race patterns we actually
  want on AFD.

At this point there are two practically useful Windows AFD research configs:

- `tools/syz-nyx-runner/windows-nyx-afd-session-none.cfg`
  Use this as the broader AFD session baseline. It keeps generation,
  borrowing, collide, and candidate/triage all in play, and is the preferred
  config for multi-run aggregate studies.
- `tools/syz-nyx-runner/windows-nyx-afd-accept-race-none.cfg`
  Use this as a narrower accept-side race research config. It trims the enabled
  syscall set toward accepted-socket data/option operations and is better for
  studying concrete accept-side collide shapes.
- `tools/syz-nyx-runner/windows-nyx-afd-transmit-none.cfg`
  Use this as a transmit-focused research config. It narrows both the seed set
  and the target policy toward file-backed accept-side data paths centered on
  `TransmitFile$inet_accept`, so transmit-specific progression can be studied
  without competing with the broader accepted-socket option/data mix.

The current data under `guest-vm/runtime/studies/` already supports both kinds
of analysis:

- balanced AFD session aggregate:
  `guest-vm/runtime/studies/afd-focused-series-20260512-091357`
- accept-side race aggregate:
  `guest-vm/runtime/studies/afd-focused-series-20260512-101211`

The accept-side race config is no longer just a narrower syscall list; it has
already been observed to produce real accept-side collide programs in runtime
logs. In particular, the current logging can emit concrete collide program
shapes such as:

- `collide:accept:recv$inet_accept|send$inet_accept`
- accept-side option/data mixtures where `getsockopt$int_accept` or
  `ioctlsocket$fionbio_accept` remains active in the collided execution

The current post-processing flow can also materialize these collided executions
into a small standalone artifact through:

- `syz-nyx-stats collide-summary --manager-log ... --output collide_summary.json`
- `syz-nyx-stats collide-quality --manager-log ... --output collide_quality.json`

This makes accept-side race investigation less dependent on manually scanning
large manager logs, and allows a later pass to relate collided executions to
their follow-up triage/corpus outcomes.

For the current accept-side line, the evidence has now bifurcated into two
clear categories:

- ordinary accepted-socket deep owners
  (`WSARecvEx$inet_accept`, `getsockopt$int_accept`,
  `ioctlsocket$fionbio_accept`) have all appeared as real owners in focused
  runtime artifacts;
- the file-backed transmit path (`TransmitFile$inet_accept`) now reaches real
  candidate/deflake stages, but still lags behind the ordinary option/data
  paths in final collide-owner retention.

Recent transmit-focused runs make this more precise:

- `TransmitFile$inet_accept` has already been observed as a real `candidate`
  triage owner in focused runtime;
- the transmit-focused path also exercises the file payload scaffold
  (`CreateFileA` / `WriteFile`) and later accept-side calls in the same
  programs;
- however, the current bottleneck is no longer seed absence or target
  reachability. Instead, the main problem is that candidate/deflake stability
  often fails to carry `TransmitFile$inet_accept` all the way into durable
  corpus / collided-owner retention.

This distinction is important: transmit is no longer blocked on basic target
description or seed absence. Its current bottleneck is the stability of the
candidate/deflake window, not the existence of a route into the pipeline.

Current accept-side experiments already show that "hitting an accept-side
collide template" and "stably preserving the deepest accept-side call as the
owning triage/corpus element" are not the same thing. For example, the
generated `collide_quality.json` artifacts can show collided accept-side
executions whose active calls include `WSARecvEx$inet_accept` or
`send$inet_accept`, while the follow-up triage/corpus path still tends to
stabilize around shallower `bind$inet_tcp` / `listen$inet_tcp` /
`send$inet_accept` combinations.

This makes `windows-nyx-afd-accept-race-none.cfg` the preferred config for
studying accept-side race *quality* rather than overall strategy mix.

By contrast, `windows-nyx-afd-transmit-none.cfg` is now the preferred config
for diagnosing why file-backed accept-side paths do or do not survive through
candidate triage, corpus retention, and later collide attempts. In recent
runtime results, it has already demonstrated that `TransmitFile$inet_accept`
can reach real candidate triage, but it still often fails to survive long
enough to become the owning collided call. This means further work on transmit
should focus first on candidate/deflake stability and only secondarily on
scoring heuristics.

At this stage, the most accurate distinction is:

- ordinary accept-side option/data owners are primarily a target-policy /
  distribution-quality problem;
- transmit/file-backed owners are primarily a runtime candidate/deflake
  convergence problem.

These are no longer "does it boot" artifacts; they are the current
architecture-level baselines for stability and strategy-mix evaluation.

## 1. Design Style

The main design rule is:

- prefer `Target`-level hooks over ad-hoc `if windows` logic spread across the
  codebase;
- keep the generic syzkaller pipeline intact where possible;
- encode Windows-specific behavior as opt-in target semantics;
- allow configs to become smaller over time instead of adding more handwritten
  helper entries.

This is why most of the current adaptation work lives in:

- `prog/target.go`
- `sys/windows/init.go`
- `sys/windows/state_policy.go`

The `state_policy.go` file is now the main home of the Windows staged-state
policy itself:

- helper syscall sets
- relevance thresholds
- bias filtering / selection rules
- pair-priority rules
- stage-closure rules

It is no longer just a bag of constants plus free functions: the policy is now
organized as an explicit policy object that owns these hook implementations,
while `init.go` primarily wires that object into `prog.Target`.

The policy object has also started to split into smaller facets rather than
keeping all knobs flat in one struct. At the moment it already separates:

- helper classification policy
- relevance-threshold policy
- bias-selection/filtering policy
- stage-closure policy

There is also now an explicit profile selector behind this policy layer.
At the moment the active built-in profiles are:

- `default`
- `afd`
- `fsctl`

These profiles can be selected from manager configs with
`experimental.windows_target_profile`, so AFD/Winsock-focused and file/FSCTL-
focused fuzzing can diverge cleanly without mutating the shared global Windows
target singleton.

and is then consumed by generic layers such as:

- `prog/prio.go`
- `prog/analysis.go`
- `prog/rand.go`
- `prog/mutation.go`
- `prog/collide.go`
- `pkg/fuzzer/fuzzer.go`
- `pkg/fuzzer/job.go`
- `pkg/mgrconfig/load.go`

## 2. Current Target Hooks

The Windows target currently uses the following `prog.Target` hooks/flags:

- `Helpers.DeprioritizeAutomaticHelpers`
- `Helpers.AvoidCollidingAutomaticHelpers`
- `Helpers.SkipHintsForAutomaticHelpers`
- `Helpers.NoMutateAutomaticHelpers`
- `Helpers.SkipCorpusForAutomaticHelpers`
- `Helpers.SkipTriageForAutomaticHelpers`
- `Helpers.AvoidAutomaticHelperBias`
- `Bias.SelectGenerationBiasCall`
- `Bias.FilterBiasCalls`
- `Bias.AdjustCallPriority`
- `ResourceUseScore`
- `CallRelevanceScore`
- `ExpandEnabledCalls`
- `RuntimePolicy.PreferCollideProgram`
- `RuntimePolicy.ShouldScheduleImmediateCollide`
- `RuntimePolicy.ShouldForceTriageCall`
- `RuntimePolicy.ShouldPersistStableTriageCall`
- `MinimumHintsCallRelevance`
- `MinimumTriageCallRelevance`
- `MinimumCollideCallRelevance`
- `MinimumMutationCallRelevance`
- `Bias.MinimumGenerationBiasCallRelevance`

These are declared in `prog/target.go` and enabled from `sys/windows/init.go`.

### 2.1 Helper semantics

`AutomaticHelper` means the syscall is primarily a state constructor or cleanup
primitive rather than a deep fuzz target.

Current helper set includes file-oriented helpers:

- `CreateFileA`
- `CreateFile2`
- `CloseHandle`
- `VirtualAlloc`

and network-oriented helpers:

- `WSAStartup`
- `WSACleanup`
- `socket$inet_tcp`
- `socket$listener_tcp`
- `socket$connected_tcp`
- `socket$inet_udp`
- `socket$accept_tcp`
- `closesocket$any`

These helpers still remain generatable and usable as constructors, but they are
gradually removed from being primary exploration targets.

## 3. Where Each Hook Applies

### 3.1 Choice table

Files:

- `prog/prio.go`
- `sys/windows/init.go`

Effects:

- helper syscalls are deprioritized as top-level call choices;
- helper syscalls are removed from the unbiased random bias pool;
- when generating the next top-level call, the target can now choose the most
  relevant existing prefix call as the bias context instead of always relying
  on a random earlier call;
- after bias selection, the target can now also override the actual next
  top-level generated syscall through `Target.Bias.SelectGeneratedCall`, which lets
  Windows continue an already-open accept/TCP/UDP/file session with deeper
  data-path calls instead of dropping back to unrelated shallow scaffolding;
- this generation override is no longer just family-based: it now uses an
  explicit continuation priority so accepted-socket data-path I/O outranks
  option toggles and NT file/FSCTL operations outrank shallower Win32 wrappers
  when choosing how to continue an existing Windows session;
- for the most common AFD/FSCTL paths, the selector now also has small
  continuation templates (for example `accept -> send/recv`, `send -> recv`,
  `NtFsControlFile -> NtWriteFile/NtReadFile`) before it falls back to the more
  generic family-based scoring path.
- these templates are no longer limited to a single previous call: the Windows
  selector can now recognize short local interaction patterns (for example
  `accept -> send -> recv` or `NtFsControlFile -> NtWriteFile -> NtFsControlFile`)
  before falling back to the more generic session-family heuristics.
- when the current prefix only contains helper/shallow scaffold state, the
  target can now explicitly suppress prefix bias altogether and fall back to
  the generic unbiased pool instead of inheriting an unhelpful shallow context;
- even without any prefix context, the target can now narrow the global
  `biasCalls` pool itself, so shallow scaffold calls do not have to dominate
  the fallback generation path;
- socket pair priorities are explicitly nudged toward staged progression:
  - socket -> bind/listen/connect
  - listen -> accept / AcceptEx
  - connect / accept -> send / recv / WSARecvEx / TransmitFile / sockopt

This is the first place where the Windows network surface is treated as a
state machine rather than a flat syscall list.

### 3.2 Program-state analysis and resource reuse

Files:

- `prog/analysis.go`
- `prog/rand.go`
- `sys/windows/init.go`

Effects:

- state analysis records which resources were consumed by which kinds of calls;
- resource reuse prefers resources that have already reached deeper stages;
- resource reuse can now also consult the syscall currently being generated, so
  Windows can prefer session-compatible resource roots (for example, keep
  `recv$inet_accept` on an already accepted socket lineage instead of reusing a
  shallower connected socket just because the base resource type is compatible);
- when several compatible roots exist in the same family, Windows now also
  prefers the most recent deep session root from the current program prefix, so
  accepted-socket and file-handle continuations stay attached to the freshest
  local interaction chain instead of drifting back to older but merely
  type-compatible state.
- this "most recent root" preference is not absolute: a freshly created but
  still shallow root can be outranked by an older root that has already entered
  the semantically relevant data path for the current syscall (for example an
  accepted socket that already sent data can beat a newer accepted socket that
  has not progressed beyond creation yet).
- corpus-derived initialization slices are now also target-scored separately
  from in-program resource reuse, so Windows can prefer deeper accept/data-path
  or NT file/FSCTL corpus slices over shallow helper-only setup fragments even
  when the base resource type is compatible in both cases.
- this corpus scoring is now finer than a simple "was the root reused" check:
  Windows can distinguish accepted-socket data-path slices from accept-side
  option-only slices, and similarly distinguish deeper NT file/FSCTL fragments
  from shallower wrapper-only corpus snippets.
- this corpus-slice scoring is also now aware of the *current* target syscall:
  for example, `recv$inet_accept` can prefer a corpus slice that already sends
  on the accepted socket, while `getsockopt$int_accept` can instead prefer an
  accept-side option-manipulation slice rather than always biasing toward the
  heaviest data-path fragment.
- on the file/FSCTL side, the same mechanism now distinguishes at least the
  main NT-path tiers (`NtFsControlFile`, `NtReadFile`, `NtWriteFile`) from
  shallower Win32 wrapper slices, so a current NT file operation can bias
  corpus borrowing toward a semantically closer NT-path fragment rather than a
  merely type-compatible `ReadFile`/`WriteFile` setup.
- the same current-aware distinction now also applies to connected TCP slices:
  a current `recv$inet_tcp` can prefer a send-bearing TCP slice, while a
  current `getsockopt$int_tcp` can prefer an option-manipulation TCP slice
  instead of always borrowing the heaviest connected-socket data-path fragment.
- the same current-aware distinction now also applies to connected UDP slices:
  a current `recv$inet_udp` can prefer a send-bearing UDP slice, while a
  current `getsockopt$int_udp` can prefer an option-manipulation UDP slice.
- generation continuation templates and corpus borrowing are now starting to
  share the same local interaction semantics as well: for example, when the
  current prefix already looks like `accept -> send`, Windows can bias corpus
  borrowing toward an accept-side slice that continues that pattern more
  naturally than an equally deep but differently-shaped accept fragment.
- collide target selection is now starting to recognize some of the same local
  continuation templates as well, so an `accept -> send -> recv` style prefix
  can bias collide focus toward the send/recv pair itself instead of only
  relying on family/root/priority filters.
- this template-aware collide focus is no longer limited to the accept path:
  connected TCP send/recv pairs and at least the basic `NtFsControlFile ->
  NtWriteFile` style file/FSCTL pairs can now be recognized as local collide
  targets as well.
- the fuzzer can also now slightly increase collide probability for programs
  that already match one of these local continuation templates, so template-like
  session programs are more likely to actually be transformed into collide mode
  during focused Windows runs.
- for sockets, later I/O-stage usage outranks earlier setup-stage usage;
- for file/NTFS paths, helper-only handle chains are less preferred than
  handles already used in FSCTL/read/write style paths.

This is currently implemented with `ResourceUseScore`.

### 3.3 Argument mutation target choice

Files:

- `prog/mutation.go`
- `prog/mutation_test.go`

Effects:

- when choosing which call inside a program to mutate, calls with higher
  `CallRelevanceScore` receive a higher effective mutation weight.
- calls below `MinimumMutationCallRelevance` can be skipped entirely as direct
  mutation targets.

This complements the choice table: we not only generate deeper calls more often,
we also spend more mutation budget on them.

### 3.4 Concurrency modeling

Files:

- `prog/collide.go`
- `prog/collide_test.go`

Effects:

- helper syscalls are avoided as async/collide targets where possible;
- collide target selection is now target-pluggable through
  `Target.SelectCollideCallIndices`, not only through generic score thresholds;
- `AssignRandomAsync`, `DupCallCollide`, and `DoubleExecCollide` prefer
  higher-relevance calls when selecting which operations to perturb
  concurrently.
- `AssignRandomRerun` now follows the same relevance policy, so rerun pairs
  are also concentrated on deeper staged operations instead of shallow setup.
- the Windows policy now narrows race candidates to the deepest relevant call
  family when possible, so accept-side calls race primarily against other
  accept-side operations, connected TCP calls race against connected TCP
  operations, UDP calls race against UDP operations, and file-handle paths race
  inside file/FSCTL sequences instead of falling back to unrelated shallow
  scaffolding.
- when several deep calls exist in the same family, the Windows selector now
  also prefers calls that share the same underlying resource root as the
  deepest call, so collide/rerun budget stays inside the same accepted socket,
  connected socket, or file-handle lineage where possible.
- inside the same family/root, the selector now also uses an explicit race
  priority ordering so accept-side and connected data-path I/O outrank socket
  option toggles, and NT file/FSCTL operations outrank shallower Win32 file
  wrappers when choosing the primary collide target.

This is important for Windows because setup helpers are often fragile and
concurrency budget is more valuable on deeper state transitions.

### 3.5 Triage, hints, corpus persistence

Files:

- `pkg/fuzzer/fuzzer.go`
- `pkg/fuzzer/job.go`
- `pkg/fuzzer/fuzzer_test.go`

Effects:

- helper-only signal can be skipped at triage entry;
- helper calls can be skipped as corpus owners;
- helper calls can be skipped for comparison-driven hints jobs;
- when several calls in the same program compete for triage ownership, deeper
  calls can replace shallower ones.
- the generic layers now share common target-level relevance helpers instead of
  open-coding separate score/threshold checks at each use site.
- hints, triage, and mutation-target selection now all consult the same
  target-level eligibility helpers for helper filtering plus relevance
  thresholds.
- helper classification itself is now also normalized behind shared target-level
  helper checks rather than being re-tested ad hoc at each use site.
- generation-bias source selection now uses the same style of target-level
  eligibility helpers as well, rather than keeping a separate local filter.

This keeps stable signal, hints effort, and corpus focus aligned with deeper
	target calls instead of setup noise.

### 3.6 Config parsing and machine-check visibility

Files:

- `pkg/mgrconfig/load.go`
- `prog/resources.go`
- `sys/windows/init.go`
- `pkg/mgrconfig/load_test.go`

Effects:

- `ExpandEnabledCalls` runs during enabled-syscall parsing;
- helper/scaffold auto-expansion happens before manager runtime starts;
- explicitly disabled syscalls still win over auto-expansion;
- machine-check sees the expanded syscall set, not just the handwritten config.
- the implementation is now organized as small stage-closure helpers instead
  of a single large block of per-syscall conditionals.

This is a key step toward Linux-like ergonomics: configs can name deeper target
ops, while the target fills in required scaffolding.

## 4. Windows Socket Resource Layering

The current network description lives in:

- `sys/windows/socket_nyx.txt`

Current socket-related resources include:

- `SOCKET`
- `SOCKET_TCP[SOCKET]`
- `SOCKET_UDP[SOCKET]`
- `SOCKET_LISTENER[SOCKET_TCP]`
- `SOCKET_CONNECTED[SOCKET_TCP]`
- `SOCKET_ACCEPT[SOCKET_TCP]`

This is already enough to distinguish generic TCP setup, listener-side state,
connected-side state, and accept-side data paths. The model is still partial,
but listener/connected/accept are now explicit active resources rather than
purely score-driven conventions.

Current stage-oriented syscall naming includes:

- constructors:
  - `socket$inet_tcp`
  - `socket$listener_tcp`
  - `socket$connected_tcp`
  - `socket$inet_udp`
  - `socket$accept_tcp`
- setup:
  - `bind$inet_tcp`
  - `bind$inet_udp`
  - `connect$inet_tcp`
  - `connect$inet_udp`
  - `listen$inet_tcp`
  - `accept$inet_tcp`
- data-path:
  - `send$inet_tcp`
  - `send$inet_udp`
  - `send$inet_accept`
  - `recv$inet_tcp`
  - `recv$inet_udp`
  - `recv$inet_accept`
- mode/options:
  - `ioctlsocket$fionbio_tcp`
  - `ioctlsocket$fionbio_udp`
  - `ioctlsocket$fionbio_accept`
  - `setsockopt$int_tcp`
  - `setsockopt$int_udp`
  - `setsockopt$int_accept`
  - `getsockopt$int_tcp`
  - `getsockopt$int_udp`
  - `getsockopt$int_accept`
- deeper AFD/Winsock paths:
  - `AcceptEx$inet_tcp`
  - `WSARecvEx$inet_accept`
  - `TransmitFile$inet_accept`

The current design intentionally keeps UDP and TCP separated, and it also
distinguishes accept-side sockets from ordinary TCP sockets.

## 5. Auto-Scaffold Expansion Rules

The Windows target now auto-adds:

### 5.1 Global helpers

- `VirtualAlloc`
- `CloseHandle`
- `CreateFileA`
- `CreateFile2`
- `WSAStartup`
- `WSACleanup`
- `socket$inet_tcp`
- `socket$listener_tcp`
- `socket$connected_tcp`
- `socket$inet_udp`
- `socket$accept_tcp`
- `closesocket$any`

depending on the requested deep target call family.

### 5.2 Network structural scaffold

Depending on the requested call, the target can automatically add:

- `bind$inet_tcp`
- `listen$inet_tcp`
- `accept$inet_tcp`
- `connect$inet_tcp`
- `connect$inet_udp`

The implementation is now grouped as explicit closure helpers:

- TCP/listener/connected/accept closure
- UDP closure
- file-handle closure

The top-level dispatch is also now resource-role driven:

- calls touching TCP/listener/connected/accept resources route into the TCP closure
- calls touching UDP resources route into the UDP closure
- calls touching file-handle paths route into the file closure

Inside the TCP closure, the logic is now further split into smaller
responsibilities:

- listener scaffold
- connected scaffold
- accept scaffold
- peer-traffic scaffold
- file-payload scaffold

The peer-traffic part is now explicit enough to describe which sender-side
operation should be added for a given receive-oriented path, rather than only
tracking a boolean "needs peer traffic" decision.

The closure facet also owns the small resource-role predicates used by these
decisions, so input/create-resource checks are no longer left as unrelated
top-level helpers.

This keeps the behavior the same while making it easier to extend the closure
logic toward richer NT/AFD state models later.

### 5.3 Minimal data-path scaffold

For deeper network calls, the target may also auto-add a minimal peer/file path:

- `send$inet_tcp` for accept-side receive paths
- `WriteFile` for `TransmitFile$inet_accept`

### 5.4 File/NTFS scaffold

For file/FSCTL calls, the target can auto-add:

- `CreateFileA`
- `CreateFile2`
- `CloseHandle`
- `NtReadFile`
- `NtWriteFile`
- `NtFsControlFile`

This is already sufficient to let several Windows configs shrink compared to
their earlier fully explicit helper lists.

## 6. Current Config Direction

Representative configs:

- `tools/syz-nyx-runner/windows-nyx-none.cfg`
- `tools/syz-nyx-runner/windows-nyx-ntfs-none.cfg`
- `tools/syz-nyx-runner/windows-nyx-fsctl-none.cfg`
- `tools/syz-nyx-runner/windows-nyx-network-none.cfg`
- `tools/syz-nyx-runner/windows-nyx-afd-none.cfg`

These configs are being progressively reduced from:

- explicit declaration of all helpers and setup calls

to:

- primarily declaring deeper target calls
- letting the target infer minimum required setup

This is still in progress, but the direction is deliberate and important.

The new `windows-nyx-afd-none.cfg` is the most target-focused configuration so
far for the AFD/Winsock path. It intentionally keeps mostly deeper accept-side
and data-path operations and relies on target-level expansion to reconstruct the
minimum socket/listener/connect/file scaffolding. It now also explicitly sets
`experimental.windows_target_profile = "afd"`.

The `windows-nyx-fsctl-none.cfg` configuration now serves as the analogous
minimal example for file/FSCTL fuzzing: it can be reduced to `NtFsControlFile`
and still rely on target-level expansion to recover the minimum file-handle
scaffolding. It now explicitly sets
`experimental.windows_target_profile = "fsctl"`.

The `windows-nyx-afd-none.cfg` configuration now serves as the analogous
minimal example for AFD/Winsock fuzzing: it can be reduced to a very small
set of deep accept-side and transmit-oriented calls while the target rebuilds
the minimum socket/listener/file scaffolding.

At this point the configs demonstrate 2 important properties:

1. deep target calls can be listed without all helper/syscall scaffolding;
2. the target can reconstruct enough state to make these configs meaningful.

However, the configs should still be treated as *focused experimental
configurations*, not yet as proof that the Windows target has reached full
Linux-like maturity.

## 7. Sparse Table / Bootstrap Synchronization

When network/file descriptions change, the following must be kept in sync:

- `executor/syscalls_windows_nyx_demo.h`
- `tools/syz-nyx-runner/main.go`
- `tools/syz-nyx-runner/windows_demo_test.go`

The Windows Nyx path currently relies on:

- sparse executor syscall table entries matching target IDs;
- deterministic standalone bootstrap programs that construct the minimum state
  needed for each deep path.

The standalone/bootstrap side is now aligned with the resource layering:

- listener-side scaffolds use `socket$listener_tcp`;
- connected-side scaffolds use `socket$connected_tcp`;
- accept-side overlapped paths use `socket$accept_tcp` plus
  `accept$inet_tcp`/`AcceptEx$inet_tcp` as appropriate.
- receive-oriented bootstrap programs now also construct explicit peer traffic
  when the path expects inbound data, instead of only exercising empty
  nonblocking receive cases.
  In particular, TCP receive bootstrap now models server-side peer send followed
  by client-side receive, rather than attempting to receive from the same socket
  endpoint that performed the send.
  UDP receive bootstrap now also models explicit peer-side send before receive,
  rather than a bare nonblocking read on an otherwise idle socket.

The standalone socket bootstrap builder has also started to share common helper
fragments for listener/client/accept setup instead of relying only on repeated
handwritten program strings.
This now also includes shared accept-session and peer-send fragments for
receive-oriented accept/TCP paths, which helps keep the bootstrap semantics
consistent when these paths are refined further.
Accept-side option and receive bootstrap paths now reuse the same accepted-session
builder as well, reducing the chance that one path quietly drifts away from the
others as the modeled interaction evolves.
The same shared accept-session builder is now also used by accept-side
transmit and socket-option bootstrap paths, so the broader accept-side family
stays aligned on one minimal session shape.
This means a larger portion of the accept-side bootstrap family now shares one
common listener/client/accept session skeleton, with only the terminal action
varying between receive, socket-option, and transmit-style paths.
Receive, nonblocking-accept, and WSA receive bootstrap variants now also share
common peer-send and close fragments on top of that accepted-session skeleton.
The builder coverage now also extends to the AcceptEx accept-socket session
shape, so both ordinary accept-side and AcceptEx-oriented bootstrap paths are
moving toward the same reusable session vocabulary.
Sender-side connected-socket send actions are also beginning to share explicit
builder fragments, further reducing repeated handwritten action tails in the
socket bootstrap family.
Accept-side send and file-payload preparation now also have explicit action
fragments, so both ordinary send and transmit-style tails are moving into the
same reusable builder vocabulary.
UDP connected-session and bound-receiver bootstrap are now also beginning to
share explicit builder fragments, so this normalization is no longer limited to
the TCP/accept-side half of the network surface.
The naming inside this bootstrap layer is also being normalized around
session/action concepts, which helps keep the growing builder vocabulary
coherent as more deep-path variants are folded into it.
Accept-side option/transmit paths are now also converging on a shared close
sequence helper, so their teardown logic stays aligned with the same session
shape used by the rest of the accept-side family.
Common "accepted session + peer send" combinations are now also represented
directly, so the most frequent accept-side dataflow setups are no longer
assembled ad hoc at every call site.
The bootstrap tests are also increasingly checking action ordering, not just
presence, so regressions in the minimal interaction sequence are more likely to
be caught when these builders evolve.
There are now also source-level regression checks that pin key deep-path
standalone cases to the shared builder fragments, so accidental drift back
toward ad hoc handwritten sequences is easier to catch.

This means syscall renames or resource-type refinements should always be
followed by:

1. regenerating descriptions with `bin/syz-sysgen`;
2. updating sparse syscall names/IDs;
3. updating standalone bootstrap programs;
4. running Windows-specific tests.

## 8. Current Validation Surface

The most important current validation points are:

- `go test ./prog ...`
- `go test ./pkg/fuzzer ...`
- `go test ./pkg/mgrconfig ...`
- `go test ./sys/windows -count=1`
- `go test ./tools/syz-nyx-runner -count=1`

Representative tests:

- helper deprioritization / bias tests
- resource-centric preference tests
- collide preference tests
- Windows triage/corpus/hints skipping tests
- config expansion tests
- Windows socket hierarchy tests
- standalone bootstrap path tests

## 9. Known Limits

The current model is still heuristic-heavy.

In particular:

- listener / connected / accept / overlapped states are still not a complete
  object-state machine even though they are now distinct explicit resources;
- some state transitions are still approximated with syscall-name-based scoring;
- `ExpandEnabledCalls` currently implements only a small set of hand-written
  closures rather than a fully generic state-closure engine;
- target-level scoring still plays a significant role because resource types do
  not yet encode all interesting AFD/NT object transitions;
- full `make generate` may still require local `flatc` availability even though
  `bin/syz-sysgen` is enough to regenerate syscall descriptions and target blobs.

## 10. Recommended Next Steps

The highest-value next directions are:

1. turn network/file expansion rules into explicit stage-closure helpers
   (accept-side closure, transmit-file closure, connected TCP closure, etc.);
2. refine AFD/Winsock object-state modeling beyond current resource aliases;
3. connect these state distinctions to hints/mutation relevance even more
   directly, not only through call names;
4. eventually move from "minimum scaffold" expansion toward "minimum valid state
   closure" expansion for deeper target calls.
