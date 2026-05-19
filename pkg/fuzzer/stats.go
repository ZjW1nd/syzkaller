// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"sync/atomic"

	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

type Stats struct {
	// Indexed by prog.Syscall.ID + the last element for extra/remote.
	Syscalls []SyscallStats

	statCandidates                  *stat.Val
	statNewInputs                   *stat.Val
	statJobs                        *stat.Val
	statJobsTriage                  *stat.Val
	statJobsTriageCandidate         *stat.Val
	statJobsSmash                   *stat.Val
	statJobsFaultInjection          *stat.Val
	statJobsHints                   *stat.Val
	statExecTime                    *stat.Val
	statExecGenerate                *stat.Val
	statExecFuzz                    *stat.Val
	statExecCandidate               *stat.Val
	statExecTriage                  *stat.Val
	statExecMinimize                *stat.Val
	statExecSmash                   *stat.Val
	statExecFaultInject             *stat.Val
	statExecHint                    *stat.Val
	statExecSeed                    *stat.Val
	statExecCollide                 *stat.Val
	statCoverOverflows              *stat.Val
	statCompsOverflows              *stat.Val
	statTemplateGen                 *stat.Val
	statTemplateCorpus              *stat.Val
	statTemplateCollide             *stat.Val
	statResourceCentricTry          *stat.Val
	statResourceCentricHit          *stat.Val
	statResourceCentricNoCandidates *stat.Val
	statResourceCentricZeroScore    *stat.Val
}

type SyscallStats struct {
	// Number of times coverage buffer for this syscall has overflowed.
	CoverOverflows atomic.Uint64
	// Number of times comparisons buffer for this syscall has overflowed.
	CompsOverflows atomic.Uint64
}

func newStats(target *prog.Target) Stats {
	return Stats{
		Syscalls: make([]SyscallStats, len(target.Syscalls)+1),
		statCandidates: stat.New("candidates", "Number of candidate programs in triage queue",
			stat.Console, stat.Graph("corpus")),
		statNewInputs: stat.New("new inputs", "Potential untriaged corpus candidates",
			stat.Graph("corpus")),
		statJobs: stat.New("fuzzer jobs", "Total running fuzzer jobs", stat.NoGraph),
		statJobsTriage: stat.New("triage jobs", "Running triage jobs", stat.StackedGraph("jobs"),
			stat.Link("/jobs?type=triage")),
		statJobsTriageCandidate: stat.New("candidate triage jobs", "Running candidate triage jobs",
			stat.StackedGraph("jobs"), stat.Link("/jobs?type=triage")),
		statJobsSmash: stat.New("smash jobs", "Running smash jobs", stat.StackedGraph("jobs"),
			stat.Link("/jobs?type=smash")),
		statJobsFaultInjection: stat.New("fault jobs", "Running fault injection jobs", stat.StackedGraph("jobs")),
		statJobsHints: stat.New("hints jobs", "Running hints jobs", stat.StackedGraph("jobs"),
			stat.Link("/jobs?type=hints")),
		statExecTime: stat.New("prog exec time", "Test program execution time (ms)", stat.Distribution{}),
		statExecGenerate: stat.New("exec gen", "Executions of generated programs", stat.Console, stat.Rate{},
			stat.StackedGraph("exec")),
		statExecFuzz: stat.New("exec fuzz", "Executions of mutated programs", stat.Console,
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecCandidate: stat.New("exec candidate", "Executions of candidate programs", stat.Console,
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecTriage: stat.New("exec triage", "Executions of corpus triage programs", stat.Console,
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecMinimize: stat.New("exec minimize", "Executions of programs during minimization",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecSmash: stat.New("exec smash", "Executions of smashed programs",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecFaultInject: stat.New("exec inject", "Executions of fault injection",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecHint: stat.New("exec hints", "Executions of programs generated using hints",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecSeed: stat.New("exec seeds", "Executions of programs for hints extraction",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecCollide: stat.New("exec collide", "Executions of programs in collide mode", stat.Console,
			stat.Rate{}, stat.StackedGraph("exec")),
		statCoverOverflows: stat.New("cover overflows", "Number of times the coverage buffer overflowed",
			stat.Rate{}, stat.NoGraph),
		statCompsOverflows: stat.New("comps overflows", "Number of times the comparisons buffer overflowed",
			stat.Rate{}, stat.NoGraph),
		statTemplateGen: stat.New("tmpl_gen", "Template-guided generation decisions",
			stat.Console, stat.Rate{}, stat.NoGraph),
		statTemplateCorpus: stat.New("tmpl_corpus", "Template-guided corpus borrowing decisions",
			stat.Console, stat.Rate{}, stat.NoGraph),
		statTemplateCollide: stat.New("tmpl_collide", "Template-guided collide decisions",
			stat.Console, stat.Rate{}, stat.NoGraph),
		statResourceCentricTry: stat.New("rc_try", "resourceCentric borrowing attempts",
			stat.Console, stat.Rate{}, stat.NoGraph),
		statResourceCentricHit: stat.New("rc_hit", "resourceCentric borrowing hits",
			stat.Console, stat.Rate{}, stat.NoGraph),
		statResourceCentricNoCandidates: stat.New("rc_no_candidates", "resourceCentric attempts with no compatible corpus candidates",
			stat.Console, stat.Rate{}, stat.NoGraph),
		statResourceCentricZeroScore: stat.New("rc_zero_score", "resourceCentric attempts where all corpus candidates scored zero",
			stat.Console, stat.Rate{}, stat.NoGraph),
	}
}
