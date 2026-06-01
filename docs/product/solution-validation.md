# Stave launch plan: validating the solution

The problem is validated. Aikido 2026 surveyed 500+ CISOs and security engineers; the pain points are real and documented. The metrics document translates those pain points into six output-model responses. The implementation plan sequences the engineering work. What's missing is the plan that gets the built product in front of the people who felt the pain, in a form where they can fairly compare Stave to what they already use, and give Stave the signal it needs to know which metric formulations land and which don't.

This plan has two constraints that shape every decision below. First, the solution formulations are medium-confidence; the release has to be shaped so that negative feedback produces revision signals, not demoralization or premature pivots. Second, Stave is a deterministic detection tool with no commercial motion yet — the release can't assume a sales pipeline, a paid-pilot structure, or a customer success function. Everything runs on practitioner goodwill and the quality of the artifact.

## The core release discipline

A validation-focused release optimizes for **falsifiable signal per unit of practitioner attention**. Every release artifact either generates signal on a specific metric formulation or justifies why it doesn't. Three properties follow from that:

**Honest comparisons as reproducible evidence, not marketing claims.** Stave ships with a Docker Compose harness that runs both Stave and Prowler against the same fixtures in identical conditions. Practitioners generate the side-by-side comparison themselves on their own machines; no one has to trust the author. If Prowler's output reads faster for a given finding, it shows in the output the reader sees with their own eyes. The reproducibility is what earns the trust; the written commentary is secondary.

**Adoption friction as close to zero as possible.** The Aikido finding on tool adoption friction applies to Stave itself. A practitioner who spends fifteen minutes figuring out how to run Stave before seeing their first finding has already decided whether to come back, and the answer isn't usually yes. Install-to-first-finding time is a release-blocking metric. `docker compose up` is the canonical "I already know how to run this" command for a working engineer.

**One validation checkpoint per release artifact.** The implementation plan already names six metric-specific validation checkpoints. Each artifact in the release is mapped to one of them; if an artifact doesn't run against a checkpoint, it gets cut.

## Pre-release: the artifacts that have to exist

The release isn't shipping code — the code will ship when the metrics implementation lands. The release is shipping the **narrative around the code plus the primary evidence for its claims**, and both need specific artifacts.

**The Docker Compose comparison harness.** A separate public repository, named something like `stave-comparison` or `cloud-security-tool-bench`, containing a Compose file that runs pinned versions of Stave and Prowler against the same fixture set with identical invocation conditions. The user clones the repo, runs one command, and sees both tools' output side-by-side for each fixture. This is the single most important release artifact; it subsumes what a written comparison document could do and does it as reader-verifiable evidence rather than author-mediated claim. Key design decisions:

- **Identical conditions.** Same fixture on disk, same invocation wrapper, same output capture. The harness script is public so anyone can verify neither tool is handicapped. Each tool runs with its strongest available flags; if Prowler needs specific configuration to produce its best output, that configuration is set.
- **Fixtures are inspectable.** Each fixture directory contains the snapshot JSON, a README naming the real incident it models, and a "what to look for" section pointing at the findings that matter. Practitioners can read the snapshot, see the misconfiguration, then read both tools' output.
- **Side-by-side rendering.** Text outputs render in a split view, or sequentially with clear delimiters, so the reader doesn't Alt-Tab to compare. Both tools' raw JSON is saved to mounted volumes for readers who want to pipe through `jq` and explore.
- **Version pinning is foundational.** Compose file names the exact Stave and Prowler versions. When either updates, a new tag releases the comparison at the new versions. Floating `latest` tags produce output drift that destroys the artifact's trust within weeks.
- **Deterministic and offline.** The image contains both tools, the fixtures, and the harness scripts. No real AWS credentials required for the included comparisons. Running the comparison today and a year from now produces identical outputs for the pinned versions.

**A pre-generated set of fixtures that reproduce real incidents.** The existing HackerOne-derived fixtures are the foundation. Round them out to five or six scenarios covering distinct incident shapes: S3 exposure (Capital One class), overprivileged IAM (Shopify class), credential rotation lapse, cross-account misconfiguration, CloudFront bypass. Each fixture has a short README explaining the real incident it models and what both tools find on it. Anyone can run the harness and see both tools working on something they've read about in the news.

Critical fairness constraint: for each fixture, run Prowler first and note what it finds before authoring any comparison narrative. If Prowler finds nothing and Stave finds a lot, flag that explicitly — either as a fair differentiation or as fixture selection bias, and let the reader decide. Equally important: include at least one fixture where Prowler's output is genuinely better (clearer remediation, more precise finding, easier scan). A comparison where Stave wins every round reads as marketing; one where Stave loses a round and names it reads as evidence. Showing Stave's weaknesses honestly is what makes its strengths credible.

**The install-to-first-finding path for Stave itself.** Separate from the comparison harness, Stave's own repo needs the minimal-friction path. One command installs Stave. A second command runs it against an included fixture. A third runs it against the practitioner's own snapshot. Time from `git clone` to first finding on their own data: under ten minutes on a laptop with AWS credentials configured. Every step beyond those three is friction that gets counted as a bug.

**The "why I built this" post.** Not a launch announcement. A technical post explaining the specific Aikido findings Stave responds to, the six metrics that translate those findings into design constraints, and the architectural decisions (credential-free, hexagonal, vendor-agnostic core) that follow. The post's call to action is concrete: `git clone && docker compose up`, three minutes, produces primary evidence the reader can inspect. This is already in progress via the HackerNoon editorial review; the timing of the revised post and the release should align.

**The coverage-posture document, not yet the feature.** Metric 6's full implementation can wait, but the document version — "here's exactly which Prowler S3 checks Stave covers, which it doesn't, and why" — can ship as markdown in the repo before the runtime feature lands. This establishes the consolidation-over-displacement positioning without requiring the implementation to be complete.

## Harness maintenance and credibility

The harness is only evidence if it stays current and fair. Two structural risks, two responses:

**Who maintains the harness over time.** If Stave's team is the only maintainer and Stave's behavior improves faster than Prowler's, the comparison drifts in Stave's favor by default. This is a real structural bias that has to be managed, not assumed away.

- *Invite Prowler's team to co-maintain*, on record, in the repo README. Their incentive to participate is weak and they may decline, but an open invitation documents that Stave isn't running a captured benchmark. A polite refusal on record is better than no invitation.
- *Commit to automated periodic re-runs.* Every release of either tool triggers a regenerated comparison. The harness is CI-runnable. When Prowler adds a check that now covers something Stave previously uniquely found, the comparison updates and says so. This is maintenance work forever, but it's the price of the artifact staying credible.

**Pre-publication courtesy.** Run the repository past the Prowler team privately before publishing. They don't have a veto, but the comparison reads very differently depending on whether they've been consulted. A courteous heads-up costs nothing and the feedback might shape the harness. Launching a public benchmark against another open-source project without a heads-up reads as adversarial even when it isn't meant to be.

## Validation cohort design

The release needs feedback from three distinct cohorts, each answering different questions.

**Cohort A: peer tool authors.** Five to eight people who maintain or have contributed to Prowler, ScoutSuite, Cloudsploit, or similar open-source cloud security tools. They understand the problem space, they've made their own tradeoffs, and they can evaluate both Stave's architectural choices and — critically — the fairness of the comparison harness on merit. Their feedback validates whether the engineering is defensible and whether the harness is honest. The ask is specific: run the harness, inspect it for fairness (are Prowler's flags optimal? Are the fixtures fairly selected?), open issues where they see gaps or disagree with positioning. This cohort is recruited through direct outreach, one conversation at a time, not through broadcast. A Prowler contributor filing a PR that tightens Prowler's invocation in the harness is the strongest possible credibility signal — the work becomes evidence Stave couldn't have bought. Success signal: at least three substantive technical issues filed within two weeks, and at least one from someone associated with Prowler or ScoutSuite.

**Cohort B: working cloud security engineers.** Fifteen to twenty practitioners who currently run at least one of Prowler, ScoutSuite, AWS Security Hub, or a commercial CSPM in their job. They care about whether the output is actionable, not whether the architecture is elegant. The ask is lower-friction than it was in earlier versions of this plan: run the comparison harness on the included fixtures first, then on a sanitized version of their own snapshot, and fill out a short structured feedback form keyed to the six metrics. The form asks, for each metric, whether Stave's output is better, worse, or equivalent to their current tool, with space for specifics. Because they're already seeing both outputs side-by-side in the harness, the feedback is richer than either tool in isolation could produce. This cohort is recruited through the curated GitHub lists, cloud security Slack and Discord communities, and targeted newsletter mentions. Success signal: ten completed feedback forms, with at least five identifying at least one metric where Stave wins on their own data.

**Cohort C: prominent security researchers.** Two to four highly visible voices in cloud security (people who write incident analyses, publish research, speak at conferences). The ask is different and smaller: run the comparison harness on the Capital One fixture, read the "why I built this" post, and either publicly engage or privately tell you why they won't. Researchers respond to primary evidence, and a reproducible benchmark is primary evidence — stronger than any written comparison. When a known researcher takes Stave seriously enough to critique it, that's the moment practitioners in Cohort B start taking it seriously too. Success signal: one public engagement of any form (blog mention, tweet thread, conference citation, opened issue with substantive commentary).

The cohorts run in sequence, not in parallel. A negative signal from Cohort A means the harness is unfair or the engineering is soft, and that needs to be fixed before Cohort B sees anything. A negative signal from Cohort B means a metric formulation is wrong, and that needs to be absorbed before expanding to Cohort C. Serialized feedback loops let the product improve between cohorts; parallel outreach burns all three audiences on a version that might still be broken.

## The feedback instruments

Three instruments collect the signal the validation checkpoints need.

**The structured feedback form for Cohort B.** Six sections, one per metric. Each section has the same three questions: "For finding X in the harness output, did Stave's output help you understand it faster, slower, or the same as Prowler's?", "What specifically was better or worse?", and "Is there information you wanted that wasn't there?" Free-text only — no Likert scales, no NPS. The goal is verbatim practitioner language that can feed back into control descriptions, translation tables, and metric formulations. Forms are completed in a single sitting, take no more than twenty minutes, and are reviewed within a week of submission. Feedback summaries (with PII stripped) are published back to the community within a month, so Cohort B sees that their input matters and Cohort C sees the responsiveness.

**The "reach-for-the-top" observation.** For every practitioner who runs Stave on their own snapshot, capture one specific interaction: do they scroll to the top of the findings list and start there, or do they scroll to find a specific asset, or do they ask "where do I start?" The answer validates Metric 1 directly. This isn't instrumented code — it's the first question asked in every feedback conversation and session. Three hours of video calls with three practitioners tells you more about whether the default sort lands than a thousand downloads.

**The "explain this finding" exercise.** Pick one finding from a shared fixture. Show a practitioner Stave's text-mode output alongside Prowler's output for the same finding. Ask them, in their own words, what each says. Compare their explanation to what each finding was trying to convey. Where Stave's gap is larger than Prowler's, the translation adapter or the matched-clauses emission isn't working; where Stave's gap is smaller, Metrics 3 and 5 are landing. The comparison framing makes the signal sharper — practitioners aren't rating Stave in isolation, they're rating it against a tool they already know. This exercise takes ten minutes per practitioner and produces the strongest signal on the hardest-to-validate metric formulations. Run it with at least ten people from Cohort B.

## Release sequencing

The release unfolds in four phases, each gated on the previous one's validation signal.

**Phase 1: foundations, weeks 0–3.** The Docker Compose comparison harness is built and polished. Five incident-reproducing fixtures ship in the harness repo with READMEs. Prowler's team receives a private heads-up. The install-to-first-finding path for Stave itself is smoke-tested on macOS, Ubuntu, and a fresh EC2 instance. The "why I built this" post is published. Cohort A outreach begins — one conversation at a time, not a broadcast. The metrics implementation for M1 (default sort, breakdown on every finding) is merged and in the release build; M2 through M6 remain as documented future work, honest about what's built and what isn't.

**Phase 2: peer validation, weeks 3–6.** Cohort A has had three weeks with the harness. Their issues and feedback are triaged in public. Material critiques — especially about harness fairness — trigger revisions before Phase 3 begins. If a Prowler contributor files a PR that improves Prowler's invocation flags, it gets merged; the updated comparison reflects the improvement. This phase's honesty is what Cohort B will pattern-match on when they see it; a repo with unresolved peer critiques closed rudely or silently signals the opposite of the reception you want. If Cohort A's feedback surfaces a metric formulation that's wrong, the release schedule adjusts — landing M3 (traceability) can shift earlier if reasoning shape is the critical gap.

**Phase 3: practitioner validation, weeks 6–12.** Cohort B outreach begins. The curated GitHub lists, community channels, and newsletters get coordinated mentions over a two-week window — not a single-day launch push. The ask leads with the harness: "clone, run one command, see both tools on the same fixtures." Feedback forms flow in over a month. The "reach-for-the-top" and "explain this finding" exercises run with subsets of Cohort B. Feedback summaries are published monthly. By the end of this phase, there should be qualitative signal on every metric: which are clearly landing, which are ambiguous, which need formulation revision.

**Phase 4: researcher engagement, weeks 12+.** Cohort C engagement is the latest because it depends on the artifact already having survived peer review. The approach is low-key: send the harness link and the "why I built this" post to four researchers with a short note, once. No follow-up, no pitch. The reproducible benchmark is the reason to engage; the rest is context. Some will engage, some won't. The ones who do are the signal that Stave has entered the public conversation. The ones who don't aren't a failure — they're just not the moment.

## What success looks like and what it doesn't

Success at the end of Phase 3 is not downloads or stars. It's a specific set of qualitative signals:

- At least five practitioners in Cohort B identified at least one metric where Stave's output beat their current tool on their own data.
- At least one formulation in the metrics document has been revised based on Cohort B feedback. (If none has, that's suspicious — either the outreach is too narrow or the feedback is too polite.)
- The public feedback summary shows a pattern: which problems practitioners felt most acutely, which Stave responses landed, and which didn't.
- At least one Cohort A contributor filed a substantive PR or issue that shaped the engineering or the harness fairness.

Success at the end of Phase 4 adds one more signal: a public mention from someone in Cohort C that a third-party practitioner would find credible.

What shouldn't be treated as success: download counts, GitHub stars, Hacker News front-page placement, a post going viral. Those are attention metrics, not validation metrics. They measure whether the launch was interesting, not whether the product solves the problem. The Aikido survey validated the problem; the only thing left to validate is whether the solution does what the design document says it does. That requires specific people giving specific feedback about their specific environments, with the comparison harness as the shared reference point. Nothing else substitutes for it.

## The honest failure mode

The risk this plan can't fully eliminate is that Cohort B's feedback is polite-but-lukewarm across all six metrics. No strong wins, no strong losses, just "this is nice, thanks." That outcome would mean the metric formulations are internally coherent and externally unmoving, and the most likely interpretation is that the metrics are the wrong response to the surveyed pain — not that the pain isn't real, but that the specific solutions aren't what practitioners were hoping for.

If that's what the feedback says, the honest move is to absorb it publicly, name it as a formulation miss rather than a product failure, and use the specific nature of the lukewarm feedback to revise the metrics document. The Aikido problem framing stays; the solution framing gets revised; a second release cycle runs against the revised formulations, with the harness providing continuity of evidence across cycles. This is the slow version of iteration, but it's the one that stays honest to the evidence.

What this plan deliberately avoids: pivoting based on feedback from people who didn't run the harness. If someone has an opinion about Stave without having run the comparison, that opinion carries no weight in the validation loop — however well-credentialed the speaker. Validation only comes from practitioner engagement with the actual artifact on actual data. That discipline is what separates a product that stays honest to its evidence from one that drifts toward whoever is loudest.

---

**Public demo (`stave/compare` or similar):** airgapped, pre-baked fixtures only, no credential code paths, public registry. Purpose: risk-free prospect evaluation. The no-network guarantee is structural (enforced by `network_mode: none`), not promised in prose.

**Internal diagnostic (`stave-support`):** live credentials, fresh extraction per session, private registry, access-controlled. Purpose: reproducing client-reported bugs against real state.

The only shared piece is the harness runner — a small library that takes `(snapshot_source, output_dir)` and produces side-by-side comparison. Everything else diverges because the threat models genuinely conflict.

The extractor-regression story moves to **Stave's CI** using the same fixture set the public image ships — it's a test, not a third image. Public image demonstrates evaluation; CI differential demonstrates reliability; no artifact tries to do both jobs.

Pick names that can't be confused from day one.







