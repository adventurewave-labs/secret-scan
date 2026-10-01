# SOTA roadmap

Working backlog for bringing secretscan up to the level of gitleaks,
TruffleHog, Kingfisher and Nosey Parker. Items are ordered; each one is sized
to land as a single tested commit on the `claude/sota-loop` branch.

## Rules for every item

1. One item per iteration. Finish it or leave the tree clean.
2. Every behaviour change ships with a test in `tests/`. Token fixtures are
   assembled at runtime (see `tests/sota_features_test.rs`) so no
   credential-shaped literal is committed.
3. Before committing: the CI test command in `.github/workflows/ci.yml` passes
   and `cargo clippy --all-features --all-targets` reports no new warnings.
4. No performance or accuracy number goes into the README unless a command in
   this repo reproduces it. Measured numbers are recorded in the log below with
   the command that produced them.
5. No network calls from tests, and no paid API calls anywhere.
6. Update `CHANGELOG.md`, tick the item here, add a line to the log.

## Done

- [x] SARIF 2.1.0 output, `--redact`, inline `secretscan:allow`, stable
      fingerprints, deterministic ordering, reproducible entropy, eight modern
      token formats, `--version` fix

## Backlog

- [x] **1. Single rule table.** Replace the two hand-maintained pattern maps in
      `src/patterns.rs` with one `Rule { id, name, regex, keywords, severity,
      min_entropy }` table; derive both maps from it. Unblocks everything below.
- [x] **2. Prefilter.** Done with a `RegexSet` over all rules instead of
      hand-written keywords: it is built from the regexes it gates, so it cannot
      drift or cause false negatives. The `keywords` field on `Rule` is unused.
- [ ] **3. Drop the UUID rules.** "Heroku API Key" and "Azure Tenant ID" match
      every UUID. Require a provider keyword on the line, or remove them.
- [ ] **4. Private-key dedupe.** One PEM block currently yields up to three
      findings (RSA / Generic / Multi-line). Report it once.
- [ ] **5. Remove debug output.** Delete the `[DEBUG]` `eprintln!` calls and the
      duplicated static/instance scan paths in `src/scanner.rs`.
- [ ] **6. Severity and confidence.** Add both to rules, JSON and SARIF
      (`level`, `security-severity`); add `--min-severity`.
- [ ] **7. Baseline.** `--baseline <file>` suppresses known fingerprints;
      `--write-baseline <file>` records them. Exit code reflects new findings only.
- [ ] **8. Config file.** `.secretscan.toml`: allowlisted paths, regexes and
      fingerprints, disabled rules, custom rules.
- [ ] **9. Stopwords and placeholders.** Reject values such as `EXAMPLE`,
      `changeme`, `xxxx`, `<your-key>` and repeated-character runs for generic
      rules, as gitleaks does.
- [ ] **10. Exit-code control.** `--exit-code <n>` and `--no-fail`, so the tool
      can run in report-only mode in CI.
- [ ] **11. Git history scan.** `--git` walks commits via `git log -p` and
      reports commit, author and date; `--since <rev>` for incremental scans.
- [ ] **12. Staged scan and pre-commit hook.** `--staged`, plus a
      `.pre-commit-hooks.yaml` so the repo works with pre-commit.
- [ ] **13. Stdin.** `secretscan -` reads from a pipe.
- [ ] **14. More providers.** Azure storage keys, GCP service-account JSON,
      Databricks, Datadog, Cloudflare, Vercel, Supabase, Telegram, Postman,
      Linear, Notion, Doppler, Age keys, Docker Hub PATs.
- [ ] **15. Offline structural validation.** Checksums that can be verified
      without a network call: GitHub token CRC32 suffix, npm token checksum,
      JWT header/payload decoding. Sets confidence to high.
- [ ] **16. Labelled accuracy corpus.** `tests/corpus/` with positives and
      negatives per rule and a test that reports precision and recall, so
      accuracy claims are reproducible.
- [ ] **17. GitHub Action.** `action.yml` that runs the scan and uploads SARIF.
- [ ] **18. Benchmarks.** Make `benches/scanning.rs` cover the prefilter path;
      document how to run it.
- [ ] **19. Repo hygiene.** Move `correctiveaction.md` and
      `secret-scan-test-report.md` out of the root or delete them; fix the
      empty 0.2.0/0.2.1 changelog entries; `cargo fmt` and a fmt check in CI.
- [ ] **20. Opt-in live verification.** `--verify` behind a cargo feature that
      is off by default. Design note only until the owner asks for it.

## Log

- Seed commit: items under "Done". CI test subset 55 → 65 tests passing.
  (An earlier version of this line said 65 → 75; that was a miscount.)
- Loop 1: item 1. `RULE_DEFS` in `src/patterns.rs` is now the only place rules
  are defined (378 → 332 lines, 259 deleted). `secretscan -q -f json test-repo`
  output is byte-identical before and after. CI test subset 65 → 70.
- Loop 2: item 2. `time ./target/release/secretscan -q -f json .` on this repo
  (80 tracked files, 2 cores): 3.96 s → 0.145 s. Two changes are combined in
  that number and were not measured separately: four regexes in
  `analyze_obfuscated_secrets_static` were recompiled for every line (now
  compiled once), and the `RegexSet` prefilter. Findings are identical before
  and after (`test-repo` byte-identical). CI test subset 70 → 74.
