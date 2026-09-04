# SPDX-License-Identifier: Apache-2.0

# ─── Repo identity ─────────────────────────────────────────────────────

variable "name" {
  type        = string
  description = "Repository name (without the owner prefix)."
}

variable "owner" {
  type        = string
  description = "GitHub owner (user or org) of the repository. Used to construct API URLs and the `repo_full_name` template variable. Must match the owner configured on the github provider passed in via `providers = { github = github.<alias> }`."
}

variable "description" {
  type        = string
  description = "One-line repo description shown on the GitHub page header."
}

variable "homepage_url" {
  type        = string
  description = "Optional homepage URL."
  default     = ""
}

variable "topics" {
  type        = list(string)
  description = "Repo topics. Lowercase, hyphenated."
  default     = []
}

variable "visibility" {
  type    = string
  default = "public"
  validation {
    condition     = contains(["public", "private", "internal"], var.visibility)
    error_message = "visibility must be one of: public, private, internal."
  }
}

# ─── Repo feature toggles ──────────────────────────────────────────────

variable "has_issues" {
  type    = bool
  default = true
}

variable "has_projects" {
  type    = bool
  default = false
}

variable "has_wiki" {
  type    = bool
  default = false
}

variable "has_discussions" {
  type    = bool
  default = false
}

variable "private_free_tier" {
  type        = bool
  description = <<-EOT
    Capability gate for the eight settings GitHub's free tier rejects with a 403
    on private repos: rulesets (protect_default_branch, protect_tag_pattern),
    vulnerability alerts, secret scanning (+ push protection), Dependabot
    security updates, dependency-review workflow, and private vulnerability
    reporting.

    Leave null (the default) to derive it from visibility, which is the correct
    behaviour for almost every caller: private means the features are
    unavailable and are forced off, public means they are free and apply. The
    gate re-evaluates on every plan, so flipping a repo public applies them and
    flipping it back private reverts them, with no second flag to keep in sync.

    Set it explicitly only to override that derivation: false on a private repo
    that really is on GitHub Pro/Team/GHAS (the features are available, so let
    them apply), or true to force everything off regardless of visibility.

    Individual feature vars still override downward, but cannot turn a feature
    ON while the gate is closed.
  EOT
  default     = null
}

variable "enable_vulnerability_alerts" {
  type        = bool
  description = "Enable Dependabot vulnerability alerts (free for public repos; requires GitHub Pro for private repos). Set false for private repos on the free tier."
  default     = true
}

# ─── Merge button + commit metadata ────────────────────────────────────

variable "allow_auto_merge" {
  type        = bool
  description = "Enable the auto-merge button on PRs (free for public repos; requires a paid plan for private repos). Forced off by the free-tier capability gate on private repos, where GitHub accepts the write but keeps reporting false, so asking for true yields a diff that never converges."
  default     = true
}

variable "allow_update_branch" {
  type        = bool
  description = "Show the 'Update branch' button on PRs so head branches can be fast-forwarded to base."
  default     = true
}

variable "web_commit_signoff_required" {
  type        = bool
  description = "Require all commits made through GitHub web (including merges) to be signed off."
  default     = true
}

variable "squash_merge_commit_title" {
  type        = string
  description = "Source of the squash commit's title. PR_TITLE uses the pull request title; COMMIT_OR_PR_TITLE picks the single-commit message or the PR title."
  default     = "PR_TITLE"
  validation {
    condition     = contains(["PR_TITLE", "COMMIT_OR_PR_TITLE"], var.squash_merge_commit_title)
    error_message = "Must be PR_TITLE or COMMIT_OR_PR_TITLE."
  }
}

variable "squash_merge_commit_message" {
  type        = string
  description = "Source of the squash commit's body. PR_BODY uses the pull request description; COMMIT_MESSAGES concatenates commit messages; BLANK leaves it empty."
  default     = "PR_BODY"
  validation {
    condition     = contains(["PR_BODY", "COMMIT_MESSAGES", "BLANK"], var.squash_merge_commit_message)
    error_message = "Must be PR_BODY, COMMIT_MESSAGES, or BLANK."
  }
}

# ─── Security analysis (free tier features only) ───────────────────────

variable "enable_secret_scanning" {
  type        = bool
  description = "Enable GitHub secret scanning. Free for public repos; requires GHAS for private repos. Set false for private free-tier repos."
  default     = true
}

variable "enable_secret_scanning_push_protection" {
  type        = bool
  description = "Block pushes that contain known secret patterns. Same availability as enable_secret_scanning."
  default     = true
}

variable "enable_dependabot_security_updates" {
  type        = bool
  description = "Enable Dependabot security updates (auto-PRs for CVEs in dependencies). Requires enable_vulnerability_alerts = true."
  default     = true
}

# ─── Labels ────────────────────────────────────────────────────────────

variable "manage_labels" {
  type        = bool
  description = "Manage the repo's full label set via TF. WARNING: labels not in the canonical + extra_labels list will be DELETED on apply. Set false to leave the repo's labels untouched."
  default     = true
}

variable "extra_labels" {
  type = list(object({
    name        = string
    color       = string
    description = string
  }))
  description = "Per-repo labels to add on top of the canonical set. Use for repo-specific labels (e.g. project codenames, ad-hoc audit tags)."
  default     = []
}

# ─── Governance files (CoC, CLAs, FUNDING) ─────────────────────────────

variable "maintainer" {
  type        = string
  description = "GitHub handle of the maintainer, used for CODEOWNERS, the CLA signature table, and the ICLA/CCLA legal text. Must be a real user or team; an organisation handle cannot be a code owner."
}

variable "manage_code_of_conduct" {
  type        = bool
  description = "Write CODE_OF_CONDUCT.md at the repo root from the bundled template (Contributor Covenant 2.1)."
  default     = true
}

variable "manage_icla" {
  type        = bool
  description = "Write .github/ICLA.md from the bundled template (ASF Individual CLA 2.0)."
  default     = true
}

variable "manage_ccla" {
  type        = bool
  description = "Write .github/CCLA.md from the bundled template (ASF Corporate CLA 2.0)."
  default     = true
}

variable "manage_funding" {
  type        = bool
  description = "Write .github/FUNDING.yml from the bundled template. Set false for repos that should not display a sponsor button (archived, private, deprecated)."
  default     = true
}

variable "funding_github" {
  type        = list(string)
  description = "GitHub Sponsors usernames (or orgs) to include in FUNDING.yml. Empty list = no github_sponsors line."
  default     = []
}

variable "funding_ko_fi" {
  type        = string
  description = "Ko-fi handle, or null to omit."
  default     = null
}

variable "funding_patreon" {
  type    = string
  default = null
}

variable "funding_open_collective" {
  type    = string
  default = null
}

variable "funding_buy_me_a_coffee" {
  type    = string
  default = null
}

variable "funding_tidelift" {
  type    = string
  default = null
}

variable "funding_polar" {
  type    = string
  default = null
}

variable "funding_custom" {
  type        = list(string)
  description = "Up to 4 custom funding URLs (per GitHub's FUNDING.yml spec)."
  default     = []
}

# ─── Shared OSS workflows ──────────────────────────────────────────────
#
# Templates for workflows that are generic across the repo set: stale
# issue management, locking, Dependabot auto-merge, PR auto-update, and
# CLA+DCO checks. All actions inside the templates are SHA-pinned to
# match the libkrun-builds hardening posture; bumps come via PRs to
# the hardened-repo module (no per-repo workflow churn).

variable "manage_workflow_stale" {
  type        = bool
  description = "Write .github/workflows/stale.yml (monthly stale-issue + stale-PR sweep)."
  default     = true
}

variable "manage_workflow_lock" {
  type        = bool
  description = "Write .github/workflows/lock.yml (monthly lock of long-closed issues + PRs)."
  default     = true
}

variable "manage_workflow_dependabot_auto_merge" {
  type        = bool
  description = "Write .github/workflows/dependabot-auto-merge.yml (auto-approves and merges Dependabot patch + minor updates)."
  default     = true
}

variable "manage_workflow_auto_update_pr" {
  type        = bool
  description = "Write .github/workflows/auto-update-pr.yml (keeps open PRs in sync with main on each push)."
  default     = true
}

variable "manage_workflow_cla_dco" {
  type        = bool
  description = "Write .github/workflows/cla-dco.yml (checks DCO sign-off on every commit and CLA signature against .github/CONTRIBUTORS.md). Requires the manage_icla/manage_ccla files to exist."
  default     = true
}

variable "manage_workflow_scorecard" {
  type        = bool
  description = "Write .github/workflows/scorecard.yml (OpenSSF Scorecard scan; pushes to https://api.scorecard.dev/ for a public README badge)."
  default     = null
}

variable "manage_workflow_osv_scan" {
  type        = bool
  description = "Write .github/workflows/osv-scan.yml (OSV-Scanner against the GitHub Advisory Database). Recursive scan of any package manifests at the repo root: Cargo.lock, package-lock.json, requirements.txt, go.sum, etc. Repos without manifests get an empty report. Set false for repos that have a bespoke vulnerability-scanning workflow (e.g. libkrun-builds downloads its source first)."
  default     = true
}

variable "manage_workflow_betterleaks" {
  type        = bool
  description = "Write .github/workflows/betterleaks.yml (betterleaks secret-scanning gate). MIT-licensed gitleaks successor by the same author, so no org-license required for private free-tier repos. The template downloads the pinned binary from GitHub releases, verifies SHA256, then runs `betterleaks git . --verbose` on PRs, pushes to main, and a weekly cron. Default true so every managed repo gets the same secret-scanning posture; set false only on repos that intentionally store fake credentials (CTF, test fixtures, etc.)."
  default     = true
}

variable "manage_workflow_clean_workflow" {
  type        = bool
  description = "Write .github/workflows/clean-workflow.yml (weekly scheduled cleanup of old workflow run history using the gh-actions-clean-workflow action). Deletes runs older than 7 days while keeping the 10 most recent per workflow. Default true so every managed repo stays tidy automatically; set false only on repos where you need manual control over workflow history retention."
  default     = true
}

variable "manage_workflow_clanker_filter" {
  type        = bool
  description = "Write .github/workflows/clanker-filter.yml (rejects AI-generated PRs and PRs without a linked issue on every PR open/reopen event). Default true for all repos; set false for private repos or repos that accept machine-generated PRs."
  default     = null
}

variable "clanker_filter_allowlist" {
  type        = list(string)
  description = "GitHub logins exempt from all clanker-filter quality-gate checks (AI-tell detection, em/en-dash scan, and linked-issue requirement). Unapproved-bot rejection still applies. Intended for repo owners or trusted maintainers who knowingly use AI tooling to author PRs. Defaults to [] so every author is gated; override per repo to add trusted logins."
  default     = []
}

variable "manage_workflow_license" {
  type        = bool
  description = "Write .github/workflows/license.yml (cross-language license compliance gate). Always runs an SPDX-License-Identifier header check across every source file in the repo. When `language` is set, additionally runs a per-ecosystem dep-license allowlist check: Rust uses `cargo deny check licenses` against the repo's `deny.toml`; JavaScript uses `license-checker` against `.license-checker.allow`; Go uses `go-licenses` against `.go-licenses.allow`. Each repo maintains its own dep-license config so the allowlist can evolve per project. Default true so every managed repo gets the SPDX check; set false only on repos that intentionally include source files without SPDX headers."
  default     = true
}

variable "bootstrap_license_checker_allow" {
  type        = bool
  description = "Bootstrap a starter .license-checker.allow (the JavaScript dep-license allowlist consumed by license.yml) into the repo when absent. Create-once: after the first apply the repo owns the file and Terraform never updates its content. Default false because the allowlist is per-repo policy; set true on a JavaScript repo that has no allowlist yet and would otherwise hard-fail the license gate. Errors at apply if the file already exists (set back to false in that case). Has no effect unless language == \"javascript\"."
  default     = false
}

variable "license_checker_allow" {
  type        = list(string)
  description = "SPDX license ids written into the bootstrapped .license-checker.allow (see bootstrap_license_checker_allow). Used only on the create-once bootstrap; ignored once the repo owns the file. Defaults to a permissive OSS set."
  default     = ["MIT", "ISC", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "0BSD", "Unlicense", "CC0-1.0", "CC-BY-4.0", "BlueOak-1.0.0", "MIT-0", "Python-2.0"]
}

variable "manage_workflow_dependency_review" {
  type        = bool
  description = "Write .github/workflows/dependency-review.yml (blocks PRs that introduce dependencies with known CVEs, complementing osv-scan which runs post-merge). Free for public repos; set false for private repos on the free tier."
  default     = true
}

variable "manage_workflow_commitlint" {
  type        = bool
  description = "Write .github/workflows/commitlint.yml (validates PR title follows Conventional Commits format). Critical for repos using squash-merge because the PR title becomes the commit message on main, which feeds changelog generation."
  default     = true
}

variable "manage_workflow_coverage_badge" {
  type        = bool
  description = "Write .github/workflows/coverage-badge.yml (runs test suite with coverage on every push to main and publishes a Shields.io endpoint JSON to the gh-pages branch). Only active when language = 'javascript'. Requires a `test:coverage` npm script that writes coverage/coverage-summary.json (Istanbul json-summary format)."
  default     = true
}

variable "manage_biome_plugins" {
  type        = bool
  description = "Write biome/plugins/*.grit and biome.plugins.json to the repo. Only active when language = 'javascript'. Repos extend the managed config via `extends: ['./biome.plugins.json']` in their biome.json (one-time manual step per repo)."
  default     = true
}

variable "enable_private_vulnerability_reporting" { # tflint-ignore: terraform_unused_declarations
  type        = bool
  description = "Enable GitHub's private vulnerability reporting (the 'Report a vulnerability' button in the Security tab). Free for public repos; not available on private repos without GHAS. Set false for private free-tier repos."
  default     = true
}

variable "pr_creation_policy" {
  type        = string
  description = "Who may open PRs against this repo. 'collaborators_only' restricts fork PRs to collaborators; 'all' allows anyone. Enforced via scripts/sync-repo-settings.sh (not yet in the GitHub provider schema). The script's effective default is visibility-gated: public repos get 'collaborators_only', private repos are left unmanaged. Set this explicitly to override (e.g. 'all' on a public repo that wants outside PRs)."
  default     = "collaborators_only"
  validation {
    condition     = contains(["all", "collaborators_only"], var.pr_creation_policy)
    error_message = "pr_creation_policy must be 'all' or 'collaborators_only'."
  }
}

variable "enforce_pr_creation_policy" {
  type        = bool
  description = "Query the repo at plan time and warn (via a check block) when pull_request_creation_policy drifts from var.pr_creation_policy. Set false to skip the API call (e.g. private repos where the unauthenticated read 404s)."
  default     = true
}

variable "manage_dependabot_config" {
  type        = bool
  description = "Write .github/dependabot.yml (monthly Dependabot version-update schedule with grouped PRs and conventional commit prefixes). Synced on every apply. Set false for repos that maintain a bespoke dependabot.yml."
  default     = true
}

variable "dependabot_version_updates" {
  type        = bool
  description = "Include version-update entries in .github/dependabot.yml. Set false to get security-only updates: the file is still written (so Dependabot recognises the repo) but the updates: block is omitted. GitHub's automatic security updates (enabled via enable_dependabot_security_updates) run regardless of this setting. Defaults to true."
  default     = true
}

# ─── Build / release scripts (Node + JSR publishing) ───────────────────

variable "manage_release_script" {
  type        = bool
  description = "Write scripts/release.mjs (changelog from conventional commits, bumps package.json + jsr.json, tags, pushes, creates GitHub release; gates on npm + JSR publish dry-runs). Node/pnpm/JSR-specific, opt in only for repos that publish to both registries (the pure-* family today). Defaults to false so Rust repos (ward, libkrun-builds) don't get a Node script pushed."
  default     = false
}

# ─── Base bootstrap files (create-if-missing, ignore future edits) ─────
#
# These files seed a baseline so brand-new repos have the OSS hygiene
# scaffolding from day one. Per-repo, set the corresponding
# bootstrap_* = false for repos that already have these files (the TF
# resource would otherwise 422 on apply because overwrite_on_create is
# false for the bootstrap pattern). After TF adopts the file, the
# lifecycle ignore_changes ensures future edits in the repo aren't
# clobbered on the next plan.

variable "manage_codeowners" {
  type        = bool
  description = "Write .github/CODEOWNERS (requires maintainer review on all files + .github/ paths). Synced on every apply. Set false for repos that maintain a bespoke CODEOWNERS with additional reviewers."
  default     = true
}

variable "manage_contributing_rules" {
  type        = bool
  description = "Write .github/CONTRIBUTING-RULES.md (universal: DCO, CLA, commit conventions, PR process, code style baseline). Synced on every apply so policy changes propagate across all repos."
  default     = true
}

variable "bootstrap_contributing" {
  type        = bool
  description = "Create CONTRIBUTING.md at the repo root if missing. The template is a thin wrapper that links to CONTRIBUTING-RULES.md plus three project-specific slots (notes, code style, tests). Set false for repos that already have a full custom CONTRIBUTING.md."
  default     = true
}

variable "contributing_project_notes" {
  type        = string
  description = "Project-specific narrative for the 'Project-Specific Notes' section of CONTRIBUTING.md (e.g. 'This is a vendor repo; see build.sh for the matrix build process')."
  default     = "No project-specific notes beyond the baseline rules. See the [README](README.md) for build and test commands."
}

variable "contributing_project_code_style" {
  type        = string
  description = "Project-specific code style rules added on top of the baseline (SPDX header, dependency policy, commit signing) defined in CONTRIBUTING-RULES.md. Use for language patterns (e.g. 'Use Result/Option not exceptions') or framework conventions."
  default     = "No project-specific code style rules beyond the baseline. See [.github/CONTRIBUTING-RULES.md](.github/CONTRIBUTING-RULES.md#code-style-baseline) for SPDX header, dependency policy, and commit signing requirements."
}

variable "contributing_project_tests" {
  type        = string
  description = "Project-specific test instructions (where tests live, how to run them, coverage expectations)."
  default     = "See the [README](README.md) for test commands and coverage expectations."
}

variable "bootstrap_pr_template" {
  type        = bool
  description = "Create .github/PULL_REQUEST_TEMPLATE.md if missing. Set false for repos with a custom PR template."
  default     = true
}

variable "bootstrap_contributors" {
  type        = bool
  description = "Create .github/CONTRIBUTORS.md with CLA-BOT markers if missing. The CLA-DCO workflow appends signatures to this file."
  default     = true
}

variable "bootstrap_issue_templates" {
  type        = bool
  description = "Create .github/ISSUE_TEMPLATE/{bug_report,feature_request,config}.yml if missing."
  default     = true
}

variable "contributors_seed_date" {
  type        = string
  description = "ISO date for the initial CONTRIBUTORS.md seed entry (the maintainer's CLA signature row)."
  default     = "2026-01-01"
}

# ─── LICENSE ───────────────────────────────────────────────────────────

variable "license" {
  type        = string
  description = <<-EOT
    SPDX identifier of the project license, written to LICENSE.

    Defaults to AGPL-3.0-only: copyleft is the safe default, because a repo that
    never states a license is worse than one that states a strong one, and a
    permissive default silently gives away more than intended. Set it explicitly
    to publish under something else.

    Supported: AGPL-3.0-only (default), AGPL-3.0 (legacy alias for the same
    text), Apache-2.0, MIT.
  EOT
  default     = "AGPL-3.0-only"

  validation {
    condition     = contains(["AGPL-3.0-only", "AGPL-3.0", "Apache-2.0", "MIT"], var.license)
    error_message = "Supported licenses: AGPL-3.0-only, AGPL-3.0, Apache-2.0, MIT. Add the corresponding licenses/<spdx>.tftpl template to extend."
  }
}

variable "license_year" {
  type        = string
  description = "The year the copyright was first established, rendered into the LICENSE file. Set this to the year the repo was created; it does not need to be the current year (copyright years record origin, not rolling time). Defaults to 2026 (the year this module was introduced)."
  default     = "2026"
}

variable "manage_license" {
  type        = bool
  description = "Write LICENSE at the repo root from the licenses/<spdx>.tftpl template. Standard legal text; safe to overwrite."
  default     = true
}

# ─── Branch ruleset ────────────────────────────────────────────────────

variable "protect_default_branch" {
  type        = bool
  description = "Apply the default-branch ruleset (deletion + force-push + PR-required, plus optional extra rules)."
  default     = true
}

variable "default_branch_ruleset_name" {
  type        = string
  description = "Display name for the default-branch ruleset. Match the existing name during import to avoid a rename-during-apply on the first run."
  default     = "Protect default branch"
}

variable "require_signatures" {
  type        = bool
  description = "Enable the `required_signatures` rule (Require signed commits). Bot PRs via peter-evans/create-pull-request + human commits via /commit-and-push --gpg-sign satisfy this."
  default     = false
}

variable "required_pr_approvals" {
  type        = number
  description = "required_approving_review_count for the pull_request rule. 0 = no required reviewer (PR still required, just no approvals). 1 = solo dev with admin bypass."
  default     = null
}

variable "require_code_owner_review" {
  type        = bool
  description = "Enable require_code_owner_review on the pull_request rule. Activates CODEOWNERS enforcement."
  default     = null
}

variable "allowed_merge_methods" {
  type        = list(string)
  description = "Subset of [merge, squash, rebase] allowed by the pull_request rule. Squash-only is the disciplined default."
  default     = ["squash"]
}

variable "required_status_check_contexts" {
  type        = list(string)
  description = "List of status-check context names required to merge. Empty list = rule not added (matches a fresh repo before any checks have been observed)."
  default     = []
}

variable "strict_required_status_checks_policy" {
  type        = bool
  description = "When true (default), require status checks to run against the latest target branch SHA before merge."
  default     = true
}

# ─── Tag ruleset ───────────────────────────────────────────────────────

variable "protect_tag_pattern" {
  type        = string
  description = "Glob for tags to protect against deletion + force-push (e.g. `libkrun-v*`). Null = skip."
  default     = null
}

variable "release_tags_ruleset_name" {
  type    = string
  default = "Protect release tags"
}

# ─── Bypass identity ───────────────────────────────────────────────────

variable "bot_app_id" {
  type        = string
  description = "App ID of the bot identity to add to ruleset bypass lists. Null = no App in bypass."
  default     = null
}

variable "bot_app_client_id" {
  type        = string
  description = "OAuth Client ID of the bot App. Used as the value of the BOT_APP_CLIENT_ID repo secret when `manage_bot_app_secrets = true`. Public identifier, not actually secret. Defaults empty so repos that don't opt into the secret can omit passing it from the root."
  default     = ""
}

variable "bot_app_private_key" {
  type        = string
  description = "PEM-encoded private key of the bot App. Used as the value of the BOT_APP_PRIVATE_KEY repo secret when `manage_bot_app_secrets = true`. Sensitive: never commit this; source from HCP workspace variable. Defaults empty so repos that don't opt into the secret can omit passing it from the root."
  default     = ""
  sensitive   = true
}

variable "github_token" {
  type        = string
  description = "Token used only for plan-time GitHub REST reads (release version lookup, PR-creation-policy drift check). Lifts the 60/hr unauthenticated rate limit and lets private repos be read. Sourced from the HCP workspace variable set. Read-only scope is sufficient."
  default     = null
  sensitive   = true
}

# ─── Managed files ─────────────────────────────────────────────────────

variable "manage_security_md" {
  type        = bool
  description = "If true, write a SECURITY.md at the repo root rendered from the module's bundled template. Set false to opt out (e.g. for repos that intentionally keep their own bespoke version)."
  default     = true
}

variable "security_contact_email" {
  type        = string
  description = "Email address shown in SECURITY.md for vulnerability reports, alongside GitHub Security Advisories. Required: there is no safe default, since a wrong address silently misdirects vulnerability reports."
}

variable "security_md_commit_message" {
  type        = string
  description = "Commit message for SECURITY.md writes. Defaults to a generic chore line."
  default     = "chore(security): sync SECURITY.md from the hardened-repo module"
}

# ─── App-token secrets (opt-in, for repos under user accounts) ─────────
#
# Two-tier design: org-owned repos inherit org-level secrets
# at org scope via org-secrets.tf, set once per org, available to all
# repos in the org via `secrets.BOT_APP_*` references. User-account
# repos owned by a user account cannot use org secrets
# (GitHub's secret model has no user-level Actions secrets), so they
# opt in to per-repo TF-managed secrets via this variable. The values
# come from the same HCP workspace variables in both cases, so there's
# one source of truth.
#
# Default false because most repos have no App-token workflow today
# (they use secrets.GITHUB_TOKEN). Flip to true on the repo that
# actually needs it; the next apply pushes both secrets to the repo.

variable "manage_bot_app_secrets" {
  type        = bool
  description = "Write `BOT_APP_CLIENT_ID` + `BOT_APP_PRIVATE_KEY` as repo-level Actions AND Dependabot secrets (the Dependabot store is what dependabot[bot]-triggered runs like dependabot-auto-merge.yml read from). Required for repos under a user account whose workflows use `actions/create-github-app-token` (org-owned repos already inherit these as org-level secrets, so leave this false there). Defaults false. When flipping to true, also pass `bot_app_client_id = var.bot_app_client_id` and `bot_app_private_key = var.bot_app_private_key` from the root in that repo's module call, both default to empty string at the module level, so omitting them produces empty-value secrets (silently broken)."
  default     = false
}

# ─── Per-language CI / release / publish workflows ─────────────────────
#
# Three new shared workflows (ci.yml, release.yml, publish.yml) layered
# on top of the existing per-repo template fan-out. Each opt-in is
# language-scoped: the module dispatches to workflows/<file>.<language>.yml.tftpl
# based on var.language. Currently only the "javascript" templates are
# implemented; "rust" and "golang" will be added in follow-up PRs as
# those repos (ward, libkrun-builds) lift their hand-tuned workflows
# into the module. Until then, set manage_workflow_* = false on those
# repos and they keep their bespoke files.
#
# Why three separate manage_workflow_* toggles instead of one global
# flag: each repo may want a custom CI matrix while still benefiting
# from the shared SLSA L3 release/publish pipeline (or vice versa).
# Independent toggles let those decisions diverge per-repo.

variable "language" {
  type        = string
  description = "Language family for the templated CI/release/publish workflows. One of javascript, rust, golang, or null. Required when any manage_workflow_* (other than the existing shared OSS workflows) is true."
  default     = null

  validation {
    condition     = var.language == null || try(contains(["javascript", "rust", "golang"], var.language), false)
    error_message = "language must be one of: javascript, rust, golang, null."
  }
}

variable "manage_workflow_ci" {
  type        = bool
  description = "Write .github/workflows/ci.yml from the templated per-language CI workflow (lint + type-check + build + unit tests + per-runtime integration matrix). Requires var.language to be set."
  default     = false
}

variable "manage_workflow_release" {
  type        = bool
  description = "Write .github/workflows/release.yml from the templated per-language SLSA L3 release workflow. Triggered on `v*` tag push: builds artefacts, generates in-toto + SLSA v1 provenance attestations via the slsa-framework/slsa-github-generator reusable workflow, and attaches everything to the GitHub Release. Requires var.language to be set."
  default     = false
}

variable "manage_workflow_publish" {
  type        = bool
  description = "Write .github/workflows/publish.yml from the templated per-language publish workflow. Triggered on `release: published`: detects target registries from source files (package.json -> npm, jsr.json/deno.json -> JSR), verifies the SLSA provenance attached by release.yml, and publishes to each registry using OIDC Trusted Publishers (no NPM_TOKEN/JSR_API_TOKEN needed). Requires var.language to be set."
  default     = false
}

variable "release_profile" {
  type        = string
  description = "Shape of the release pipeline when manage_workflow_release = true. \"library\" (default) renders the per-language SLSA release.<language>.yml + publish.<language>.yml (npm/JSR registry publishing). \"action\" renders the language-neutral release.action.yml (git-ref + Marketplace shipping: git-cliff changelog, GitHub Release, build-provenance attestation, moving major tag) and renders NO publish workflow. Actions ship via git ref, not a package registry."
  default     = "library"

  validation {
    condition     = contains(["library", "action"], var.release_profile)
    error_message = "release_profile must be one of: library, action."
  }
}

variable "release_use_semantic_release" {
  type        = bool
  description = "Only meaningful when release_profile = \"action\" and language = \"javascript\". false (default) renders the git-cliff flavor: workflow_dispatch with a manually supplied version, changelog derived from Conventional Commits, language-neutral (works for a Python/Rust/Go composite action). true renders the semantic-release flavor instead: push-to-main triggered, commit-analyzer decides the version bump from Conventional Commits with no contributor action beyond the commit message, and a release is cut automatically whenever a qualifying commit lands, no manual step. Both flavors use the bot App token to bypass the tag-protection ruleset and both move the vMAJOR tag on release. semantic-release requires a package.json/Node toolchain, so this is rejected for non-javascript repos."
  default     = false
}

# ─── JS-specific CI knobs ──────────────────────────────────────────────

variable "ci_runtimes" {
  type        = list(string)
  description = "JavaScript-only: integration matrix runtimes. Accepted values: `node-<version>` (e.g. node-22, node-24), `deno-<version>` (e.g. deno-2.x, deno-canary), `bun-<version>` (e.g. bun-latest, bun-canary), `browser`, `cf-workers`. Each runtime family is opt-in: only entries listed here generate integration jobs. An empty list keeps only the lint-and-test job. Per-repo config is the source of truth for which runtimes are supported."
  default     = ["node-24"]
}

variable "node_version" {
  type        = string
  description = "Node major version for setup-node steps (the lint-and-test job, the build step in release.yml, the publish step in publish.yml, and the Node side-toolchain in deno/bun/workers/browser integration jobs). Always set to the latest stable release."
  default     = "26"
}

# .npmrc (registry/auth) is always synced for language == "javascript" repos.
# Hardened pnpm settings live in pnpm-workspace.yaml because pnpm v10+ ignores
# them in .npmrc; opt in per repo with manage_pnpm_workspace.

variable "manage_pnpm_workspace" {
  type        = bool
  description = "Seed a pnpm-workspace.yaml with minimal pnpm hardening (saveExact, strictPeerDependencies), the settings pnpm does NOT record in the lockfile, so seeding them never breaks pnpm install --frozen-lockfile. pnpm v10+ reads these from pnpm-workspace.yaml, not .npmrc. Seed-once: the module writes the baseline on the first apply (merging any pnpm_workspace_settings the repo passes) and then sets ignore_changes on content, so the repo OWNS the file afterward and can add or change overrides/allowBuilds freely without them being clobbered. Pinning is enforced by the CI pin guard regardless. Has no effect unless language == \"javascript\". Default false."
  default     = false
}

variable "pnpm_workspace_settings" {
  type        = any
  description = "Repo-specific pnpm-workspace.yaml keys merged into the seeded file, e.g. { packages = [\"packages/*\"], allowBuilds = { sharp = true }, overrides = { ws = \"^8\" } }. These override the hardening defaults on key conflict. Only seeds the FIRST apply (the repo owns the file afterward), so later override changes belong in the repo, not here. Used only when manage_pnpm_workspace = true."
  default     = {}
}

# ─── SLSA L3 generator pin ─────────────────────────────────────────────

variable "slsa_generator_ref" {
  type        = string
  description = "Tag ref of slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml. MUST be a vX.Y.Z release tag, never a commit SHA: the generator resolves its pre-built builder binary from the release matching the tag ref and hard-fails at runtime on SHA refs (\"Invalid ref: ... Expected ref of the form refs/tags/vX.Y.Z\"). Bump via PRs to the hardened-repo module so all consuming repos move together."
  default     = "v2.1.0"

  validation {
    condition     = can(regex("^v[0-9]+\\.[0-9]+\\.[0-9]+$", var.slsa_generator_ref))
    error_message = "slsa_generator_ref must be a vX.Y.Z release tag. The SLSA generator rejects commit SHAs at runtime, which silently breaks every consuming repo's release pipeline."
  }
}

# ─── Publish environments (per-registry deployment gates) ──────────────
#
# Each environment is created only when manage_workflow_publish is true
# AND language is "javascript" (the only language with publish.yml
# templated today). The environments enforce two policies:
#
#   1. Tag-only deployments. The deployment_branch_policy below
#      restricts the environment to deployments originating from `v*`
#      tags, so an attacker who got code merged to main still couldn't
#      publish without also pushing (and signing) a release tag.
#   2. Optional human approval. npm_publish_reviewers / jsr_publish_reviewers
#      lists are wired into the reviewers block; empty list disables the
#      manual-approval gate but keeps the tag policy.
#
# Trusted Publisher configuration on npm/JSR must reference the
# environment name verbatim (`npm-publish`, `jsr-publish`); see
# modules/hardened-repo/docs/setup-trusted-publishers.md.

variable "npm_publish_reviewers" {
  type        = list(string)
  description = "GitHub usernames who must approve before an npm publish runs. Empty list disables the manual-approval gate (tag-only policy still applies). For a solo-author project, [] is a reasonable default, the signed-tag push is already strong gating."
  default     = []
}

variable "npm_publish_wait_timer_minutes" {
  type        = number
  description = "Wait timer in minutes before the npm publish job can run after deployment-pending state. Useful as an undo window for accidental releases. 0 disables."
  default     = 0

  validation {
    condition     = var.npm_publish_wait_timer_minutes >= 0 && var.npm_publish_wait_timer_minutes <= 43200
    error_message = "wait_timer must be between 0 and 43200 minutes (GitHub's maximum)."
  }
}

variable "jsr_publish_reviewers" {
  type        = list(string)
  description = "GitHub usernames who must approve before a JSR publish runs. Same semantics as npm_publish_reviewers."
  default     = []
}

variable "jsr_publish_wait_timer_minutes" {
  type        = number
  description = "Wait timer in minutes before the JSR publish job can run. Same semantics as npm_publish_wait_timer_minutes."
  default     = 0

  validation {
    condition     = var.jsr_publish_wait_timer_minutes >= 0 && var.jsr_publish_wait_timer_minutes <= 43200
    error_message = "wait_timer must be between 0 and 43200 minutes (GitHub's maximum)."
  }
}

variable "release_reviewers" {
  type        = list(string)
  description = "GitHub usernames who must approve the release environment before the publish-gh job runs. Empty list disables the manual-approval gate (tag policy still applies)."
  default     = []
}

variable "release_wait_timer_minutes" {
  type        = number
  description = "Minutes to wait before the release environment allows the publish-gh job to run. 0 disables. Same semantics as npm_publish_wait_timer_minutes."
  default     = 0

  validation {
    condition     = var.release_wait_timer_minutes >= 0 && var.release_wait_timer_minutes <= 43200
    error_message = "release_wait_timer_minutes must be between 0 and 43200 minutes (GitHub's maximum)."
  }
}


# ─── Hardening profile ─────────────────────────────────────────────────

variable "profile" {
  type        = string
  description = <<-EOT
    Team shape of the project, which decides the rules that only make sense with
    more than one maintainer.

    "solo" (default): a single maintainer. Review rules are relaxed because they
    would otherwise deadlock the repo, since GitHub does not let you approve your
    own pull request. Required approvals drop to 0, code-owner review is off, and
    the clanker filter (which polices multi-contributor PR noise) is off.

    "team": more than one maintainer. Required approvals go to 1, code-owner
    review is on, and the clanker filter is on.

    This axis is independent of visibility. Public versus private is handled by
    the capability gate, which derives from visibility on its own, so the two
    compose: solo-private, solo-public, team-private and team-public all fall out
    without naming four presets.

    The profile only supplies defaults. Setting required_pr_approvals,
    require_code_owner_review or manage_workflow_clanker_filter explicitly always
    wins. DCO and CLA enforcement is deliberately NOT part of this axis: it
    applies to every repo, solo or team, public or private.
  EOT
  default     = "solo"
  validation {
    condition     = contains(["solo", "team"], var.profile)
    error_message = "profile must be one of: solo, team."
  }
}
