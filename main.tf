# SPDX-License-Identifier: Apache-2.0
#
# Module: hardened-repo
#
# Codifies a standard hardening posture for a GitHub repository.
# Configurable so that each repo's per-repo .tf file can express its
# specific ruleset (signed commits on/off, status checks list, allowed
# merge methods, etc.) without diverging from the module shape.
#
# Safety: github_repository has `prevent_destroy = true` and
# `archive_on_destroy = true`. Terraform refuses to destroy the repo;
# in the worst case (manual override) it archives rather than deletes.

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    github = {
      source  = "integrations/github"
      version = "~> 6.12"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }
  }
}

# ─── Effective variable resolution ─────────────────────────────────────
#
# Two independent axes decide the posture, and they compose:
#
#   1. Capability gate, derived from visibility. Private repos on the free tier
#      get a 403 for the eight Pro-only settings, so those are forced off, and
#      applied automatically once the repo is public.
#   2. Hardening profile (var.profile), solo or team. Decides the rules that
#      only make sense with more than one maintainer, such as required reviews.
#
# Explicit variables always override both. All resources below read the
# local.eff_* values instead of var.* directly.

locals {
  # Capability gate. Verified from visibility, the only signal that is always
  # available: GitHub does not expose a repo's plan on the repo object, and the
  # org plan endpoint needs auth this module's http data sources do not have.
  #
  # Public repos get the eight features free, private repos on the free tier get
  # a 403, so deriving from visibility both prevents those errors and makes the
  # flip automatic: going public applies them, going private reverts them. An
  # explicit private_free_tier overrides the derivation (e.g. false on a private
  # repo that is genuinely on Pro/Team/GHAS).
  _ftr = var.private_free_tier != null ? var.private_free_tier : (var.visibility == "private")

  # Auto-merge belongs on this gate for the same reason as the rest, but fails
  # differently and so is easy to miss: GitHub does not 403 the write, it accepts
  # it, keeps reporting false, and leaves Terraform with an
  # "allow_auto_merge: false -> true" diff that can never converge. Permanent
  # noise on a governance resource is how a real change gets skimmed past.
  eff_allow_auto_merge                       = local._ftr ? false : var.allow_auto_merge
  eff_enable_vulnerability_alerts            = local._ftr ? false : var.enable_vulnerability_alerts
  eff_enable_secret_scanning                 = local._ftr ? false : var.enable_secret_scanning
  eff_enable_secret_scanning_push_protection = local._ftr ? false : var.enable_secret_scanning_push_protection
  eff_enable_dependabot_security_updates     = local._ftr ? false : var.enable_dependabot_security_updates
  eff_manage_workflow_dependency_review      = local._ftr ? false : var.manage_workflow_dependency_review
  eff_enable_private_vulnerability_reporting = local._ftr ? false : var.enable_private_vulnerability_reporting
  eff_protect_default_branch                 = local._ftr ? false : var.protect_default_branch
  eff_protect_tag_pattern                    = local._ftr ? null : var.protect_tag_pattern

  # ── Profile-derived defaults ──
  # var.profile decides the rules that only make sense with more than one
  # maintainer. A solo repo cannot satisfy required reviews (GitHub does not let
  # you approve your own PR), so demanding them would deadlock the repo. An
  # explicit var always wins over the profile.
  _team = var.profile == "team"

  eff_required_pr_approvals          = var.required_pr_approvals != null ? var.required_pr_approvals : (local._team ? 1 : 0)
  eff_require_code_owner_review      = var.require_code_owner_review != null ? var.require_code_owner_review : local._team
  eff_manage_workflow_clanker_filter = var.manage_workflow_clanker_filter != null ? var.manage_workflow_clanker_filter : local._team

  # Scorecard is capability-derived, not profile-derived: it publishes to the
  # public api.scorecard.dev and only works on public repos, so it follows
  # visibility exactly like the free-tier gate above.
  eff_manage_workflow_scorecard = var.manage_workflow_scorecard != null ? var.manage_workflow_scorecard : (var.visibility == "public")

  # LICENSE body to write. AGPL-3.0-only and the legacy AGPL-3.0 alias share the
  # same text: the only-versus-or-later distinction is expressed in per-file
  # SPDX headers, not in the LICENSE file, so both map to one template.
  license_template = var.license == "AGPL-3.0-only" ? "AGPL-3.0" : var.license

  # NOTE: manage_workflow_cla_dco is deliberately absent here. DCO and CLA
  # enforcement applies to every repo, solo or team, public or private, so it is
  # never derived off by a profile or by visibility.
}

check "private_repo_free_tier_guard" {
  assert {
    condition = (
      var.visibility != "private"
      || local._ftr
      || !(
        var.protect_default_branch
        || var.protect_tag_pattern != null
        || var.enable_vulnerability_alerts
        || var.enable_secret_scanning
        || var.enable_secret_scanning_push_protection
        || var.enable_dependabot_security_updates
        || var.enable_private_vulnerability_reporting
        || var.manage_workflow_dependency_review
      )
    )
    error_message = "Repo ${var.name} is private and private_free_tier was explicitly set to false while a Pro-only feature is enabled (rulesets, vulnerability alerts, secret scanning, Dependabot security updates, private vuln reporting, or dependency-review). That override tells the module the repo is on GitHub Pro/Team/GHAS; on the free tier GitHub returns 403 at apply. Either drop the override so the gate derives from visibility and forces these off, set the individual feature vars to false, or make the repo public."
  }
}

# ─── Repo settings ─────────────────────────────────────────────────────

resource "github_repository" "this" {
  name         = var.name
  description  = var.description
  homepage_url = var.homepage_url
  topics       = var.topics

  visibility = var.visibility

  has_issues      = var.has_issues
  has_projects    = var.has_projects
  has_wiki        = var.has_wiki
  has_discussions = var.has_discussions

  # Repo-level merge button toggles. These must agree with the
  # allowed_merge_methods in the pull_request rule below; GitHub picks
  # the intersection of the two.
  allow_merge_commit = contains(var.allowed_merge_methods, "merge")
  allow_squash_merge = contains(var.allowed_merge_methods, "squash")
  allow_rebase_merge = contains(var.allowed_merge_methods, "rebase")
  # Derived, not hardcoded true: auto-merge is Pro-only on private repos. See
  # eff_allow_auto_merge above. Deriving from visibility rather than pinning a
  # literal matters for repos that flip public to run CI and private again,
  # where either literal would be wrong half the time.
  allow_auto_merge       = local.eff_allow_auto_merge
  allow_update_branch    = var.allow_update_branch
  delete_branch_on_merge = true

  # Squash-commit message templating (only applies when squash is the
  # chosen merge method, which it is by default).
  squash_merge_commit_title   = var.squash_merge_commit_title
  squash_merge_commit_message = var.squash_merge_commit_message

  # Force sign-off on commits made through GitHub's web UI (catches
  # the "edit on github.com" path, which otherwise bypasses any local
  # commit hooks).
  web_commit_signoff_required = var.web_commit_signoff_required

  # vulnerability_alerts moved to its own resource (see
  # github_repository_vulnerability_alerts below) per the provider's
  # deprecation of the inline attribute.

  # Security analysis. Secret scanning and push protection are free on
  # public repos; for private repos they require GHAS and have to be
  # disabled on free tier (set the enable_* variables to false).
  # Private vulnerability reporting: managed via scripts/sync-private-vulnerability-reporting.sh
  # because hashicorp/github provider v6.x does not expose this attribute yet.
  # Track: https://github.com/integrations/terraform-provider-github/issues/2427

  security_and_analysis {
    secret_scanning {
      status = local.eff_enable_secret_scanning ? "enabled" : "disabled"
    }
    secret_scanning_push_protection {
      status = local.eff_enable_secret_scanning_push_protection ? "enabled" : "disabled"
    }
  }

  archive_on_destroy = true
  lifecycle {
    prevent_destroy = true
  }
}

# ─── Dependabot vulnerability alerts ───────────────────────────────────
#
# Standalone resource (replaces the deprecated inline
# `vulnerability_alerts` attribute on github_repository). Defaults to
# enabled; opt out per-repo via `enable_vulnerability_alerts = false`
# for private repos on the free tier where alerts require GitHub Pro.

resource "github_repository_vulnerability_alerts" "this" {
  count = local.eff_enable_vulnerability_alerts ? 1 : 0

  repository = github_repository.this.name
}

# ─── Dependabot security updates ───────────────────────────────────────
#
# Auto-PRs from Dependabot for CVEs in dependencies. Requires
# vulnerability_alerts enabled first (the resource above), so the count
# guard checks both toggles to avoid a confusing 422 from GitHub.

resource "github_repository_dependabot_security_updates" "this" {
  count = local.eff_enable_dependabot_security_updates && local.eff_enable_vulnerability_alerts ? 1 : 0

  repository = github_repository.this.name
  enabled    = true

  depends_on = [github_repository_vulnerability_alerts.this]
}

# ─── Branch ruleset: protect the default branch ────────────────────────

resource "github_repository_ruleset" "default_branch" {
  count = local.eff_protect_default_branch ? 1 : 0

  repository  = github_repository.this.name
  name        = var.default_branch_ruleset_name
  target      = "branch"
  enforcement = "active"

  conditions {
    ref_name {
      include = ["~DEFAULT_BRANCH"]
      exclude = []
    }
  }

  # Repository admin (built-in role ID 5) always bypasses.
  bypass_actors {
    actor_id    = 5
    actor_type  = "RepositoryRole"
    bypass_mode = "always"
  }

  # Plus the App if one is configured.
  dynamic "bypass_actors" {
    for_each = var.bot_app_id != null ? [var.bot_app_id] : []
    content {
      actor_id    = tonumber(bypass_actors.value)
      actor_type  = "Integration"
      bypass_mode = "always"
    }
  }

  rules {
    deletion         = true
    non_fast_forward = true

    # required_signatures is a flag-style rule; the block toggles its
    # presence in the rules list. terraform-provider-github exposes it
    # as `required_signatures = true | false`.
    required_signatures = var.require_signatures

    pull_request {
      required_approving_review_count   = local.eff_required_pr_approvals
      dismiss_stale_reviews_on_push     = true
      require_code_owner_review         = local.eff_require_code_owner_review
      require_last_push_approval        = false
      required_review_thread_resolution = true
      allowed_merge_methods             = var.allowed_merge_methods
    }

    # required_status_checks block is added only when at least one
    # status-check context is specified. Adding the rule with an empty
    # list silently blocks every merge (no check ever satisfies it).
    dynamic "required_status_checks" {
      for_each = length(var.required_status_check_contexts) > 0 ? [1] : []
      content {
        strict_required_status_checks_policy = var.strict_required_status_checks_policy
        dynamic "required_check" {
          for_each = var.required_status_check_contexts
          content {
            context = required_check.value
          }
        }
      }
    }
  }
}

# ─── Managed files: SECURITY.md ────────────────────────────────────────
#
# Generic security policy across the managed repo set: GHSA + email
# reporting, standard timeline, generic in/out-of-scope, pointer at
# the hardened-repo module for the cross-repo hardening posture. Only `repo_full_name`,
# `contact_email`, and the auto-detected `latest_version` vary per repo;
# everything else is one canonical template. Set var.manage_security_md
# = false to opt out for a repo that needs a bespoke policy.
#
# Version auto-pumping:
#   - Query GitHub's "latest release" endpoint on each plan.
#   - If a release exists, render its tag (e.g. `v1.18.1`) into the
#     supported-versions section.
#   - If no releases exist (404), fall back to `v0.1.0` as the assumed
#     starting version, so brand-new repos still get a non-generic table.

data "http" "latest_release" {
  count = var.manage_security_md ? 1 : 0

  url = "https://api.github.com/repos/${var.owner}/${var.name}/releases/latest"
  request_headers = merge(
    { Accept = "application/vnd.github+json" },
    var.github_token != null ? { Authorization = "Bearer ${var.github_token}" } : {}
  )

  retry {
    attempts = 1
  }
}

locals {
  latest_release_enabled = var.manage_security_md
  latest_release_status  = local.latest_release_enabled ? try(data.http.latest_release[0].status_code, 0) : 0

  # 404 = repo has no releases yet -> use the v0.1.0 fallback. 200 = parse the
  # tag. Any other status (403 rate-limit, 401 auth, 5xx) must NOT silently
  # regress SECURITY.md; the check block below fails the plan.
  latest_version = (
    local.latest_release_status == 200
    ? try(jsondecode(data.http.latest_release[0].response_body).tag_name, "v0.1.0")
    : "v0.1.0"
  )
}

check "latest_release_reachable" {
  assert {
    condition = (
      !local.latest_release_enabled
      || contains([200, 404], local.latest_release_status)
    )
    error_message = "GitHub /releases/latest for ${var.owner}/${var.name} returned ${local.latest_release_status} (expected 200 or 404). SECURITY.md would silently fall back to v0.1.0. Check the github_token or rate limit."
  }
}

resource "github_repository_file" "security_md" {
  count = var.manage_security_md ? 1 : 0

  repository = github_repository.this.name
  file       = "SECURITY.md"
  branch     = "main"

  content = templatefile("${path.module}/SECURITY.md.tftpl", {
    repo_full_name = "${var.owner}/${var.name}"
    contact_email  = var.security_contact_email
    latest_version = local.latest_version
  })

  commit_message      = var.security_md_commit_message
  overwrite_on_create = true

  # Prevent TF from churning the file on every plan when the only diff
  # is the commit metadata. The commit itself only happens when
  # `content` changes.
  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

# ─── Managed files: governance pack ────────────────────────────────────
#
# CODE_OF_CONDUCT.md, ICLA.md, CCLA.md, and FUNDING.yml all follow the
# same shape as SECURITY.md: templated from bundled .tftpl files,
# overwrite_on_create = true to adopt any existing copies on first
# apply, ignore_changes on commit metadata to prevent plan churn.
#
# Each is independently togglable via manage_* variables so repos that
# need a bespoke version can opt out without forking the whole module.

resource "github_repository_file" "code_of_conduct" {
  count = var.manage_code_of_conduct ? 1 : 0

  repository = github_repository.this.name
  file       = "CODE_OF_CONDUCT.md"
  branch     = "main"

  content = templatefile("${path.module}/CODE_OF_CONDUCT.md.tftpl", {
    contact_email = var.security_contact_email
  })

  commit_message      = "chore(governance): sync CODE_OF_CONDUCT.md from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "icla" {
  count = var.manage_icla ? 1 : 0

  repository = github_repository.this.name
  file       = ".github/ICLA.md"
  branch     = "main"

  content = templatefile("${path.module}/ICLA.md.tftpl", {
    maintainer = var.maintainer
  })

  commit_message      = "chore(governance): sync ICLA.md from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "ccla" {
  count = var.manage_ccla ? 1 : 0

  repository = github_repository.this.name
  file       = ".github/CCLA.md"
  branch     = "main"

  content = templatefile("${path.module}/CCLA.md.tftpl", {
    maintainer    = var.maintainer
    contact_email = var.security_contact_email
  })

  commit_message      = "chore(governance): sync CCLA.md from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "funding" {
  count = var.manage_funding ? 1 : 0

  repository = github_repository.this.name
  file       = ".github/FUNDING.yml"
  branch     = "main"

  content = templatefile("${path.module}/FUNDING.yml.tftpl", {
    funding_github          = var.funding_github
    funding_ko_fi           = var.funding_ko_fi
    funding_patreon         = var.funding_patreon
    funding_open_collective = var.funding_open_collective
    funding_buy_me_a_coffee = var.funding_buy_me_a_coffee
    funding_tidelift        = var.funding_tidelift
    funding_polar           = var.funding_polar
    funding_custom          = var.funding_custom
  })

  commit_message      = "chore(governance): sync FUNDING.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

# ─── Managed files: shared OSS workflows ───────────────────────────────
#
# Five generic workflows templated identically across the repo set.
# Each has its own manage_workflow_* toggle so repos that need a
# bespoke version can opt out and keep their own. Actions are
# SHA-pinned in the templates (bumps come via Dependabot or manual PRs
# to the hardened-repo module; per-repo workflow files stay in sync).

resource "github_repository_file" "workflow_stale" {
  count = var.manage_workflow_stale ? 1 : 0

  repository          = github_repository.this.name
  file                = ".github/workflows/stale.yml"
  branch              = "main"
  content             = templatefile("${path.module}/workflows/stale.yml.tftpl", {})
  commit_message      = "chore(ci): sync stale.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "workflow_lock" {
  count = var.manage_workflow_lock ? 1 : 0

  repository          = github_repository.this.name
  file                = ".github/workflows/lock.yml"
  branch              = "main"
  content             = templatefile("${path.module}/workflows/lock.yml.tftpl", {})
  commit_message      = "chore(ci): sync lock.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "workflow_dependabot_auto_merge" {
  count = var.manage_workflow_dependabot_auto_merge ? 1 : 0

  repository          = github_repository.this.name
  file                = ".github/workflows/dependabot-auto-merge.yml"
  branch              = "main"
  content             = templatefile("${path.module}/workflows/dependabot-auto-merge.yml.tftpl", {})
  commit_message      = "chore(ci): sync dependabot-auto-merge.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "workflow_auto_update_pr" {
  count = var.manage_workflow_auto_update_pr ? 1 : 0

  repository          = github_repository.this.name
  file                = ".github/workflows/auto-update-pr.yml"
  branch              = "main"
  content             = templatefile("${path.module}/workflows/auto-update-pr.yml.tftpl", {})
  commit_message      = "chore(ci): sync auto-update-pr.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "workflow_cla_dco" {
  count = var.manage_workflow_cla_dco ? 1 : 0

  repository          = github_repository.this.name
  file                = ".github/workflows/cla-dco.yml"
  branch              = "main"
  content             = templatefile("${path.module}/workflows/cla-dco.yml.tftpl", {})
  commit_message      = "chore(ci): sync cla-dco.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "workflow_scorecard" {
  count = local.eff_manage_workflow_scorecard ? 1 : 0

  repository          = github_repository.this.name
  file                = ".github/workflows/scorecard.yml"
  branch              = "main"
  content             = templatefile("${path.module}/workflows/scorecard.yml.tftpl", {})
  commit_message      = "chore(ci): sync scorecard.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "workflow_osv_scan" {
  count = var.manage_workflow_osv_scan ? 1 : 0

  repository          = github_repository.this.name
  file                = ".github/workflows/osv-scan.yml"
  branch              = "main"
  content             = templatefile("${path.module}/workflows/osv-scan.yml.tftpl", {})
  commit_message      = "chore(ci): sync osv-scan.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "workflow_betterleaks" {
  count = var.manage_workflow_betterleaks ? 1 : 0

  repository          = github_repository.this.name
  file                = ".github/workflows/betterleaks.yml"
  branch              = "main"
  content             = templatefile("${path.module}/workflows/betterleaks.yml.tftpl", {})
  commit_message      = "chore(ci): sync betterleaks.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "workflow_clean_workflow" {
  count = var.manage_workflow_clean_workflow ? 1 : 0

  repository          = github_repository.this.name
  file                = ".github/workflows/clean-workflow.yml"
  branch              = "main"
  content             = templatefile("${path.module}/workflows/clean-workflow.yml.tftpl", {})
  commit_message      = "chore(ci): sync clean-workflow.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "workflow_clanker_filter" {
  count = local.eff_manage_workflow_clanker_filter ? 1 : 0

  repository = github_repository.this.name
  file       = ".github/workflows/clanker-filter.yml"
  branch     = "main"
  content = templatefile("${path.module}/workflows/clanker-filter.yml.tftpl", {
    clanker_filter_allowlist = var.clanker_filter_allowlist
  })
  commit_message      = "chore(ci): sync clanker-filter.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "workflow_license" {
  count = var.manage_workflow_license ? 1 : 0

  repository = github_repository.this.name
  file       = ".github/workflows/license.yml"
  branch     = "main"
  content = templatefile("${path.module}/workflows/license.yml.tftpl", {
    language = var.language
  })
  commit_message      = "chore(ci): sync license.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "workflow_dependency_review" {
  count = local.eff_manage_workflow_dependency_review ? 1 : 0

  repository          = github_repository.this.name
  file                = ".github/workflows/dependency-review.yml"
  branch              = "main"
  content             = templatefile("${path.module}/workflows/dependency-review.yml.tftpl", {})
  commit_message      = "chore(ci): sync dependency-review.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "workflow_commitlint" {
  count = var.manage_workflow_commitlint ? 1 : 0

  repository          = github_repository.this.name
  file                = ".github/workflows/commitlint.yml"
  branch              = "main"
  content             = templatefile("${path.module}/workflows/commitlint.yml.tftpl", {})
  commit_message      = "chore(ci): sync commitlint.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "workflow_coverage_badge" {
  count = (var.manage_workflow_coverage_badge && var.language == "javascript") ? 1 : 0

  repository          = github_repository.this.name
  file                = ".github/workflows/coverage-badge.yml"
  branch              = "main"
  content             = templatefile("${path.module}/workflows/coverage-badge.yml.tftpl", {})
  commit_message      = "chore(ci): sync coverage-badge.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

# ─── Biome GritQL lint plugins ─────────────────────────────────────────
#
# Drops .biome/plugins/*.grit + biome.plugins.json into each JS repo.
# Repos activate them by adding `"extends": ["./biome.plugins.json"]`
# to their biome.json (one-time manual step; not managed here to avoid
# clobbering custom biome.json settings).

locals {
  _biome_plugins = [
    "no-console",
    "no-process-exit",
    "no-prototype-builtins",
    "no-instanceof-array",
    "prefer-number-properties",
    "prefer-number-isfinite",
    "prefer-object-has-own",
    "no-new-wrappers",
    "no-new-wrappers-number",
    "no-new-wrappers-boolean",
    "prefer-string-slice",
    "prefer-string-slice-substring",
    "prefer-object-spread",
    "prefer-await-to-then",
    "security-no-eval",
    "security-no-new-regexp",
    "security-no-dynamic-require",
    "security-no-child-process",
    "security-no-buffer-constructor",
  ]
}

resource "github_repository_file" "biome_plugin" {
  for_each = (var.manage_biome_plugins && var.language == "javascript") ? toset(local._biome_plugins) : toset([])

  repository          = github_repository.this.name
  file                = ".biome/plugins/${each.key}.grit"
  branch              = "main"
  content             = file("${path.module}/biome-plugins/${each.key}.grit")
  commit_message      = "chore(lint): sync biome plugin ${each.key}.grit from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "biome_plugins_json" {
  count = (var.manage_biome_plugins && var.language == "javascript") ? 1 : 0

  repository          = github_repository.this.name
  file                = "biome.plugins.json"
  branch              = "main"
  content             = file("${path.module}/biome-plugins/biome.plugins.json")
  commit_message      = "chore(lint): sync biome.plugins.json from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}


# ─── Per-language CI / release / publish workflows ─────────────────────
#
# Three new shared workflows layered on top of the language-agnostic
# ones above. The template file is selected by var.language so a single
# resource block dispatches to javascript / rust / golang variants.
# Until the rust and golang templates exist, the precondition on each
# resource keeps Terraform from rendering a missing file by checking
# fileexists() at plan time.

locals {
  # Parse the flat var.ci_runtimes list into per-family arrays for the
  # JS CI template. `trimprefix` strips the family prefix so "node-22"
  # becomes "22", the value the matrix's setup-node action expects.
  _ci_node_runtimes    = [for r in var.ci_runtimes : trimprefix(r, "node-") if startswith(r, "node-")]
  _ci_deno_runtimes    = [for r in var.ci_runtimes : trimprefix(r, "deno-") if startswith(r, "deno-")]
  _ci_bun_runtimes     = [for r in var.ci_runtimes : trimprefix(r, "bun-") if startswith(r, "bun-")]
  _ci_has_browser      = contains(var.ci_runtimes, "browser")
  _ci_has_cf_workers   = contains(var.ci_runtimes, "cf-workers")
  _release_env_enabled = var.manage_workflow_release && (var.language == "javascript" || var.release_profile == "action")
  # Single source of truth for "the action release flavor is active in this repo",
  # shared by every action-profile-only resource (workflow, cliff.toml, branch policy).
  _action_release_enabled = var.manage_workflow_release && var.release_profile == "action"
  # Which flavor of the action release flavor: git-cliff (language-neutral,
  # default) or semantic-release (javascript-only). Single source of truth
  # shared by the release workflow, cliff.toml, and .releaserc.json below.
  _action_release_uses_semantic_release = local._action_release_enabled && var.release_use_semantic_release

  # Discoverable list of languages with templated workflows. Used in
  # precondition error messages to tell the operator which values of
  # var.language the manage_workflow_* toggles support today.
  _languages_with_ci_template      = [for f in fileset(path.module, "workflows/ci.*.yml.tftpl") : trimprefix(trimsuffix(f, ".yml.tftpl"), "workflows/ci.")]
  _languages_with_release_template = [for f in fileset(path.module, "workflows/release.*.yml.tftpl") : trimprefix(trimsuffix(f, ".yml.tftpl"), "workflows/release.")]
  _languages_with_publish_template = [for f in fileset(path.module, "workflows/publish.*.yml.tftpl") : trimprefix(trimsuffix(f, ".yml.tftpl"), "workflows/publish.")]
}

resource "github_repository_file" "workflow_ci" {
  count = var.manage_workflow_ci ? 1 : 0

  repository = github_repository.this.name
  file       = ".github/workflows/ci.yml"
  branch     = "main"
  content = templatefile("${path.module}/workflows/ci.${var.language}.yml.tftpl", {
    node_runtimes  = local._ci_node_runtimes
    deno_runtimes  = local._ci_deno_runtimes
    bun_runtimes   = local._ci_bun_runtimes
    has_browser    = local._ci_has_browser
    has_cf_workers = local._ci_has_cf_workers
    node_version   = var.node_version
  })
  commit_message      = "chore(ci): sync ci.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
    precondition {
      condition     = var.language != null && contains(local._languages_with_ci_template, coalesce(var.language, "_"))
      error_message = "manage_workflow_ci=true requires var.language to be a language with a templated CI workflow. Available: ${join(", ", local._languages_with_ci_template)}. Got: ${coalesce(var.language, "null")}."
    }
  }
}

resource "github_repository_file" "workflow_release" {
  count = var.manage_workflow_release && var.release_profile == "library" ? 1 : 0

  repository = github_repository.this.name
  file       = ".github/workflows/release.yml"
  branch     = "main"
  content = templatefile("${path.module}/workflows/release.${var.language}.yml.tftpl", {
    node_version       = var.node_version
    slsa_generator_ref = var.slsa_generator_ref
  })
  commit_message      = "chore(ci): sync release.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
    precondition {
      condition     = var.language != null && contains(local._languages_with_release_template, coalesce(var.language, "_"))
      error_message = "manage_workflow_release=true requires var.language to be a language with a templated release workflow. Available: ${join(", ", local._languages_with_release_template)}. Got: ${coalesce(var.language, "null")}."
    }
  }
}

resource "github_repository_file" "workflow_publish" {
  count = var.manage_workflow_publish && var.release_profile == "library" ? 1 : 0

  repository = github_repository.this.name
  file       = ".github/workflows/publish.yml"
  branch     = "main"
  content = templatefile("${path.module}/workflows/publish.${var.language}.yml.tftpl", {
    node_version = var.node_version
  })
  commit_message      = "chore(ci): sync publish.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
    precondition {
      condition     = var.language != null && contains(local._languages_with_publish_template, coalesce(var.language, "_"))
      error_message = "manage_workflow_publish=true requires var.language to be a language with a templated publish workflow. Available: ${join(", ", local._languages_with_publish_template)}. Got: ${coalesce(var.language, "null")}."
    }
  }
}

resource "github_repository_file" "workflow_action_release" {
  count = local._action_release_enabled ? 1 : 0

  repository = github_repository.this.name
  file       = ".github/workflows/release.yml"
  branch     = "main"
  content = (
    local._action_release_uses_semantic_release
    ? templatefile("${path.module}/workflows/profiles/release.action.semantic-release.yml.tftpl", {
      node_version = var.node_version
    })
    : templatefile("${path.module}/workflows/profiles/release.action.yml.tftpl", {})
  )
  commit_message      = "chore(ci): sync release.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
    precondition {
      condition     = !var.release_use_semantic_release || var.language == "javascript"
      error_message = "release_use_semantic_release=true requires var.language = \"javascript\" (semantic-release needs a package.json/Node toolchain); use the default git-cliff flavor (release_use_semantic_release = false) for non-javascript action repos."
    }
  }
}

# git-cliff config: only rendered for the default (non-semantic-release) flavor.
resource "github_repository_file" "cliff_config" {
  count = local._action_release_enabled && !var.release_use_semantic_release ? 1 : 0

  repository          = github_repository.this.name
  file                = "cliff.toml"
  branch              = "main"
  content             = file("${path.module}/cliff.toml")
  commit_message      = "chore(release): sync cliff.toml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

# semantic-release config: only rendered for the semantic-release flavor.
# package.json's "private": true stays a one-time manual step in the
# consuming repo (see docs/action-release-flavor.md) -- Terraform doesn't
# merge into an existing package.json. No devDependencies needed: the
# workflow installs semantic-release and its plugins fresh in the job.
resource "github_repository_file" "semantic_release_config" {
  count = local._action_release_uses_semantic_release ? 1 : 0

  repository          = github_repository.this.name
  file                = ".releaserc.json"
  branch              = "main"
  content             = file("${path.module}/semantic-release/.releaserc.json")
  commit_message      = "chore(release): sync .releaserc.json from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

# ─── Build / release scripts ───────────────────────────────────────────
#
# Loaded via file() (not templatefile()) because release.mjs is a JS file
# with 66+ ${...} template literals, escaping each as $${...} would be
# unreadable and easy to break on every upstream change. The asset lives
# in scripts/ (not workflows/) and keeps its native .mjs extension.

resource "github_repository_file" "release_script" {
  count = var.manage_release_script ? 1 : 0

  repository          = github_repository.this.name
  file                = "scripts/release.mjs"
  branch              = "main"
  content             = file("${path.module}/scripts/release.mjs")
  commit_message      = "chore(release): sync release.mjs from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "dependabot_config" {
  count = var.manage_dependabot_config ? 1 : 0

  repository = github_repository.this.name
  file       = ".github/dependabot.yml"
  branch     = "main"
  content = templatefile("${path.module}/dependabot.yml.tftpl", {
    language                   = var.language
    dependabot_version_updates = var.dependabot_version_updates
  })
  commit_message      = "chore(deps): sync dependabot.yml from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "codeowners" {
  count = var.manage_codeowners ? 1 : 0

  repository = github_repository.this.name
  file       = ".github/CODEOWNERS"
  branch     = "main"
  content = templatefile("${path.module}/CODEOWNERS.tftpl", {
    maintainer = var.maintainer
  })
  commit_message      = "chore(governance): sync CODEOWNERS from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "npmrc" {
  count = var.language == "javascript" ? 1 : 0

  repository = github_repository.this.name
  file       = ".npmrc"
  branch     = "main"
  # Raw copy, not templated: .npmrc has no ${} variables. Kept .tftpl for
  # convention; if a variable is ever added here, switch to templatefile().
  content             = file("${path.module}/.npmrc.tftpl")
  commit_message      = "chore(deps): sync hardened .npmrc from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

locals {
  # Minimal pnpm hardening seeded into pnpm-workspace.yaml (pnpm v10+ ignores
  # these in .npmrc). ONLY settings pnpm does not record in the lockfile, so
  # seeding them never forces a lockfile regen. autoInstallPeers and
  # lockfileIncludeTarballUrl were dropped for exactly that reason: they change
  # the lockfile and break `pnpm install --frozen-lockfile` (CI) until it is
  # regenerated. Seeded once, then the repo owns the file; pinning is enforced
  # by the CI pin guard regardless of saveExact.
  _pnpm_workspace_hardening = {
    saveExact              = true
    strictPeerDependencies = true
  }
}

resource "github_repository_file" "pnpm_workspace" {
  count = var.manage_pnpm_workspace && var.language == "javascript" ? 1 : 0

  repository = github_repository.this.name
  file       = "pnpm-workspace.yaml"
  branch     = "main"
  content = join("\n", [
    "# Seeded by the hardened-repo module. This repo OWNS this file after the first apply:",
    "# add or change overrides/allowBuilds freely; they are preserved (the",
    "# module sets ignore_changes on content). pnpm v10+ reads hardened",
    "# settings here, not .npmrc; pinning is enforced by the CI pin guard.",
    yamlencode(merge(local._pnpm_workspace_hardening, var.pnpm_workspace_settings)),
  ])
  commit_message      = "chore(deps): seed hardened pnpm-workspace.yaml from the hardened-repo module"
  overwrite_on_create = true

  # Seed-once: write the hardened baseline on first apply, then let the repo own
  # the file. Overrides change often (CVE bumps); routing each through Terraform
  # would be friction. The CI pin guard is the real pinning gate.
  lifecycle {
    ignore_changes = [content, commit_message, commit_author, commit_email]
  }
}

# ─── Bootstrap files: create if missing, then leave alone ──────────────
#
# Pattern: overwrite_on_create = false (TF errors if file already exists
# on the repo, prompting the operator to set bootstrap_<file> = false on
# that repo). After the first apply, lifecycle.ignore_changes = [content]
# means TF tracks existence but never updates the content. Per-repo edits
# made directly in the repo are preserved.

resource "github_repository_file" "license_checker_allow" {
  count = var.bootstrap_license_checker_allow && var.language == "javascript" ? 1 : 0

  repository = github_repository.this.name
  file       = ".license-checker.allow"
  branch     = "main"
  content = templatefile("${path.module}/.license-checker.allow.tftpl", {
    allow = var.license_checker_allow
  })
  commit_message      = "chore(license): bootstrap .license-checker.allow from the hardened-repo module"
  overwrite_on_create = false

  lifecycle {
    ignore_changes = [content, commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "contributing_rules" {
  count = var.manage_contributing_rules ? 1 : 0

  repository = github_repository.this.name
  file       = ".github/CONTRIBUTING-RULES.md"
  branch     = "main"
  content = templatefile("${path.module}/CONTRIBUTING-RULES.md.tftpl", {
    maintainer    = var.maintainer
    contact_email = var.security_contact_email
  })
  commit_message      = "chore(governance): sync CONTRIBUTING-RULES.md from the hardened-repo module"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "contributing" {
  count = var.bootstrap_contributing ? 1 : 0

  repository = github_repository.this.name
  file       = "CONTRIBUTING.md"
  branch     = "main"
  content = templatefile("${path.module}/CONTRIBUTING.md.tftpl", {
    repo_display_name  = var.name
    maintainer         = var.maintainer
    project_notes      = var.contributing_project_notes
    project_code_style = var.contributing_project_code_style
    project_tests      = var.contributing_project_tests
  })
  commit_message      = "chore(governance): bootstrap CONTRIBUTING.md"
  overwrite_on_create = false

  lifecycle {
    ignore_changes = [content, commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "pr_template" {
  count = var.bootstrap_pr_template ? 1 : 0

  repository          = github_repository.this.name
  file                = ".github/PULL_REQUEST_TEMPLATE.md"
  branch              = "main"
  content             = templatefile("${path.module}/PULL_REQUEST_TEMPLATE.md.tftpl", {})
  commit_message      = "chore(governance): bootstrap PR template"
  overwrite_on_create = false

  lifecycle {
    ignore_changes = [content, commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "contributors" {
  count = var.bootstrap_contributors ? 1 : 0

  repository = github_repository.this.name
  file       = ".github/CONTRIBUTORS.md"
  branch     = "main"
  content = templatefile("${path.module}/CONTRIBUTORS.md.tftpl", {
    maintainer = var.maintainer
    seed_date  = var.contributors_seed_date
  })
  commit_message      = "chore(governance): bootstrap CONTRIBUTORS.md (seeds CLA-BOT markers)"
  overwrite_on_create = false

  lifecycle {
    ignore_changes = [content, commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "issue_template_bug" {
  count = var.bootstrap_issue_templates ? 1 : 0

  repository          = github_repository.this.name
  file                = ".github/ISSUE_TEMPLATE/bug_report.yml"
  branch              = "main"
  content             = templatefile("${path.module}/issue-templates/bug_report.yml.tftpl", {})
  commit_message      = "chore(governance): bootstrap bug report template"
  overwrite_on_create = false

  lifecycle {
    ignore_changes = [content, commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "issue_template_feature" {
  count = var.bootstrap_issue_templates ? 1 : 0

  repository          = github_repository.this.name
  file                = ".github/ISSUE_TEMPLATE/feature_request.yml"
  branch              = "main"
  content             = templatefile("${path.module}/issue-templates/feature_request.yml.tftpl", {})
  commit_message      = "chore(governance): bootstrap feature request template"
  overwrite_on_create = false

  lifecycle {
    ignore_changes = [content, commit_message, commit_author, commit_email]
  }
}

resource "github_repository_file" "issue_template_config" {
  count = var.bootstrap_issue_templates ? 1 : 0

  repository = github_repository.this.name
  file       = ".github/ISSUE_TEMPLATE/config.yml"
  branch     = "main"
  content = templatefile("${path.module}/issue-templates/config.yml.tftpl", {
    repo_full_name = "${var.owner}/${var.name}"
  })
  commit_message      = "chore(governance): bootstrap issue template config"
  overwrite_on_create = false

  lifecycle {
    ignore_changes = [content, commit_message, commit_author, commit_email]
  }
}

# ─── LICENSE ───────────────────────────────────────────────────────────
#
# Standard SPDX-licensed text per project. Sync on every apply (legal
# text shouldn't drift, and any drift signals tampering worth catching).

resource "github_repository_file" "license" {
  count = var.manage_license ? 1 : 0

  repository = github_repository.this.name
  file       = "LICENSE"
  branch     = "main"
  content = templatefile("${path.module}/licenses/${local.license_template}.tftpl", {
    copyright_holder = var.maintainer
    copyright_year   = var.license_year
  })
  commit_message      = "chore(governance): sync ${var.license} LICENSE"
  overwrite_on_create = true

  lifecycle {
    ignore_changes = [commit_message, commit_author, commit_email]
  }
}

# ─── Labels ────────────────────────────────────────────────────────────
#
# Canonical label set applied to every managed repo. Mirrors what
# ward already have (colors + descriptions taken from pure-fx as
# representative). Includes:
#   - GitHub default labels (bug, enhancement, documentation, etc.)
#   - Conventional Commits types (feat, fix, perf, refactor, test, chore,
#     ci, docs, breaking)
#   - CLA + DCO status (cla:needed/signed, dco:failed/passed)
#   - PR size markers (size:xs through size:xl)
#   - Workflow signals (dependencies, stale)
#
# github_issue_labels manages the FULL label set on the repo: any label
# not in this list (or var.extra_labels) is DELETED on apply. Per-repo
# customisations go via extra_labels.

locals {
  canonical_labels = [
    { name = "breaking", color = "b60205", description = "Breaking change" },
    { name = "bug", color = "d73a4a", description = "Something isn't working" },
    { name = "chore", color = "ededed", description = "Maintenance" },
    { name = "ci", color = "e6e6e6", description = "CI/CD changes" },
    { name = "cla:needed", color = "b60205", description = "CLA signature required" },
    { name = "cla:signed", color = "0e8a16", description = "CLA signed by contributor" },
    { name = "collaborator-opened", color = "0e8a16", description = "Opened by a repository collaborator; exempt from stale auto-close" },
    { name = "dco:failed", color = "b60205", description = "Commits missing Signed-off-by" },
    { name = "dco:passed", color = "0e8a16", description = "All commits have Signed-off-by" },
    { name = "dependencies", color = "0366d6", description = "Dependency updates" },
    { name = "docs", color = "0075ca", description = "Documentation change" },
    { name = "documentation", color = "0075ca", description = "Improvements or additions to documentation" },
    { name = "duplicate", color = "cfd3d7", description = "This issue or pull request already exists" },
    { name = "enhancement", color = "a2eeef", description = "New feature or request" },
    { name = "feat", color = "a2eeef", description = "New feature" },
    { name = "fix", color = "d73a4a", description = "Bug fix" },
    { name = "gate:quality:needs-issue", color = "fbca04", description = "Rejected by the PR Quality Gate: PR is missing a linked issue (`Closes #N`)" },
    { name = "gate:quality:rejected", color = "b60205", description = "Rejected by the PR Quality Gate" },
    { name = "gate:quality:unapproved-bot", color = "b60205", description = "Rejected by the PR Quality Gate: opened by a bot account not on the allow-list" },
    { name = "good first issue", color = "7057ff", description = "Good for newcomers" },
    { name = "help wanted", color = "008672", description = "Extra attention is needed" },
    { name = "invalid", color = "e4e669", description = "This doesn't seem right" },
    { name = "keep-open", color = "0e8a16", description = "Exempt from automated close (auto-supersede, etc.) until manually unlabeled by a trusted human" },
    { name = "perf", color = "f9d0c4", description = "Performance improvement" },
    { name = "question", color = "d876e3", description = "Further information is requested" },
    { name = "refactor", color = "fef2c0", description = "Code refactoring" },
    { name = "size:l", color = "f9d0c4", description = "Large change (250-999 lines)" },
    { name = "size:m", color = "fef2c0", description = "Medium change (50-249 lines)" },
    { name = "size:s", color = "bfd4f2", description = "Small change (10-49 lines)" },
    { name = "size:xl", color = "b60205", description = "Very large change (1000+ lines)" },
    { name = "size:xs", color = "ededed", description = "Tiny change (1-9 lines)" },
    { name = "stale", color = "ededed", description = "No activity for extended period" },
    { name = "superseded", color = "cfd3d7", description = "Closed because a sibling PR was merged that overlaps with the same files" },
    { name = "test", color = "bfd4f2", description = "Test changes" },
    { name = "wontfix", color = "ffffff", description = "This will not be worked on" },
  ]

  all_labels = concat(local.canonical_labels, var.extra_labels)
}

resource "github_issue_labels" "this" {
  count = var.manage_labels ? 1 : 0

  repository = github_repository.this.name

  dynamic "label" {
    for_each = local.all_labels
    content {
      name        = label.value.name
      color       = label.value.color
      description = label.value.description
    }
  }
}

# ─── Tag ruleset: protect release tags ─────────────────────────────────

# ─── App-token secrets (repo-level, opt-in) ────────────────────────────
#
# See the manage_bot_app_secrets variable for the design rationale.
# These resources push the same values as the org-level secrets in
# org-secrets.tf, but at repo scope, needed for repos under user
# accounts where GitHub's secret model has no user-level org-equivalent.
# Both resources are gated on the same variable so they stay in lockstep.

resource "github_actions_secret" "bot_app_client_id" {
  count = var.manage_bot_app_secrets ? 1 : 0

  repository  = github_repository.this.name
  secret_name = "BOT_APP_CLIENT_ID"
  value       = var.bot_app_client_id

  lifecycle {
    precondition {
      condition     = !var.manage_bot_app_secrets || length(var.bot_app_client_id) > 0
      error_message = "manage_bot_app_secrets = true requires a non-empty bot_app_client_id."
    }
  }
}

resource "github_actions_secret" "bot_app_private_key" {
  count = var.manage_bot_app_secrets ? 1 : 0

  repository  = github_repository.this.name
  secret_name = "BOT_APP_PRIVATE_KEY"
  value       = var.bot_app_private_key

  lifecycle {
    precondition {
      condition     = !var.manage_bot_app_secrets || length(var.bot_app_private_key) > 0
      error_message = "manage_bot_app_secrets = true requires a non-empty bot_app_private_key."
    }
  }
}

# Dependabot-triggered workflow runs (actor == dependabot[bot]) read
# secrets from the separate Dependabot store, not the Actions store.
# dependabot-auto-merge.yml mints an App token to approve + enable
# auto-merge, so the same two values are mirrored into that store.
# Gated on the same variable as the Actions pair to stay in lockstep.

resource "github_dependabot_secret" "bot_app_client_id" {
  count = var.manage_bot_app_secrets ? 1 : 0

  repository  = github_repository.this.name
  secret_name = "BOT_APP_CLIENT_ID"
  value       = var.bot_app_client_id
}

resource "github_dependabot_secret" "bot_app_private_key" {
  count = var.manage_bot_app_secrets ? 1 : 0

  repository  = github_repository.this.name
  secret_name = "BOT_APP_PRIVATE_KEY"
  value       = var.bot_app_private_key
}

# ─── Tag ruleset: protect release tags ─────────────────────────────────

resource "github_repository_ruleset" "release_tags" {
  count = local.eff_protect_tag_pattern != null ? 1 : 0

  repository  = github_repository.this.name
  name        = var.release_tags_ruleset_name
  target      = "tag"
  enforcement = "active"

  conditions {
    ref_name {
      include = ["refs/tags/${local.eff_protect_tag_pattern}"]
      exclude = []
    }
  }

  bypass_actors {
    actor_id    = 5
    actor_type  = "RepositoryRole"
    bypass_mode = "always"
  }

  dynamic "bypass_actors" {
    for_each = var.bot_app_id != null ? [var.bot_app_id] : []
    content {
      actor_id    = tonumber(bypass_actors.value)
      actor_type  = "Integration"
      bypass_mode = "always"
    }
  }

  rules {
    creation         = true
    deletion         = true
    non_fast_forward = true
  }
}

# ─── Publish environments (per-registry deployment gates) ──────────────
#
# Two environments per JS repo with manage_workflow_publish = true,
# matching the environment names the templated publish.yml references
# (`npm-publish`, `jsr-publish`). Each enforces:
#
#   1. Tag-only deployments via the deployment_branch_policy block +
#      github_repository_environment_deployment_policy below.
#   2. Optional human approval via the reviewers list (empty list
#      disables the manual-approval gate but keeps the tag policy).
#
# Reviewers in the variable are usernames; the resource expects user
# IDs. data.github_user is the username -> ID lookup. Only created when
# the reviewer list is non-empty, so empty-list repos don't burn an API
# call per plan.

data "github_user" "npm_publish_reviewers" {
  for_each = (var.manage_workflow_publish && var.language == "javascript") ? toset(var.npm_publish_reviewers) : toset([])
  username = each.value
}

data "github_user" "jsr_publish_reviewers" {
  for_each = (var.manage_workflow_publish && var.language == "javascript") ? toset(var.jsr_publish_reviewers) : toset([])
  username = each.value
}

resource "github_repository_environment" "npm_publish" {
  count = (var.manage_workflow_publish && var.language == "javascript") ? 1 : 0

  repository  = github_repository.this.name
  environment = "npm-publish"

  wait_timer = var.npm_publish_wait_timer_minutes

  dynamic "reviewers" {
    for_each = length(var.npm_publish_reviewers) > 0 ? [1] : []
    content {
      users = [for u in var.npm_publish_reviewers : data.github_user.npm_publish_reviewers[u].id]
    }
  }

  deployment_branch_policy {
    protected_branches     = false
    custom_branch_policies = true
  }
}

resource "github_repository_environment_deployment_policy" "npm_publish_tag" {
  count = (var.manage_workflow_publish && var.language == "javascript") ? 1 : 0

  repository  = github_repository.this.name
  environment = github_repository_environment.npm_publish[0].environment
  tag_pattern = "v*"
}

resource "github_repository_environment" "jsr_publish" {
  count = (var.manage_workflow_publish && var.language == "javascript") ? 1 : 0

  repository  = github_repository.this.name
  environment = "jsr-publish"

  wait_timer = var.jsr_publish_wait_timer_minutes

  dynamic "reviewers" {
    for_each = length(var.jsr_publish_reviewers) > 0 ? [1] : []
    content {
      users = [for u in var.jsr_publish_reviewers : data.github_user.jsr_publish_reviewers[u].id]
    }
  }

  deployment_branch_policy {
    protected_branches     = false
    custom_branch_policies = true
  }
}

resource "github_repository_environment_deployment_policy" "jsr_publish_tag" {
  count = (var.manage_workflow_publish && var.language == "javascript") ? 1 : 0

  repository  = github_repository.this.name
  environment = github_repository_environment.jsr_publish[0].environment
  tag_pattern = "v*"
}

# ─── Release environment ────────────────────────────────────────────────
#
# Gates the publish-gh job in release.yml behind a `release` environment.
# Only fires when manage_workflow_release = true; tag policy restricts
# deployments to v* tags. Reviewer list defaults empty (no manual gate),
# but can be set per-repo to require a human sign-off before assets are
# attached to the GitHub release.

data "github_user" "release_reviewers" {
  for_each = local._release_env_enabled ? toset(var.release_reviewers) : toset([])
  username = each.value
}

resource "github_repository_environment" "release" {
  count = local._release_env_enabled ? 1 : 0

  repository  = github_repository.this.name
  environment = "release"

  wait_timer = var.release_wait_timer_minutes

  dynamic "reviewers" {
    for_each = length(var.release_reviewers) > 0 ? [1] : []
    content {
      users = [for u in var.release_reviewers : data.github_user.release_reviewers[u].id]
    }
  }

  deployment_branch_policy {
    protected_branches     = false
    custom_branch_policies = true
  }
}

resource "github_repository_environment_deployment_policy" "release_tag" {
  count = local._release_env_enabled && var.release_profile == "library" ? 1 : 0

  repository  = github_repository.this.name
  environment = github_repository_environment.release[0].environment
  tag_pattern = "v*"
}

resource "github_repository_environment_deployment_policy" "release_branch" {
  count = local._action_release_enabled ? 1 : 0

  repository  = github_repository.this.name
  environment = github_repository_environment.release[0].environment
  # Literal "main": the module syncs every file to branch "main", so the default
  # branch is main by construction. Avoids the github_repository.this.default_branch
  # deprecation warning firing on every plan.
  branch_pattern = "main"
}

# ─── PR creation policy drift check ────────────────────────────────────
#
# `pull_request_creation_policy` ("Creation allowed by: Collaborators only")
# is not yet writable through the Terraform GitHub provider (the field exists
# in the REST API response but the provider schema does not expose it). We
# enforce it via a check block: query the repo API at plan time and warn if
# the field is not "collaborators_only".
#
# Pass conditions (check is skipped):
#   - The API returns a non-200 status (private repo, auth missing, rate limit).
#     In these cases we can't verify, so we don't block the plan.
#   - The field is already "collaborators_only".
#
# To fix: Settings > General > Pull Requests > "Creation allowed by" ->
# select "Collaborators only".

data "http" "repo_settings" {
  count = var.enforce_pr_creation_policy ? 1 : 0

  url = "https://api.github.com/repos/${var.owner}/${var.name}"
  request_headers = merge(
    { Accept = "application/vnd.github+json" },
    var.github_token != null ? { Authorization = "Bearer ${var.github_token}" } : {}
  )

  retry {
    attempts = 1
  }
}

check "pr_creation_policy" {
  assert {
    condition = (
      !var.enforce_pr_creation_policy
      || try(data.http.repo_settings[0].status_code, 0) != 200
      || try(jsondecode(data.http.repo_settings[0].response_body).pull_request_creation_policy, "") == var.pr_creation_policy
    )
    error_message = "Repo ${var.name} has pull_request_creation_policy != '${var.pr_creation_policy}'. Run scripts/sync-repo-settings.sh to fix."
  }
}

# Actions ship via git ref, not a package registry: publish + action profile
# is a configuration error. Surfaces as a plan-time warning, not a hard failure,
# to match the other check blocks in this module.
check "action_profile_has_no_publish" {
  assert {
    condition     = !(var.release_profile == "action" && var.manage_workflow_publish)
    error_message = "release_profile = \"action\" does not publish to a registry; set manage_workflow_publish = false."
  }
}
