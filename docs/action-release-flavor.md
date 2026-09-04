# Action release flavor

Standardized release pipeline for GitHub Actions (git-ref + Marketplace),
distinct from the npm/JSR library flavor. Two changelog/versioning
sub-flavors share everything else (bot App token, tag-protection bypass,
build-provenance attestation, moving the vMAJOR tag): **git-cliff**
(default, language-neutral) and **semantic-release** (javascript only). Pick
one with `release_use_semantic_release`.

## git-cliff sub-flavor (default)

    language                = "javascript"   # or omit for a non-JS composite action
    manage_workflow_release = true
    release_profile         = "action"
    manage_workflow_publish = false           # actions do not publish to a registry
    protect_tag_pattern     = "v*"            # tag ruleset; bot bypasses non-fast-forward
    manage_bot_app_secrets  = true            # or rely on org-level BOT_APP_* secrets
    bot_app_id              = var.bot_app_id
    bot_app_client_id       = var.bot_app_client_id
    bot_app_private_key     = var.bot_app_private_key

What it renders into the repo:

- `.github/workflows/release.yml` — `workflow_dispatch` with a `version` input.
- `cliff.toml` — Keep-a-Changelog git-cliff config.

Cutting a release: run the `release` workflow (Actions tab) with `version`
(e.g. `1.0.0`). The bot-privileged job renders `CHANGELOG.md`, commits it,
tags `v1.0.0`, publishes a GitHub Release with a build-provenance attestation
over the source tarball, and moves the `v1` major tag (stable releases only;
prereleases like `1.0.0-rc.1` do not move the major tag).

Changelog entries come entirely from Conventional Commits: no contributor
action beyond writing a properly-scoped commit message.

## semantic-release sub-flavor (`release_use_semantic_release = true`, javascript only)

    language                     = "javascript"
    manage_workflow_release      = true
    release_profile              = "action"
    release_use_semantic_release = true
    manage_workflow_publish      = false
    protect_tag_pattern          = "v*"
    manage_bot_app_secrets       = true
    bot_app_id                   = var.bot_app_id
    bot_app_client_id            = var.bot_app_client_id
    bot_app_private_key          = var.bot_app_private_key

Rejected at plan time (a `precondition` on `workflow_action_release`) unless
`language = "javascript"`: semantic-release needs a package.json/Node
toolchain, so it can't run for a Python/Rust/Go composite action. Use the
git-cliff sub-flavor for those.

What it renders into the repo:

- `.github/workflows/release.yml` — triggered on every push to `main`, no
  `workflow_dispatch` input.
- `.releaserc.json` — plugins: commit-analyzer, release-notes-generator,
  changelog, npm (`npmPublish: false`), exec (`pnpm run build`), git
  (commits `package.json`, `CHANGELOG.md`, `dist/**`), github.

Cutting a release: nothing manual. On every push to `main`, `commit-analyzer`
reads Conventional Commits since the last release and decides the bump
(`fix:` -> patch, `feat:` -> minor, a `BREAKING CHANGE` footer or `!` ->
major). If no commit warrants a release, the job is a no-op. If one does, the
workflow installs the repo's own dependencies (`pnpm install
--frozen-lockfile`, from the repo's own lockfile, same as `ci.yml`), then the
bot-privileged job bumps `package.json`, builds `dist/` (`@semantic-release/exec`'s
`prepareCmd` runs `pnpm run build` after the version bump, before the commit),
and commits `package.json` + `CHANGELOG.md` + `dist/**` straight to `main` (no
PR, same bot-bypass as the git-cliff flavor's changelog commit), tags the
release (e.g. `v1.2.0`), publishes a GitHub Release (`@semantic-release/github`
writes the body from the generated release notes; the workflow then attaches
the source tarball, checksum, and build-provenance attestation), and moves
the `v1` major tag.

`dist/index.js` (the file the `node24` runtime actually executes for
`uses: owner/repo@ref`) is gitignored everywhere except this release commit:
it is intentionally not committed on regular pushes to `main`, only built and
committed here as part of cutting a release. This requires a `"build"` script
in the consuming repo's `package.json` that produces `dist/index.js`.

`@semantic-release/changelog`, `@semantic-release/exec`, and
`@semantic-release/git` are not bundled with `semantic-release` core
(`commit-analyzer`, `release-notes-generator`, `npm`, and `github` are); the
workflow's `cycjimmy/semantic-release-action` step pre-installs them via
`extra_plugins`.

### One-time manual step (semantic-release only)

Terraform owns `.releaserc.json`, but not the rest of `package.json` (it
doesn't merge into an existing file). Before the first apply with
`release_use_semantic_release = true`, add by hand:

    "private": true

Also required by hand, both one-time:

- A `"build"` script in `package.json` that produces `dist/index.js`
  (`@semantic-release/exec`'s `prepareCmd` in `.releaserc.json` runs
  `pnpm run build`).
- `dist/` added to `.gitignore` in the consuming repo, and removed from
  regular `main` tracking if it was previously committed there
  (`git rm --cached -r dist/`). It should only ever be committed by this
  release workflow, never on a regular push to `main` or in a PR.

No *semantic-release* devDependencies needed: it and its plugins install
fresh inside the job via `extra_plugins`, not into the repo's own lockfile.
The repo's own devDependencies (esbuild etc., whatever the `"build"` script
needs) are a separate concern, already in its lockfile, installed by the
workflow's `pnpm install --frozen-lockfile` step.

`"private": true` matters here for a reason distinct from "don't publish to
npm": `@semantic-release/npm`'s `prepare` step still runs `npm version
<x> --no-git-tag-version` regardless (that's what keeps `package.json`'s
version field in sync with the tag), but its `verifyConditions`/`publish`
steps skip npm registry auth and the actual `npm publish` call entirely when
`pkg.private === true` (verified against `@semantic-release/npm`'s source:
`if (pluginConfig.npmPublish !== false && pkg.private !== true)`). Without
`"private": true`, the job would fail on missing npm registry credentials it
has no reason to need.

## Prerequisites (one-time, per repo, both sub-flavors)

1. **Disable GitHub Immutable Releases.** Moving the major tag needs mutable
   tags. See `disable-immutable-releases.md`. The `warn_on_immutable_releases`
   check fires a plan warning if a published release is immutable.
2. **Marketplace branding.** Add `branding: { icon, color }` to `action.yml`.
   The first-ever Marketplace publish is a manual acceptance in the Release UI;
   subsequent releases list automatically.
3. **Bot secrets present.** `BOT_APP_CLIENT_ID` / `BOT_APP_PRIVATE_KEY`
   (repo-level via `manage_bot_app_secrets`, or org-level).

Not included: registry publishing, SLSA reusable-generator provenance (the
library flavor's `publish.<language>.yml` / SLSA L3 pipeline). The attestation
here is a single `actions/attest-build-provenance` step over the tarball.
