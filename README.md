# openclaw-read-guardrail

A `before_tool_call` plugin for [OpenClaw](https://github.com/openclaw/openclaw) that enforces read-only workspace isolation for multi-agent setups. The upstream `tools.fs.workspaceOnly: true` config enforces write/edit but **not read**. This plugin fills that gap.

Built for setups where a social/public-facing agent shares a gateway with a private agent and must never read the private agent's workspace, config files, credentials, or environment variables.

## The Problem

OpenClaw's `workspaceOnly` restricts write, edit, and apply-patch tools to the agent's workspace. But the `read` tool, `image` tool, and `pdf` tool can access any path on the filesystem. In a multi-agent setup where one agent handles private DMs and another handles group chats with non-operator humans, this is a privacy gap. A prompt injection in the group chat could instruct the social agent to read `openclaw.json`, `.env`, or private workspace files and leak them into the conversation.

GitHub issues requesting this feature natively:
- [#12202](https://github.com/openclaw/openclaw/issues/12202) -- per-agent file path access control
- [#28869](https://github.com/openclaw/openclaw/issues/28869) -- tools.fs.allowPaths

Neither has shipped. This plugin fills the gap using the `before_tool_call` hook, the same pattern used by [EasyClaw's file-permissions plugin](https://github.com/gaoyangz77/easyclaw) (guards read/write/edit/image/apply-patch), [ClawBands](https://github.com/SeyZ/clawbands), [predicate-claw](https://github.com/PredicateSystems/predicate-claw), and [Equilibrium Guard](https://github.com/rizqcon/equilibrium-guard).

## What It Does

Registers a `before_tool_call` hook that intercepts `read`, `image`, `pdf`, and `diffs` tool calls. For the configured agent (default: "social"), it:

1. Extracts file paths from tool-specific parameters (read uses `path`, image uses `image`, pdf uses `pdf`/`pdfs`)
2. Filters out remote URIs (http, https, ftp, s3, data, etc.)
3. Normalizes local paths (null bytes, `~`, `$HOME`, `${HOME}`, `file://` URIs, `..` traversals, relative paths)
4. Checks against an always-blocked list (defense in depth)
5. Checks against an allowlist (default: agent workspace + /tmp/)
6. Returns `{ block: true }` if not allowed

The main/private agent is unrestricted. Unknown agents are unrestricted (fail-open for non-configured agents, fail-closed for missing paths).

### Why only read tools?

OpenClaw's `tools.fs.workspaceOnly` already enforces write, edit, and apply_patch to the agent's workspace. The `exec` tool is separately gated by `exec-approvals.json`. The **read** tool is the gap: `workspaceOnly` does not restrict it. This plugin fills exactly that gap plus the `image` and `pdf` tools which have the same unrestricted file-loading behavior.

If you need a plugin that guards both reads AND writes in a single hook (e.g., because you don't trust `workspaceOnly` or want unified logging), see [EasyClaw's file-permissions plugin](https://github.com/gaoyangz77/easyclaw) which guards read/write/edit/image/apply_patch together.

## Requirements

- **OpenClaw v2026.3.12 or later.** Tested on v2026.3.12.
- **`before_tool_call` hook must be wired up in your version.** This hook was reported as unwired in [#5943](https://github.com/openclaw/openclaw/issues/5943) (Feb 2026) and [#5513](https://github.com/openclaw/openclaw/issues/5513) (Jan 2026). It is working in v2026.3.12. We cannot confirm which version first wired it up. If your version is older than v2026.3.12, the plugin may load and register without error but the hook may never fire, silently allowing all reads. See [Troubleshooting](#troubleshooting) to verify.

## Install

### 1. Copy plugin files

```bash
mkdir -p ~/.openclaw/extensions/read-guardrail
cp index.ts openclaw.plugin.json ~/.openclaw/extensions/read-guardrail/
```

### 2. Verify the manifest has the id field

```bash
cat ~/.openclaw/extensions/read-guardrail/openclaw.plugin.json | jq .id
```

Must return `"read-guardrail"`. If it returns `null`, your manifest is missing the required `id` field and the gateway will refuse to start. The `name` field is display-only. The `id` field is what the gateway uses for discovery and config binding. OpenClaw does **not** infer id from the directory name.

### 3. Add to plugins.allow and plugins.entries

**Both steps are required on v2026.3.12+.** v2026.3.12 disabled implicit workspace plugin auto-load as a security fix ([GHSA-99qw-6mr3-36qr](https://github.com/openclaw/openclaw/security/advisories/GHSA-99qw-6mr3-36qr)). Without `plugins.allow`, the plugin silently fails to load with no error, only a warning buried in journalctl.

```bash
jq '
  .plugins.allow = ((.plugins.allow // []) + ["read-guardrail"] | unique) |
  .plugins.entries."read-guardrail" = {"enabled": true}
' ~/.openclaw/openclaw.json > /tmp/oc-patch.json && mv /tmp/oc-patch.json ~/.openclaw/openclaw.json
```

This command is safe to run multiple times (it deduplicates the allow array).

### 4. Restart gateway

```bash
openclaw gateway restart
```

This works on both macOS (launchd) and Linux (systemd). If you run OpenClaw as a system service on Linux, use `sudo systemctl restart openclaw` instead.

### 5. Verify

```bash
journalctl -u openclaw --since "1 min ago" | grep '\[read-guardrail\]'
```

You should see a line like:

```
[read-guardrail] Active v1.3.4. Guarding agent="social", tools=[read,image,pdf,diffs], 2 allowed paths, 6 always-blocked paths, workspaceRoot="<your-workspace-path>".
```

You should NOT see:
- `plugin not found` -- missing `plugins.allow` (see step 3)
- `plugin manifest requires id` -- missing `id` field in manifest (see step 2)
- `Unknown config key` -- you have an old version with the ALLOWED_KEYS bug (update to v1.3.4)

### 6. Test

**Block test:** In the social agent's channel, ask it to read `~/.openclaw/openclaw.json`. Should get "Access denied."

**Allow test:** Ask the social agent to read `SOUL.md` (or any file in its workspace). Should succeed.

## Adapt for Your Setup

The plugin auto-detects your home directory from `process.env.HOME` (Linux/macOS) or `process.env.USERPROFILE` (Windows). The `~`, `$HOME`, and `${HOME}` path expansions, the default allowed paths, and the always-blocked paths all use this detected value. **No source edits needed for home directory differences.**

You may still need to edit these constants for your agent setup:

| Constant | What to change | Default |
|----------|---------------|---------|
| `DEFAULT_SOCIAL_AGENT_ID` | Your restricted agent's id (from `openclaw.json` agents section) | `"social"` |
| `DEFAULT_ALLOWED_PATHS` | Your restricted agent's workspace path (with trailing slash) + any other allowed directories | `HOME_DIR + "/.openclaw/workspace-social/"`, `"/tmp/"` |
| `ALWAYS_BLOCKED` | Sensitive paths to block even if they fall within an allowed prefix. Update agent/workspace names to match your setup. | Config files, credentials, main agent workspace |

If your restricted agent uses a different workspace name (not `workspace-social`) or a different main agent workspace (not `workspace`), edit those path suffixes in the constants.

**Why not runtime config?** The manifest declares `configSchema` with `socialAgentId` and `allowedPaths` properties, and the gateway validates them. However, `api.config` in the plugin's `register()` function returns the full global `openclaw.json`, not plugin-scoped config. Reading plugin-scoped config would require `api.config?.plugins?.entries?.["read-guardrail"]?.config`. We use hardcoded defaults for simplicity. The configSchema is preserved so that if OpenClaw adds plugin-scoped config injection in the future, the schema is already in place.

## Architecture

### Hook priority

This plugin runs at priority 99. If you also use a write-guarding plugin (e.g., a privacy-guardrail at priority 100), it runs first since higher priority = earlier execution. There is no conflict because write-guarding plugins intercept write/edit/exec/bash while this plugin intercepts read/image/pdf/diffs.

If this is your only guardrail plugin, priority 99 is fine. The value only matters relative to other plugins using the same hook.

### Path normalization

The `normalizePath` function handles:

- Null byte stripping (OS truncation attack vector)
- `file://` URI scheme stripping with RFC 8089 authority handling
- `~` and `~/` home directory expansion (via `HOME_DIR` from `process.env.HOME`)
- `$HOME` and `${HOME}` expansion with boundary checks (prevents `$HOME_EXTRA` false match)
- Relative path resolution against workspace root
- `..` traversal resolution

### Tool parameter extraction

Param names verified from [docs.openclaw.ai/tools](https://docs.openclaw.ai/tools) (March 2026):

| Tool | Param | Type | Notes |
|------|-------|------|-------|
| read | path | string | Canonical. `file_path` aliased to `path` pre-hook per [#5943](https://github.com/openclaw/openclaw/issues/5943). |
| image | image | string | Path or URL. |
| pdf | pdf | string | Single path or URL. |
| pdf | pdfs | string[] | Array of paths/URLs. All local paths validated. |
| diffs | path | string | Display label only, not a file read. Defense in depth. |

If no path can be extracted from a guarded tool call, the hook **fails closed** (blocks the call).

### Known limitations

- **Does not guard write/edit/apply_patch.** These are already restricted by `tools.fs.workspaceOnly`. If you have `workspaceOnly` disabled or set to false, this plugin alone is not sufficient. Note that apply_patch has a known path traversal issue when sandbox is disabled ([#12173](https://github.com/openclaw/openclaw/issues/12173)).
- **Symlink resolution timing.** The hook sees the path the model sends, not resolved symlinks. Social reads shared files (SOUL.md, IDENTITY.md) via symlinks in its workspace. **Verified safe on v2026.3.12** by Eve on live system: the hook fires before the read tool's `execute` function, receiving raw model params, not resolved targets. If OpenClaw ever changes this order, symlinked files would hit ALWAYS_BLOCKED. Test after any OpenClaw update.
- **exec tool bypass.** `exec` can read files via `cat`, `less`, etc. Mitigate separately with `exec-approvals.json`.
- **message tool media attachments.** The social agent's `message` tool can send files as media attachments, bypassing this plugin. Eve verified on live system that `mediaLocalRoots` defaults to the agent workspace + `~/.openclaw/media/` (inbound files only). Acceptable for setups where the media directory only contains files already sent to the bot.
- **Fail-open for unknown agents.** Only the configured agent is restricted. A future third agent would have unrestricted reads. Correct for two-agent setups.

## Troubleshooting

**Plugin loads but hook never fires (all reads succeed):**
Your OpenClaw version may not have `before_tool_call` wired into the tool execution pipeline. This was reported in [#5943](https://github.com/openclaw/openclaw/issues/5943) and [#5513](https://github.com/openclaw/openclaw/issues/5513). Confirmed working in v2026.3.12; we cannot confirm the exact version that first wired it up. To verify, check journalctl for `BLOCKED` or `ALLOWED` log lines from the plugin after a social agent read. If you see the plugin's `Active v1.3.4` startup line but no per-request log lines, the hook is not firing.

**`plugin not found: read-guardrail` (stale config entry ignored):**
You're on v2026.3.12+ and the plugin isn't in `plugins.allow`. This is a silent failure. See install step 3.

**`plugin manifest requires id`:**
Your manifest has `name` but no `id`. The `id` field is required. The `name` field is display-only. See install step 2.

**`Unknown config key` warnings (many lines on startup):**
You have an older version of this plugin with the `ALLOWED_KEYS` validation loop. Update to v1.3.4. In older versions, the plugin iterated `api.config` (the full global `openclaw.json`) and warned on every top-level key. The gateway already validates plugin config against `configSchema` before plugin code loads, so this loop was redundant.

**Social agent can't read its own workspace files:**
Check that `DEFAULT_ALLOWED_PATHS` includes your social agent's workspace path **with a trailing slash**. Without the trailing slash, `startsWith` matching won't work for files inside the directory.

**`loaded without install/load-path provenance` warning:**
This is informational, not an error. It appears for any plugin deployed manually to `~/.openclaw/extensions/` instead of installed via `openclaw plugins install`. The plugin works correctly. The warning goes away if you register it via the plugin installer, but for hand-deployed plugins it's expected and harmless.

## Audit History

This plugin went through **7 audit passes across 4 independent auditors** before and during deploy, plus 3 issues found during live deployment.

| Version | Auditor | Blockers | Key findings |
|---------|---------|----------|-------------|
| v1.0.0 | Author | -- | Initial draft |
| v1.1.0 | Author (3 passes) | B1, B2, B3 | Symlink allowlist, dead code, missing configSchema |
| v1.2.0 | Fresh Opus | B4, B5 | image/pdf param names wrong (silent bypass) |
| v1.3.0 | Fresh Opus | B6 | Relative path false positive broke workspace reads |
| v1.3.1 | Fresh Opus | -- | $HOME boundary, URI scheme filter, expansion math |
| v1.3.2 | Claude Code | -- | file:// authority component bypass (W11) |
| v1.3.2 | Eve (live walle) | -- | Symlinks SAFE (hook sees pre-resolution paths). mediaLocalRoots acceptable gap. Approved for deploy. |
| v1.3.3 | Live deploy | -- | Manifest id, plugins.allow, api.config scoping |
| v1.3.4 | Fresh Opus (GitHub prep) | -- | Portable HOME_DIR (process.env.HOME), audit history reordered |

**Total: 6 blockers + 11 warnings found and fixed.** 3 blockers by author, 3 by external auditor. 1 warning-level defense-in-depth fix by Claude Code. Eve verified live system behavior. 3 integration issues found on live deploy.

Full details in [CHANGELOG.md](CHANGELOG.md).

## Lessons Learned (for plugin authors)

These are things we hit during development and deploy that aren't obvious from the docs.

1. **The manifest requires `id`, not just `name`.** The `name` field is display-only. The gateway uses `id` for plugin discovery, config binding, and `plugins.entries` mapping. Without `id`, the gateway refuses to start: `plugin manifest requires id`.

2. **v2026.3.12+ requires `plugins.allow`.** Workspace plugins in `~/.openclaw/extensions/` are no longer auto-loaded ([GHSA-99qw-6mr3-36qr](https://github.com/openclaw/openclaw/security/advisories/GHSA-99qw-6mr3-36qr)). The failure mode is silent: no error, just a warning in journalctl that the plugin was "not found."

3. **`api.config` is the full global config, not plugin-scoped.** If your `register(api)` function reads `api.config`, you get every key in `openclaw.json` (meta, gateway, channels, models, agents, tools, etc.). Do not validate api.config keys against your plugin's expected config. Use `configSchema` in the manifest for config validation, which the gateway enforces before your code loads.

4. **Plugin-scoped config is at a nested path.** If you need runtime access to your plugin's config values, read from `api.config?.plugins?.entries?.["your-plugin-id"]?.config`, not from `api.config` directly.

5. **Verify tool param names from the docs, not from assumptions.** The `read` tool uses `params.path`. The `image` tool uses `params.image`. The `pdf` tool uses `params.pdf`/`params.pdfs`. We assumed they all used `params.path` and shipped a silent bypass for two tools. Always verify from [docs.openclaw.ai/tools](https://docs.openclaw.ai/tools).

6. **`before_tool_call` may not be wired up in older versions.** Issues [#5943](https://github.com/openclaw/openclaw/issues/5943) and [#5513](https://github.com/openclaw/openclaw/issues/5513) reported it wasn't connected to the tool execution pipeline. The plugin will load and register without error, but the hook will never fire. Verify on your version by checking for log output after a tool call.

## Related Projects

- [openclaw-agent-privacy](https://github.com/jamebobob/openclaw-agent-privacy) -- Parent framework: three-layer defense model for multi-agent privacy
- [openclaw-mem0-multi-pool](https://github.com/jamebobob/openclaw-mem0-multi-pool) -- Per-agent memory pool isolation plugin patches
- [openclaw-privacy-guardrail](https://github.com/jamebobob/openclaw-privacy-guardrail) -- Write/edit/exec blocking for public-facing agents
- [openclaw-privacy-protocol](https://github.com/jamebobob/openclaw-privacy-protocol) -- Output scrubbing rules
- [openclaw-sticky-context](https://github.com/jamebobob/openclaw-sticky-context) -- Compaction-proof context injection plugin
- [openclaw-memory-protocol](https://github.com/jamebobob/openclaw-memory-protocol) -- Memory persistence protocol

## License

MIT
