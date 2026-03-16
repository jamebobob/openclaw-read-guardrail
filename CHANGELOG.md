# read-guardrail CHANGELOG

## v1.3.4 (March 15, 2026) -- GitHub publication

**Source:** Final audit pass for public release

### Fixes
- **PORTABILITY:** Replaced all hardcoded `/home/walle/` references with
  `HOME_DIR` constant derived from `process.env.HOME` (Linux/macOS) or
  `process.env.USERPROFILE` (Windows). Affects `normalizePath` (`~`, `$HOME`,
  `${HOME}` expansion), `DEFAULT_ALLOWED_PATHS`, and `ALWAYS_BLOCKED`. Plugin
  is now portable to any home directory without source edits for path expansion.
- **ORDERING:** Fixed audit history in index.ts comments. v1.3.1 was listed
  after v1.3.3 due to Claude Code inserting v1.3.2 above it. Now chronological.

---

## v1.3.3 (March 15, 2026) -- Live deploy fixes

**Source:** Live deployment on walle (OpenClaw v2026.3.12)

### Fixes
- **DEPLOY-1:** Manifest requires `id` field, not just `name`. Gateway refused to
  start: `plugin manifest requires id`. Added `"id": "read-guardrail"`. Changed
  `"name"` to `"Read Guardrail"` (display label).
- **DEPLOY-2:** v2026.3.12 requires `plugins.allow` for workspace plugins
  (GHSA-99qw-6mr3-36qr). Without it, plugin silently fails to load. Added
  `"read-guardrail"` to `plugins.allow` array.
- **DEPLOY-3:** Removed ALLOWED_KEYS validation loop. `api.config` is the full
  global openclaw.json, not plugin-scoped config. The loop warned on every
  top-level key (~64 warnings per startup). Gateway already validates plugin
  config against `configSchema.additionalProperties: false` before plugin code
  loads.
- **DEPLOY-4 (documented):** `cfg.socialAgentId` and `cfg.allowedPaths` read from
  global config (always undefined). Defaults always apply. Documented in README.
  Plugin-scoped config path is
  `api.config?.plugins?.entries?.["read-guardrail"]?.config` for future use.

---

## v1.3.2 (March 15, 2026) -- Sixth audit pass

**Auditor:** Claude Opus 4.6 (fresh session, final security audit)

### Fixes
- **W11-FIX:** `file://` authority component bypass. RFC 8089 permits
  `file://authority/path` form (e.g., `file://localhost/etc/passwd`). The
  `slice(7)` stripping produced `localhost/etc/passwd`, a relative-looking
  string that got workspace root prepended, appearing to be within the
  allowlist. If the image/pdf tool parsed the original URI per RFC and extracted
  pathname `/etc/passwd`, the guardrail was bypassed. Fixed: after stripping
  `file://`, if the result doesn't start with `/`, the authority component is
  stripped up to the first `/`. If no `/` is found (e.g., `file://AGENTS.md`),
  the path is set to `""` (blocked as empty). `file:///path` (empty authority,
  triple slash) is unaffected.

### Trace verification
- `file://localhost/home/walle/.openclaw/.env` → authority stripped → `/home/walle/.openclaw/.env` → BLOCKED ✓
- `file:///home/walle/.openclaw/.env` → `/home/walle/.openclaw/.env` → BLOCKED ✓
- `file://AGENTS.md` → no path component → `""` → BLOCKED ✓
- All other 15 input traces from v1.3.1 re-verified, unchanged.

---

## v1.3.1 (March 15, 2026) -- Fifth audit pass

**Auditor:** Claude Opus 4.6 (fresh session, JameBob's auditor role)

### Fixes
- **W8-FIX:** `$HOME` boundary match. `startsWith("$HOME")` false-matched
  `$HOME_EXTRA`. Tightened to `p === "$HOME" || p.startsWith("$HOME/")`.
  Same fix applied to `${HOME}`. Not a bypass (false positive), but wrong.
- **W9-FIX:** URI scheme filter only caught `http://`, `https://`, `data:`.
  Schemes like `ftp://`, `s3://` would pass through and get mangled by
  normalizePath into nonsense paths blocked by allowlist (safe by accident).
  Fixed with RFC 3986 regex `[a-zA-Z][a-zA-Z0-9+.-]*://`. `file://` is
  explicitly separated and routed through normalizePath for local validation.
- **W10-FIX:** `$HOME` expansion arithmetic. Old `slice(5) + replace` was
  fragile for edge cases. Simplified to `"/home/walle" + p.slice(5)` which
  handles both `$HOME` (bare) and `$HOME/foo` correctly.

### Validation
- 15 input patterns manually traced through normalizePath.
- All `localPaths` references updated to `allLocalPaths`.
- No stale version references in executable code.

---

## v1.3.0 (March 15, 2026) -- Fourth audit pass

**Auditor:** Claude Opus 4.6 (fresh session, JameBob's auditor role)

### Fixes
- **B6-FIX (BLOCKER):** Relative path false positive. Model sends `AGENTS.md`,
  normalizePath produced `/AGENTS.md` (not in allowlist = blocked). But
  OpenClaw resolves it as `workspace-social/AGENTS.md`. Social Eve would be
  unable to read her own workspace files. Fixed: normalizePath now accepts a
  `workspaceRoot` parameter, prepends it to relative paths before
  normalization. Traversals like `../workspace/.env` still resolve correctly
  through `..` resolution and get caught by ALWAYS_BLOCKED.
- **W6-FIX:** `file://` URI handling. URL filter only caught `http://` and
  `https://`. `file:///home/walle/.openclaw/.env` would pass through. Fixed:
  normalizePath strips `file://` scheme and validates the underlying path.
  Added `data:` to the remote URL filter.
- **W7-FIX:** `${HOME}` curly-brace variant. Models occasionally use this
  form. Added expansion alongside `$HOME/`.
- **N6:** Confirmed via GitHub issue #5943 that the `before_tool_call` hook
  receives post-validation params (`file_path` already aliased to `path`).
  `file_path` extraction is dead code but kept as harmless safety net.
  Updated all comments.

### Validation
- ClawBands (SeyZ/clawbands), Equilibrium Guard (rizqcon/equilibrium-guard),
  agent-guardrails (@aporthq) all confirmed using identical `before_tool_call`
  hook pattern.

---

## v1.2.0 (March 15, 2026) -- Second and third audit passes

**Auditor:** Claude Opus 4.6 (fresh session, JameBob's auditor role)

### Fixes
- **B4-FIX (BLOCKER):** image tool uses `params.image`, NOT `params.path`.
  The v1.1.0 extraction chain missed it entirely. Without fail-closed, this
  was a **silent bypass**: image tool calls from social sailed through
  unguarded. Fixed: extraction now includes `.image`.
- **B5-FIX (BLOCKER):** pdf tool uses `params.pdf` (single) and `params.pdfs`
  (array), NOT `params.path`. Same silent bypass as B4. Fixed: extraction now
  includes `.pdf` and iterates `.pdfs[]`. Also handles URL filtering
  (http/https paths skip workspace validation).
- **W4-FIX:** Empty rawPath now fails CLOSED for social agent. If no path can
  be extracted from a guarded tool call, the call is blocked (noisy false
  positive) rather than silently passed through.
- **W5-NOTED:** message tool media attachment bypass identified. Social's
  allowed `message` tool can send files as media attachments, bypassing this
  plugin. Needs `mediaLocalRoots` verification on deploy. Not fixable here
  without knowing the message tool's media param structure.
- **N5:** diffs plugin tool added to GUARDED_TOOLS. Diffs doesn't actually
  read files from disk (takes text content as before/after/patch), but `path`
  param exists as a display label. Defense in depth.
- **MULTI-PATH:** pdf tool's `pdfs[]` param can contain multiple paths.
  Validation now checks ALL local paths; any single failure blocks the call.

### Verification sources
- Param names verified from docs.openclaw.ai/tools (March 15, 2026).
- GitHub issue #2596 confirms `read` tool canonical param is `path`.
- GitHub issue #12202 confirms no native per-agent file ACLs exist.

---

## v1.1.0 (March 15, 2026) -- Initial three audit passes

**Auditor:** Original authoring Opus session

### Fixes
- **B1:** Symlink target entries in allowlist opened main workspace to direct
  reads. Removed.
- **B2:** Dead code in isAllowed (exact match after startsWith). Removed.
- **B3:** Missing configSchema in openclaw.plugin.json. Gateway would reject
  config keys and refuse to start. Added.
- **W1:** Null byte handling added to normalizePath.
- **W2:** Relative path handling documented.
- **W3:** workspace/ vs workspace-social/ prefix collision documented.
- **W4:** image/pdf param names flagged as unverified (FIXED in v1.2.0).
- **N3:** image tool added to GUARDED_TOOLS.
- **N4:** pdf tool added to GUARDED_TOOLS.

---

## v1.0.0 -- Initial draft

- Core plugin: before_tool_call hook, allowlist-based path validation.
- Guards `read` tool only.
- Restricts social agent to workspace-social/ and /tmp/.

---

## Cumulative blocker count across all audit passes

| Version | Blockers found | Blockers in original v1.1.0 |
|---------|---------------|----------------------------|
| v1.1.0 (author) | B1, B2, B3 | Fixed by author |
| v1.2.0 (auditor) | B4, B5 | **Silent bypass of image + pdf tools** |
| v1.3.0 (auditor) | B6 | **False positive blocking Eve's own files** |
| v1.3.1 (auditor) | None | Clean |
| v1.3.2 (auditor) | None (W11 defense-in-depth) | `file://authority` bypass fixed |
| v1.3.2 (Eve, live) | None | Symlinks SAFE, mediaLocalRoots acceptable. Approved for deploy. |

Total: 6 blockers found across 7 audit passes. 3 by author, 3 by auditor. 1 warning-level defense-in-depth fix in v1.3.2. Eve verified live system. 3 deploy-time issues in v1.3.3.
