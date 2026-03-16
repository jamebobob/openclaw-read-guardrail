// read-guardrail plugin for OpenClaw v1.3.4
// Enforces workspace-only read access for the social agent.
// The upstream workspaceOnly config enforces write/edit but NOT read.
// This plugin fills that gap with a before_tool_call hook.
//
// Covers: read, image, pdf, and diffs tools.
//   - read: primary file reading tool (workspaceOnly doesn't enforce)
//   - image: vision tool (GHSA-q6qf-4p5j-r25g proved bypass)
//   - pdf: document analyzer (same file-loading pattern as image)
//
// Design: allowlist, not denylist. Social agent can read:
//   - Its own workspace (~/.openclaw/workspace-social/)
//   - /tmp/ (needed for transient operations)
// Everything else is blocked at the code level.
//
// Main agent is unrestricted. This plugin only gates the social agent.
//
// AUDIT HISTORY:
//   v1.0.0: Initial draft.
//   v1.1.0: Three audit passes found 3 blockers, 4 warnings, 2 new tools.
//     B1: Symlink target entries in allowlist opened main workspace to
//         direct reads. Removed. Social reads symlinked files via its
//         own workspace-social/ prefix. Hook sees pre-resolution paths.
//     B2: Dead code in isAllowed (exact match after startsWith). Removed.
//     B3: Missing configSchema in openclaw.plugin.json. Gateway would
//         reject any config keys (socialAgentId, allowedPaths) and refuse
//         to start. Fixed in manifest.
//     W1: Null byte handling added to normalizePath.
//     W2: Relative path handling documented (blocks correctly).
//     W3: workspace/ vs workspace-social/ prefix collision documented.
//         ALWAYS_BLOCKED has /home/walle/.openclaw/workspace/ which does
//         NOT match /home/walle/.openclaw/workspace-social/ because
//         startsWith("workspace/") !== startsWith("workspace-social/").
//         Safe, but close enough to warrant this comment.
//     W4: image and pdf tool parameter names were WRONG in v1.1.0.
//         v1.1.0 extracted params.path || params.file_path. Actual params:
//         image uses params.image, pdf uses params.pdf/params.pdfs.
//         v1.1.0 was a SILENT BYPASS for both tools. FIXED in v1.2.0:
//         extraction chain now includes all verified param names, plus
//         fail-closed for any remaining unknown params.
//     N3: image tool added to guarded tools (same path param pattern,
//         proven bypass vector per GHSA-q6qf-4p5j-r25g). Param: .image.
//     N4: pdf tool added to guarded tools (same file-loading pattern
//         as image, neither in social's explicit deny list, could leak
//         through #42165 tools.profile bug). Params: .pdf, .pdfs[].
//   v1.2.0: Fresh Opus audit verified actual tool param names from docs:
//     B4-FIX: image tool uses params.image, NOT params.path. The v1.1.0
//         extraction chain missed it entirely. Without fail-closed (v1.1.0),
//         this was a silent bypass. Fixed: extraction now includes .image.
//     B5-FIX: pdf tool uses params.pdf (single) and params.pdfs (array),
//         NOT params.path. Same bypass as B4. Fixed: extraction now includes
//         .pdf and iterates .pdfs[]. Also handles URL filtering (http/https
//         paths skip workspace validation since they're network fetches).
//     W4-FIX: Empty rawPath now fails CLOSED for social agent. Catches any
//         future tools with unknown param names.
//     N5: diffs plugin tool added to GUARDED_TOOLS. Diffs doesn't actually
//         read files (takes text content as before/after/patch), but path
//         param exists as display label. Defense in depth.
//     W5-NOTED: message tool media attachment bypass. Social's allowed
//         message tool can send files as media attachments, bypassing
//         read guardrail. Needs mediaLocalRoots verification on deploy.
//         Not fixable here without knowing message param structure.
//     MULTI-PATH: pdf tool's pdfs[] param can contain multiple paths.
//         Validation now checks ALL paths; any failure blocks the call.
//   v1.3.0: Fourth audit pass, GitHub source verification:
//     B6-FIX: Relative path false positive. Model sends "AGENTS.md",
//         normalizePath produced "/AGENTS.md" (not in allowlist, blocked).
//         But OpenClaw resolves it as workspace-social/AGENTS.md. Fixed:
//         normalizePath now accepts workspaceRoot param, prepends it to
//         relative paths before normalization. Traversals like
//         "../workspace/.env" still resolve correctly and get blocked.
//     W6-FIX: file:// URI handling. URL filter only caught http/https.
//         file:///path could pass through. Fixed: normalizePath strips
//         file:// scheme, validates underlying path. Also added data:
//         to the remote URL filter.
//     W7-FIX: ${HOME} variant. Models occasionally use curly-brace form.
//         Added ${HOME}/ expansion alongside $HOME/.
//     N6: Confirmed via #5943 that hook receives post-validation params
//         (file_path already aliased to path). file_path extraction is
//         dead code but harmless safety net. Updated comments.
//     VALIDATED: ClawBands (SeyZ/clawbands) uses identical before_tool_call
//         + tool-interceptor.ts pattern. Equilibrium Guard (rizqcon) also
//         uses this pattern. agent-guardrails (@aporthq) another impl.
//   v1.3.1: Fifth audit pass, exhaustive input tracing:
//     W8-FIX: $HOME boundary. startsWith("$HOME") matched $HOME_EXTRA.
//         Tightened to exact: p === "$HOME" || p.startsWith("$HOME/").
//         Same fix for ${HOME}. (False positive, not a bypass, but wrong.)
//     W9-FIX: URI scheme filter. Only http/https/data: were filtered as
//         remote. ftp://, s3://, etc. would pass through and normalizePath
//         would mangle them into nonsense blocked-by-allowlist paths.
//         Fixed: regex [a-zA-Z][a-zA-Z0-9+.-]*:// catches any scheme.
//         file:// is explicitly separated and passed to normalizePath for
//         scheme stripping + local path validation.
//     W10-FIX: $HOME expansion math. Old code used slice(5) + replace
//         which produced double-slash for $HOME/foo or missing slash for
//         bare $HOME. Simplified: slice(5) preserves the / naturally
//         since "$HOME/" slice(5) = "/", and "$HOME" slice(5) = "".
//         Now uses HOME_DIR + p.slice(5) which is correct for both.
//     TRACE: Manually traced 15 input patterns through normalizePath.
//   v1.3.2: Sixth audit pass (Claude Code, mechanical verification):
//     W11-FIX: file:// authority bypass. file://localhost/etc/passwd was
//         normalized as relative path "localhost/etc/passwd" (workspace
//         prepended, appeared allowed). RFC 8089 file URIs can have an
//         authority component: file://host/path. Fixed: after stripping
//         file://, if result doesn't start with "/", strip authority up to
//         first "/" (or set empty if no "/" found). file:///path (empty
//         authority) unaffected. file://AGENTS.md (no path) now correctly
//         returns "" and gets blocked.
//   v1.3.3: Deploy cleanup (post-deploy on walle):
//     Removed ALLOWED_KEYS validation loop. api.config is the full global
//     OpenClaw config, not plugin-scoped config. The loop warned on every
//     top-level key (meta, gateway, channels, etc.). configSchema validates
//     at gateway level. Updated DEPLOYMENT docs with manifest id and
//     plugins.allow requirements learned during deploy.
//   v1.3.4: GitHub publication prep:
//     Replaced hardcoded /home/walle/ with HOME_DIR constant derived from
//     process.env.HOME. Plugin is now portable to any home directory
//     without source edits for path expansion (~, $HOME, ${HOME}).
//     DEFAULT_ALLOWED_PATHS and ALWAYS_BLOCKED also use HOME_DIR.
//     Fixed audit history ordering (v1.3.1 was after v1.3.3).
//
// VALIDATED BY: EasyClaw (gaoyangz77/easyclaw) uses identical pattern:
//   before_tool_call hook intercepting read/write/edit/image/apply_patch
//   with path validation. No vendor source modifications needed.
//   ClawBands (SeyZ/clawbands): tool-interceptor.ts, same hook pattern.
//   Equilibrium Guard (rizqcon): zero-trust security layer, same hook.
//   agent-guardrails (@aporthq): allowlist + 40 blocked patterns.
//   GitHub #12202 requests per-agent file ACLs natively (not shipped).
//   GitHub #28869 requests tools.fs.allowPaths (not shipped).
//   GitHub #5943 confirms hook receives post-validation params.
//
// KNOWN LIMITATIONS:
//   - Hook sees the path the model sends, not resolved symlinks.
//     Social reads symlinked files via workspace-social/ prefix.
//     If OpenClaw ever resolves symlinks before firing the hook,
//     this would break. Test after any OpenClaw update.
//     CDNsun blog reported OpenClaw ignoring some symlinked files,
//     reinforcing this uncertainty.
//   - exec tool can read files via cat/less/head etc. This is already
//     mitigated by exec-approvals.json (social: python3 only).
//   - Fail-open for unknown agents. Only social is restricted. A future
//     third agent would have unrestricted reads. Correct for current
//     two-agent setup.
//   - image tool uses params.image, pdf tool uses params.pdf/pdfs.
//     These are now extracted correctly (v1.2.0). Unknown future tools
//     still fail closed if no path can be extracted.
//   - Relative paths resolved against social workspace root (v1.3.0).
//     Model sends "AGENTS.md" -> prepends workspace root -> validated.
//     Traversals like "../workspace/.env" still caught by normalization.
//   - file:// URIs stripped to underlying path (v1.3.0). data: URIs
//     filtered as remote. pdf tool rejects non-http schemes natively,
//     but this is defense in depth.
//   - pdf tool's pdfs[] can contain URLs (http/https/data:). These are
//     filtered out before workspace validation (remote fetches).
//   - message tool can send files as media attachments. This plugin does
//     not intercept the message tool. Verify mediaLocalRoots is scoped
//     to workspace-social/ for the social agent on deploy.
//
// PLUGIN INTERACTION:
//   - privacy-guardrail runs at priority 100 (higher = first).
//   - read-guardrail runs at priority 99.
//   - No conflict: privacy-guardrail only intercepts write/edit/exec/bash.
//   - Hook runner continues to next plugin when a hook returns undefined.
//
// DEPLOYMENT:
//   1. Copy to ~/.openclaw/extensions/read-guardrail/
//   2. Manifest MUST have "id" field (not just "name"). Gateway refuses
//      to start without it: "plugin manifest requires id".
//   3. Add to plugins.entries:
//      jq '.plugins.entries."read-guardrail" = {"enabled": true}' ...
//   4. Add to plugins.allow (required since v2026.3.12, GHSA-99qw-6mr3-36qr):
//      jq '.plugins.allow += ["read-guardrail"]' ...
//   5. openclaw doctor (may fail with dist/entry.js error, bug #10. OK.)
//   6. Restart: sudo systemctl restart openclaw
//   7. Verify: journalctl -u openclaw --since "1 min ago" | grep read-guardrail
//      Look for "Active v1.3.4" line. No "plugin not found" errors.
//   8. Test: message social agent in group, ask it to read openclaw.json.
//      Should get "Access denied" in the response.
//   9. Test: ask social agent to read SOUL.md. Should succeed (symlink safe).
//
// PRE-DEPLOY VERIFICATION (run on walle):
//   1. Symlink test: Send social agent a message asking it to read SOUL.md.
//      If blocked, the hook sees resolved symlink targets (bad). If allowed,
//      the hook sees workspace-social/SOUL.md (good).
//   2. Privacy test: Ask social to read ~/.openclaw/openclaw.json.
//      Must get "Access denied".
//   3. Message tool: Verify mediaLocalRoots scoping for social agent:
//      grep -n "mediaLocalRoots\|mediaLocal" ~/.npm-global/lib/node_modules/openclaw/dist/*.js | head -10
//   Param names verified from docs.openclaw.ai/tools (March 15 2026):
//     read:  params.path (canonical)
//     image: params.image (path or URL)
//     pdf:   params.pdf (path or URL), params.pdfs (array of paths/URLs)
//     diffs: params.path (display label, not a file read)

const PLUGIN_VERSION = "1.3.4";

const DEFAULT_SOCIAL_AGENT_ID = "social";

// Home directory for path expansion (~, $HOME, ${HOME}).
// Uses process.env.HOME (Linux/macOS) or USERPROFILE (Windows).
// Plugins run in-process with the gateway, so process.env is available.
const HOME_DIR = process.env.HOME || process.env.USERPROFILE || "/home/user";

// Tools that accept file path parameters and must be guarded.
// read:  params.path (canonical; file_path aliased to path pre-hook per #5943)
// image: params.image (path or URL, verified docs.openclaw.ai/tools)
//        (GHSA-q6qf-4p5j-r25g proved this bypass)
// pdf:   params.pdf (single path/URL), params.pdfs (array of paths/URLs)
//        (verified docs.openclaw.ai/tools/pdf)
// diffs: params.path (display label only, not a file read). Optional plugin,
//        read-only diff viewer + PNG/PDF renderer. Defense in depth.
const GUARDED_TOOLS = new Set(["read", "image", "pdf", "diffs"]);

// Paths the social agent is allowed to read.
// Uses startsWith after path normalization.
// NOTE: No main workspace paths here. Social reads shared files
// (SOUL.md, IDENTITY.md, USER.md) via symlinks in workspace-social/.
// The hook sees the pre-resolution path (workspace-social/SOUL.md),
// not the symlink target (workspace/SOUL.md).
const DEFAULT_ALLOWED_PATHS = [
  HOME_DIR + "/.openclaw/workspace-social/",
  "/tmp/",
];

// Paths that must NEVER be readable by social, even if they somehow
// fall within an allowed prefix. Defense in depth.
//
// NOTE on workspace/ vs workspace-social/:
// HOME_DIR + "/.openclaw/workspace/" is blocked here. This does NOT
// accidentally block workspace-social/ because
// startsWith("workspace/") !== startsWith("workspace-social/").
// The trailing slash in the blocked entry is critical.
const ALWAYS_BLOCKED = [
  HOME_DIR + "/.openclaw/openclaw.json",
  HOME_DIR + "/.openclaw/.env",
  HOME_DIR + "/.openclaw/exec-approvals.json",
  HOME_DIR + "/.openclaw/credentials/",
  HOME_DIR + "/.openclaw/agents/main/",
  HOME_DIR + "/.openclaw/workspace/",
];

function normalizePath(inputPath, workspaceRoot) {
  if (!inputPath || typeof inputPath !== "string") return "";
  let p = inputPath.trim();
  // Strip null bytes (path traversal vector: OS truncates at \0)
  p = p.replace(/\0/g, "");
  // Strip file:// URI scheme. The underlying path must still pass validation.
  // file:///foo -> /foo (absolute). file://host/foo -> /foo (authority stripped).
  // file://foo -> "" (no path component, will be blocked).
  if (p.startsWith("file://")) {
    p = p.slice(7);
    // RFC 8089: file://authority/path. If authority is present (no leading /),
    // strip it. file:///path has empty authority and starts with /.
    if (p && !p.startsWith("/")) {
      const slashIdx = p.indexOf("/");
      p = slashIdx === -1 ? "" : p.slice(slashIdx);
    }
  }
  // Expand ~ to home directory. Must be exactly ~ or ~/...
  if (p === "~" || p.startsWith("~/")) {
    p = HOME_DIR + "/" + p.slice(p === "~" ? 1 : 2);
  }
  // Expand $HOME. Boundary: must be exactly $HOME or $HOME/...
  // Without boundary check, $HOME_EXTRA would false-match.
  if (p === "$HOME" || p.startsWith("$HOME/")) {
    p = HOME_DIR + p.slice(5);
  }
  // Expand ${HOME}. Same boundary logic.
  if (p === "${HOME}" || p.startsWith("${HOME}/")) {
    p = HOME_DIR + p.slice(7);
  }
  // Resolve relative paths against workspace root.
  // The before_tool_call hook sees raw model params. OpenClaw resolves
  // relative paths against the agent's workspace AFTER the hook. Without
  // this, relative paths like "AGENTS.md" normalize to "/AGENTS.md" and
  // get falsely blocked even though they refer to workspace-social/AGENTS.md.
  if (workspaceRoot && !p.startsWith("/")) {
    p = workspaceRoot + p;
  }
  // Resolve .. traversals and normalize
  const parts = p.split("/");
  const resolved = [];
  for (const part of parts) {
    if (part === "..") {
      resolved.pop();
    } else if (part !== "." && part !== "") {
      resolved.push(part);
    }
  }
  return "/" + resolved.join("/");
}

function isAllowed(normalizedPath, allowedPaths) {
  for (const allowed of allowedPaths) {
    if (normalizedPath.startsWith(allowed)) return true;
  }
  return false;
}

function isAlwaysBlocked(normalizedPath) {
  for (const blocked of ALWAYS_BLOCKED) {
    if (normalizedPath.startsWith(blocked)) return true;
  }
  return false;
}

export default function register(api) {
  // api.config is the full global OpenClaw config, not plugin-scoped.
  // cfg.socialAgentId and cfg.allowedPaths will always be undefined here
  // (they're not top-level openclaw.json keys), so DEFAULT_ values apply.
  // This is correct for Eve's setup. If plugin-scoped config is ever needed,
  // read from api.config?.plugins?.entries?.["read-guardrail"]?.config instead.
  // configSchema.additionalProperties validates plugin config at gateway level.
  const cfg = api.config || {};

  const socialAgentId = cfg.socialAgentId || DEFAULT_SOCIAL_AGENT_ID;
  const allowedPaths = cfg.allowedPaths || DEFAULT_ALLOWED_PATHS;
  // Workspace root for resolving relative paths the model might send.
  // The before_tool_call hook fires BEFORE the tool resolves paths against
  // the workspace. Without this, "AGENTS.md" -> "/AGENTS.md" -> blocked.
  const socialWorkspaceRoot = allowedPaths.find((p) => p.includes("workspace")) || allowedPaths[0] || "/";

  api.logger.info(
    `[read-guardrail] Active v${PLUGIN_VERSION}. ` +
    `Guarding agent="${socialAgentId}", ` +
    `tools=[${[...GUARDED_TOOLS].join(",")}], ` +
    `${allowedPaths.length} allowed paths, ` +
    `${ALWAYS_BLOCKED.length} always-blocked paths, ` +
    `workspaceRoot="${socialWorkspaceRoot}".`
  );

  api.on(
    "before_tool_call",
    async (event, ctx) => {
      // Only gate guarded tools (read + image + pdf + diffs)
      if (!GUARDED_TOOLS.has(event.toolName)) return;

      // Only gate the social agent
      const agentId = (ctx as any)?.agentId;
      if (!agentId || agentId !== socialAgentId) return;

      // Extract file paths from tool params.
      // NOTE: params are post-validation (alias-resolved). file_path is
      // already mapped to path by OpenClaw before the hook fires (#5943).
      // We still extract file_path as a safety net.
      //
      // Param names verified from docs.openclaw.ai/tools (March 15 2026):
      //   read:  params.path (canonical; file_path aliased to path pre-hook)
      //   image: params.image (required, path or URL)
      //   pdf:   params.pdf (single path/URL) and/or params.pdfs (array)
      //   diffs: params.path (display label only, not a file read)
      const rawPaths = [];
      if (event.params?.path) rawPaths.push(event.params.path);
      if (event.params?.file_path) rawPaths.push(event.params.file_path);
      if (event.params?.image) rawPaths.push(event.params.image);
      if (event.params?.pdf) rawPaths.push(event.params.pdf);
      if (Array.isArray(event.params?.pdfs)) {
        for (const p of event.params.pdfs) {
          if (typeof p === "string") rawPaths.push(p);
        }
      }

      // Filter out remote URIs. These are network fetches, not local reads.
      // Match any scheme:// pattern (http, https, ftp, s3, etc.) plus data:.
      // file:// is NOT filtered here; normalizePath strips it and validates
      // the underlying local path.
      const URI_SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//;
      const localPaths = rawPaths.filter(
        (p) => typeof p === "string" &&
          !URI_SCHEME_RE.test(p) &&
          !p.startsWith("data:") &&
          !p.startsWith("file://")
      );
      // file:// paths are local. They pass through here and normalizePath
      // strips the scheme before validation.
      const fileSchemePaths = rawPaths.filter(
        (p) => typeof p === "string" && p.startsWith("file://")
      );
      const allLocalPaths = [...localPaths, ...fileSchemePaths];

      if (allLocalPaths.length === 0 && rawPaths.length > 0) {
        // All paths are remote URIs. No local file access. Allow.
        return;
      }

      if (allLocalPaths.length === 0) {
        // No path extracted at all. Fail CLOSED.
        api.logger.warn(
          `[read-guardrail] BLOCKED (no path extracted, fail-closed): ` +
          `agent=${agentId} tool=${event.toolName} params=${JSON.stringify(event.params)}`
        );
        return {
          block: true,
          blockReason:
            `[read-guardrail] Access denied. ` +
            `Could not extract file path from ${event.toolName} tool call. ` +
            `The social agent is restricted to its own workspace.`,
        };
      }

      // Validate EVERY local path. If any fails, block the entire call.
      for (const rawPath of allLocalPaths) {
        const normalizedPath = normalizePath(rawPath, socialWorkspaceRoot);

        if (!normalizedPath || normalizedPath === "/") {
          api.logger.warn(
            `[read-guardrail] BLOCKED (empty/root after normalize): ` +
            `agent=${agentId} tool=${event.toolName} rawPath=${rawPath}`
          );
          return {
            block: true,
            blockReason:
              `[read-guardrail] Access denied. Invalid path.`,
          };
        }

        if (isAlwaysBlocked(normalizedPath)) {
          api.logger.warn(
            `[read-guardrail] BLOCKED (always-blocked): ` +
            `agent=${agentId} tool=${event.toolName} path=${rawPath} normalized=${normalizedPath}`
          );
          return {
            block: true,
            blockReason:
              `[read-guardrail] Access denied. ` +
              `The ${event.toolName} tool cannot access this path from the social agent.`,
          };
        }

        if (!isAllowed(normalizedPath, allowedPaths)) {
          api.logger.warn(
            `[read-guardrail] BLOCKED (not in allowlist): ` +
            `agent=${agentId} tool=${event.toolName} path=${rawPath} normalized=${normalizedPath}`
          );
          return {
            block: true,
            blockReason:
              `[read-guardrail] Access denied. ` +
              `The social agent can only read files within its own workspace.`,
          };
        }
      }

      // All paths allowed
      api.logger.debug(
        `[read-guardrail] ALLOWED: agent=${agentId} tool=${event.toolName} paths=${allLocalPaths.length}`
      );
    },
    { name: "read-guardrail-hook", priority: 99 }
  );
}
