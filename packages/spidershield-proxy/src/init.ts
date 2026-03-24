/**
 * spidershield-proxy init / uninstall
 *
 * Auto-discovers MCP server configurations and injects/removes the proxy.
 *
 * Supported configs:
 *   - Claude Desktop: ~/Library/Application Support/Claude/claude_desktop_config.json (Mac)
 *                     %APPDATA%/Claude/claude_desktop_config.json (Windows)
 *   - Cursor:         ~/.cursor/mcp.json
 *   - Windsurf:       ~/.windsurf/mcp.json
 *   - Claude Code:    .claude/settings.json (project) or ~/.claude/settings.json (global)
 */

import { readFileSync, writeFileSync, copyFileSync, existsSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";

// ── Config file locations ─────────────────────────────────────────

type ConfigLocation = {
  name: string;
  paths: string[];
  type: "mcp-servers" | "claude-code-hooks";
};

function getConfigLocations(): ConfigLocation[] {
  const home = homedir();
  const isWin = platform() === "win32";

  const claudeDesktopDir = isWin
    ? join(process.env.APPDATA || join(home, "AppData", "Roaming"), "Claude")
    : join(home, "Library", "Application Support", "Claude");

  return [
    {
      name: "Claude Desktop",
      paths: [join(claudeDesktopDir, "claude_desktop_config.json")],
      type: "mcp-servers",
    },
    {
      name: "Cursor",
      paths: [join(home, ".cursor", "mcp.json")],
      type: "mcp-servers",
    },
    {
      name: "Windsurf",
      paths: [join(home, ".windsurf", "mcp.json")],
      type: "mcp-servers",
    },
    {
      name: "Claude Code (global)",
      paths: [join(home, ".claude", "settings.json")],
      type: "claude-code-hooks",
    },
    {
      name: "Claude Code (project)",
      paths: [join(process.cwd(), ".claude", "settings.json")],
      type: "claude-code-hooks",
    },
  ];
}

// ── Init command ──────────────────────────────────────────────────

export function runInit(): void {
  console.log("\n  SpiderShield Proxy v0.1.0 — init\n");

  const locations = getConfigLocations();
  let totalWrapped = 0;
  let configsModified = 0;

  for (const loc of locations) {
    for (const configPath of loc.paths) {
      if (!existsSync(configPath)) continue;

      try {
        const raw = readFileSync(configPath, "utf-8");
        const config = JSON.parse(raw);

        if (loc.type === "mcp-servers") {
          const result = wrapMcpServers(config, configPath, loc.name);
          totalWrapped += result.wrapped;
          if (result.wrapped > 0) configsModified++;
        } else if (loc.type === "claude-code-hooks") {
          const result = injectHook(config, configPath, loc.name);
          if (result.injected) configsModified++;
        }
      } catch (e) {
        console.log(`  ⚠ ${loc.name}: failed to parse ${configPath}`);
      }
    }
  }

  console.log("");
  if (totalWrapped === 0 && configsModified === 0) {
    console.log("  No MCP configurations found. Nothing to do.");
    console.log("  Supported: Claude Desktop, Cursor, Windsurf, Claude Code\n");
  } else {
    console.log(`  Done! ${totalWrapped} server(s) wrapped, ${configsModified} config(s) modified.`);
    console.log("  Policy: balanced (block malicious, warn risky)");
    console.log("  Audit log: ~/.spidershield/audit/");
    console.log("  Undo: spidershield-proxy uninstall\n");
  }
}

// ── Uninstall command ────────────────────────────────────────────

export function runUninstall(): void {
  console.log("\n  SpiderShield Proxy — uninstall\n");

  const locations = getConfigLocations();
  let restored = 0;

  for (const loc of locations) {
    for (const configPath of loc.paths) {
      const bakPath = configPath + ".spidershield-bak";
      if (!existsSync(bakPath)) continue;

      try {
        copyFileSync(bakPath, configPath);
        console.log(`  ✓ ${loc.name}: restored from backup`);
        restored++;
      } catch {
        console.log(`  ⚠ ${loc.name}: failed to restore`);
      }
    }
  }

  if (restored === 0) {
    console.log("  No backups found. Nothing to restore.\n");
  } else {
    console.log(`\n  Restored ${restored} config(s). SpiderShield proxy removed.\n`);
  }
}

// ── Wrap MCP servers ─────────────────────────────────────────────

function wrapMcpServers(
  config: Record<string, unknown>,
  configPath: string,
  name: string
): { wrapped: number } {
  const servers = config.mcpServers as Record<
    string,
    { command?: string; args?: string[] }
  > | undefined;

  if (!servers || typeof servers !== "object") {
    return { wrapped: 0 };
  }

  let wrapped = 0;

  for (const [serverName, serverConfig] of Object.entries(servers)) {
    if (!serverConfig.command) continue;

    // Skip if already wrapped
    if (
      serverConfig.command === "spidershield-proxy" ||
      serverConfig.command === "npx" &&
      serverConfig.args?.[0] === "spidershield-proxy"
    ) {
      console.log(`  · ${name}/${serverName}: already protected`);
      continue;
    }

    // Wrap: move original command into args after "spidershield-proxy"
    const originalCommand = serverConfig.command;
    const originalArgs = serverConfig.args || [];

    serverConfig.command = "spidershield-proxy";
    serverConfig.args = [originalCommand, ...originalArgs];

    console.log(`  ✓ ${name}/${serverName}: wrapped with SpiderShield proxy`);
    wrapped++;
  }

  if (wrapped > 0) {
    // Backup original
    const bakPath = configPath + ".spidershield-bak";
    if (!existsSync(bakPath)) {
      const originalRaw = readFileSync(configPath, "utf-8");
      writeFileSync(bakPath, originalRaw);
    }
    // Write modified
    writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n");
  }

  return { wrapped };
}

// ── Inject Claude Code hook ──────────────────────────────────────

function injectHook(
  config: Record<string, unknown>,
  configPath: string,
  name: string
): { injected: boolean } {
  // Check if hook already exists
  const hooks = config.hooks as Record<string, unknown[]> | undefined;
  if (hooks?.PreToolUse) {
    const existing = hooks.PreToolUse as Array<{
      hooks?: Array<{ command?: string; url?: string }>;
    }>;
    const alreadyHas = existing.some((entry) =>
      entry.hooks?.some(
        (h) =>
          h.command?.includes("spidershield") ||
          h.url?.includes("spiderrating")
      )
    );
    if (alreadyHas) {
      console.log(`  · ${name}: SpiderShield hook already configured`);
      return { injected: false };
    }
  }

  // Backup
  const bakPath = configPath + ".spidershield-bak";
  if (!existsSync(bakPath)) {
    writeFileSync(bakPath, readFileSync(configPath, "utf-8"));
  }

  // Inject hook
  if (!config.hooks) config.hooks = {};
  const hooksObj = config.hooks as Record<string, unknown[]>;
  if (!hooksObj.PreToolUse) hooksObj.PreToolUse = [];

  (hooksObj.PreToolUse as unknown[]).push({
    matcher: "mcp__.*",
    hooks: [
      {
        type: "http",
        url: "https://spiderrating-api-production.up.railway.app/v1/public/check",
        timeout: 5,
      },
    ],
  });

  writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n");
  console.log(`  ✓ ${name}: SpiderShield PreToolUse hook added`);
  return { injected: true };
}
