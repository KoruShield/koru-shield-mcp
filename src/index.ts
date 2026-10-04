#!/usr/bin/env node
/**
 * Koru Shield MCP Server
 *
 * Exposes Koru Shield DNS filtering as MCP tools so AI assistants
 * (Claude, ChatGPT, Cursor, VS Code, ...) can manage protection
 * through natural language: block domains, check policies,
 * review blocked queries, manage schedules, and more.
 *
 * Auth: set KORU_SHIELD_API_KEY (create one in the dashboard at
 * https://my.korushield.com under API keys). For the HTTP transport,
 * pass it as the Authorization: Bearer header instead.
 *
 * Env:
 *   KORU_SHIELD_API_KEY - your Koru Shield API key (stdio transport)
 *   KORU_SHIELD_API_URL - API base URL (default https://my.korushield.com/api)
 *   PORT                - HTTP transport port (default 3000)
 *   MCP_TRANSPORT       - "stdio" (default) or "http"
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import express from "express";
import rateLimit from "express-rate-limit";
import { createHash } from "node:crypto";
import { KoruClient, KoruApiError } from "./koru-client.js";

const VERSION = "1.0.0";

function getClient(apiKey?: string): KoruClient {
  const key = apiKey || process.env.KORU_SHIELD_API_KEY;
  if (!key) {
    throw new Error(
      "Missing Koru Shield API key. Set KORU_SHIELD_API_KEY or pass Authorization: Bearer <key>."
    );
  }
  return new KoruClient({ apiKey: key });
}

type ToolResult =
  | { content: { type: "text"; text: string }[] }
  | { content: { type: "text"; text: string }[]; isError: true };

function toolError(err: unknown): ToolResult {
  if (err instanceof KoruApiError) {
    return {
      content: [{ type: "text", text: `Koru Shield API error (${err.status}). Reference: ${err.correlationId}. Ask the user to report this reference if the problem persists.` }],
      isError: true,
    };
  }
  if (err instanceof DOMException && err.name === "AbortError") {
    return { content: [{ type: "text", text: "Error: request to the Koru Shield API timed out after 30s; try again." }], isError: true };
  }
  const msg = err instanceof Error ? err.message : String(err);
  return { content: [{ type: "text", text: `Error: ${msg}` }], isError: true };
}

function ok(data: unknown): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
}

const IdSchema = z.string().regex(/^[A-Za-z0-9_-]+$/).describe("ID (letters, digits, underscore, hyphen only)");
const ProfileId = IdSchema.describe("Profile ID (use list_profiles to discover IDs)");
const encodePath = (s: string) => encodeURIComponent(s);
const DomainSchema = z.string().trim().regex(/^(?=.{1,253}$)(([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/).describe("Domain hostname, e.g. example.com");

export function createServer(apiKey?: string): McpServer {
  const server = new McpServer({ name: "koru-shield", version: VERSION });

  const run = async (fn: () => Promise<ToolResult>): Promise<ToolResult> => {
    try { return await fn(); } catch (e) { return toolError(e); }
  };

  // ---------- Profiles ----------
  server.registerTool("list_profiles", {
    description: "List all DNS protection profiles on the account (e.g. Kids, Work, IoT).",
  }, async () => run(async () => ok(await getClient(apiKey).get("/v1/profiles"))));

  server.registerTool("get_profile", {
    description: "Get details of a single profile.",
    inputSchema: { profile_id: ProfileId },
  }, async ({ profile_id }) => run(async () => ok(await getClient(apiKey).get(`/v1/profiles/${encodePath(profile_id)}`))));

  // ---------- Rules ----------
  server.registerTool("list_rules", {
    description: "List custom allow/deny rules for a profile.",
    inputSchema: { profile_id: ProfileId },
  }, async ({ profile_id }) => run(async () => ok(await getClient(apiKey).get(`/v1/profiles/${encodePath(profile_id)}/rules`))));

  server.registerTool("create_rule", {
    description: "Create a custom allow or deny rule for a domain on a profile. Use kind=deny to block a domain, kind=allow to explicitly permit it.",
    inputSchema: {
      profile_id: ProfileId,
      kind: z.enum(["allow", "deny"]).describe("allow to permit, deny to block"),
      domain: DomainSchema.describe("Domain to match, e.g. tiktok.com (matches subdomains)"),
      note: z.string().optional().describe("Human-readable note for why this rule exists"),
    },
  }, async ({ profile_id, kind, domain, note }) => run(async () =>
    ok(await getClient(apiKey).post(`/v1/profiles/${encodePath(profile_id)}/rules`, { kind, domain, note }))));

  server.registerTool("delete_rule", {
    description: "Delete a custom rule from a profile. Destructive: the rule stops applying immediately.",
    inputSchema: {
      profile_id: ProfileId,
      rule_id: IdSchema.describe("Rule ID (use list_rules to discover IDs)"),
    },
  }, async ({ profile_id, rule_id }) => run(async () => {
    await getClient(apiKey).delete(`/v1/profiles/${encodePath(profile_id)}/rules/${encodePath(rule_id)}`);
    return ok({ deleted: rule_id });
  }));

  // ---------- Filter categories ----------
  server.registerTool("list_filter_categories", {
    description: "List filter categories (adult content, gambling, social media, etc.) and whether each is enabled on a profile.",
    inputSchema: { profile_id: ProfileId },
  }, async ({ profile_id }) => run(async () =>
    ok(await getClient(apiKey).get(`/v1/profiles/${encodePath(profile_id)}/filter-categories`))));

  server.registerTool("set_filter_category", {
    description: "Enable or disable a filter category on a profile.",
    inputSchema: {
      profile_id: ProfileId,
      slug: z.string().describe("Category slug, e.g. adult, gambling, social-media (see list_filter_categories)"),
      enabled: z.boolean().describe("true to enable blocking, false to disable"),
    },
  }, async ({ profile_id, slug, enabled }) => run(async () =>
    ok(await getClient(apiKey).post(`/v1/profiles/${encodePath(profile_id)}/filter-categories`, { slug, enabled }))));

  // ---------- Policy simulation ----------
  server.registerTool("simulate_policy", {
    description: "Check what the profile policy would do for a domain right now: allowed, blocked, and why. Does not change anything.",
    inputSchema: {
      profile_id: ProfileId,
      domain: DomainSchema.describe("Domain to test, e.g. example.com"),
    },
  }, async ({ profile_id, domain }) => run(async () =>
    ok(await getClient(apiKey).post(`/v1/profiles/${encodePath(profile_id)}/simulate`, { domain }))));

  // ---------- Logs ----------
  server.registerTool("get_logs", {
    description: "Get recent DNS query logs: what was queried, allowed or blocked, and when. Useful for reviewing activity or investigating a block.",
    inputSchema: {
      profile_id: IdSchema.optional().describe("Filter to one profile (omit for all)"),
      action: z.enum(["allowed", "blocked", "refused", "error", "rate_limited"]).optional().describe("Filter by action"),
      limit: z.number().int().positive().max(100).default(25).describe("Max entries to return"),
    },
  }, async ({ profile_id, action, limit }) => run(async () =>
    ok(await getClient(apiKey).get("/v1/logs", { profile_id, action, limit: String(limit) }))));

  // ---------- Analytics ----------
  server.registerTool("analytics_summary", {
    description: "Summary of DNS activity: total queries, blocked vs allowed counts, blocked percentage, IPv4/IPv6, encrypted queries.",
    inputSchema: {
      profile_id: IdSchema.optional().describe("Filter to one profile (omit for account-wide)"),
      from: z.string().optional().describe("Start of window, RFC3339 timestamp (default: last 24h)"),
      to: z.string().optional().describe("End of window, RFC3339 timestamp"),
    },
  }, async ({ profile_id, from, to }) => run(async () =>
    ok(await getClient(apiKey).get("/v1/analytics/summary", { profile_id, from, to }))));

  // ---------- Schedules ----------
  server.registerTool("list_schedules", {
    description: "List time-based schedules on a profile (e.g. bedtime 21:00-07:00 on weekdays).",
    inputSchema: { profile_id: ProfileId },
  }, async ({ profile_id }) => run(async () =>
    ok(await getClient(apiKey).get(`/v1/profiles/${encodePath(profile_id)}/schedules`))));

  server.registerTool("create_schedule", {
    description: "Create a time-based schedule on a profile. Rules and filter categories can reference schedules to apply only during the window.",
    inputSchema: {
      profile_id: ProfileId,
      name: z.string().describe("Schedule name, e.g. Bedtime"),
      timezone: z.string().refine((tz) => { try { Intl.DateTimeFormat(undefined, { timeZone: tz }); return true; } catch { return false; } }, { message: "Must be a valid IANA timezone, e.g. America/Chicago" }).describe("IANA timezone, e.g. America/Chicago"),
      days: z.array(z.enum(["mon", "tue", "wed", "thu", "fri", "sat", "sun"])).describe("Days of week, e.g. [\"mon\",\"tue\",\"wed\",\"thu\",\"fri\"]"),
      start: z.string().regex(/^([01][0-9]|2[0-3]):[0-5][0-9]$/).describe("HH:MM 24h, e.g. 21:00"),
      end: z.string().regex(/^([01][0-9]|2[0-3]):[0-5][0-9]$/).describe("HH:MM 24h, e.g. 21:00"),
    },
  }, async ({ profile_id, name, timezone, days, start, end }) => run(async () =>
    ok(await getClient(apiKey).post(`/v1/profiles/${encodePath(profile_id)}/schedules`, { name, timezone, days, start, end }))));

  server.registerTool("delete_schedule", {
    description: "Delete a schedule from a profile. Destructive: rules referencing it lose their time window.",
    inputSchema: {
      profile_id: ProfileId,
      schedule_id: IdSchema.describe("Schedule ID (use list_schedules to discover IDs)"),
    },
  }, async ({ profile_id, schedule_id }) => run(async () => {
    await getClient(apiKey).delete(`/v1/profiles/${encodePath(profile_id)}/schedules/${encodePath(schedule_id)}`);
    return ok({ deleted: schedule_id });
  }));

  // ---------- Devices ----------
  server.registerTool("list_devices", {
    description: "List devices enrolled on a profile and their protection status.",
    inputSchema: { profile_id: ProfileId },
  }, async ({ profile_id }) => run(async () =>
    ok(await getClient(apiKey).get(`/v1/profiles/${encodePath(profile_id)}/devices`))));

  // ---------- Account ----------
  server.registerTool("get_entitlements", {
    description: "Get the account plan, limits (max rules, profiles, devices), and current usage.",
  }, async () => run(async () => {
    const client = getClient(apiKey);
    const [entitlements, usage] = await Promise.all([
      client.get("/v1/account/entitlements"),
      client.get("/v1/account/usage"),
    ]);
    return ok({ entitlements, usage });
  }));

  server.registerTool("get_referral_code", {
    description: "Get the account referral code and link for the give-a-month-get-a-month program.",
  }, async () => run(async () => ok(await getClient(apiKey).get("/referrals/code"))));

  return server;
}

async function main() {
  const transport = (process.env.MCP_TRANSPORT || "stdio").toLowerCase();

  if (transport === "http") {
    const app = express();
    app.use(express.json());
    const port = parseInt(process.env.PORT || "3000", 10);

    const ipLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false });
    const credentialLimiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 600,
      standardHeaders: true,
      legacyHeaders: false,
      keyGenerator: (req) => {
        const credential = parseBearer(req.headers.authorization) as string;
        return createHash("sha256").update(credential).digest("hex");
      },
    });

    app.post("/mcp", ipLimiter, async (req, res, next) => {
      const apiKey = parseBearer(req.headers.authorization);
      if (!apiKey) {
        return res.status(401).json({ error: "Missing or invalid Authorization header. Pass your Koru Shield API key as: Authorization: Bearer <key>." });
      }
      credentialLimiter(req, res, async (err) => {
        if (err) return next(err);
        try {
          const server = createServer(apiKey);
          const httpTransport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
          res.on("close", () => { httpTransport.close(); });
          await server.connect(httpTransport);
          await httpTransport.handleRequest(req, res, req.body);
        } catch (err) {
          next(err);
        }
      });
    });

    app.get("/healthz", (_req, res) => res.json({ status: "ok", service: "koru-shield-mcp", version: VERSION }));

    app.listen(port, () => {
      console.log(`koru-shield-mcp ${VERSION} listening on :${port} (streamable HTTP at /mcp)`);
    });
  } else {
    const server = createServer();
    const stdioTransport = new StdioServerTransport();
    await server.connect(stdioTransport);
    console.error(`koru-shield-mcp ${VERSION} running on stdio`);
  }
}

function parseBearer(header: string | undefined): string | undefined {
  const match = header?.trim().match(/^Bearer\s+(.+)$/i);
  const credential = match?.[1]?.trim();
  return credential || undefined;
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
