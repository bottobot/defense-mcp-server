/**
 * tool-annotations.ts — Centralized MCP ToolAnnotations for all tools.
 *
 * Annotations are auto-injected by the tool-wrapper proxy at registration
 * time, so individual tool files do not need modification.
 *
 * @module tool-annotations
 */

import type { ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";

export const TOOL_ANNOTATIONS: Record<string, ToolAnnotations> = {
  // Read-only tools (ALL actions are non-modifying)
  secrets:          { readOnlyHint: true,  destructiveHint: false, idempotentHint: true,  openWorldHint: false },
  cloud_security:   { readOnlyHint: true,  destructiveHint: false, idempotentHint: true,  openWorldHint: true  },
  process_security: { readOnlyHint: true,  destructiveHint: false, idempotentHint: true,  openWorldHint: false },
  api_security:     { readOnlyHint: true,  destructiveHint: false, idempotentHint: true,  openWorldHint: true  },

  // Destructive tools (at least one state-modifying action)
  firewall:            { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  harden_kernel:       { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  harden_host:         { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  access_control:      { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  compliance:          { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  integrity:           { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  log_management:      { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  malware:             { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  container_docker:    { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  container_isolation: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  ebpf:                { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  crypto:              { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  network_defense:     { readOnlyHint: false, destructiveHint: false, idempotentHint: true,  openWorldHint: false },
  patch:               { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  incident_response:   { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  defense_mgmt:        { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  sudo_session:        { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  backup:              { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  supply_chain:        { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  zero_trust:          { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  honeypot_manage:     { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  dns_security:        { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  threat_intel:        { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  vuln_manage:         { readOnlyHint: false, destructiveHint: false, idempotentHint: true,  openWorldHint: true  },
  waf_manage:          { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  wireless_security:   { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  app_harden:          { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
};

export function getToolAnnotations(toolName: string): ToolAnnotations | undefined {
  return TOOL_ANNOTATIONS[toolName];
}

export function isReadOnlyTool(toolName: string): boolean {
  return TOOL_ANNOTATIONS[toolName]?.readOnlyHint === true;
}
