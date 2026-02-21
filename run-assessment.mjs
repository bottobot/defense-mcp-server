#!/usr/bin/env node
// MCP Assessment Runner - Calls defense tools via JSON-RPC stdio protocol
import { spawn } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SERVER_PATH = resolve(__dirname, 'build/index.js');

function callMcpTool(toolName, args = {}) {
  return new Promise((resolve, reject) => {
    const proc = spawn('node', [SERVER_PATH], {
      env: { ...process.env, KALI_DEFENSE_DRY_RUN: 'true' },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stdout = '';
    proc.stdout.on('data', (d) => stdout += d.toString());
    proc.stderr.on('data', () => {}); // ignore stderr

    const initMsg = JSON.stringify({
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'assessment', version: '1.0.0' } }
    });
    const callMsg = JSON.stringify({
      jsonrpc: '2.0', id: 2, method: 'tools/call',
      params: { name: toolName, arguments: args }
    });

    proc.stdin.write(initMsg + '\n');
    proc.stdin.write(callMsg + '\n');
    proc.stdin.end();

    const timeout = setTimeout(() => { proc.kill(); reject(new Error('Timeout')); }, 60000);

    proc.on('close', () => {
      clearTimeout(timeout);
      const lines = stdout.split('\n').filter(l => l.trim());
      for (const line of lines) {
        try {
          const data = JSON.parse(line);
          if (data.id === 2 && data.result) {
            const text = data.result.content?.[0]?.text || '';
            resolve({ text, isError: data.result.isError || false });
            return;
          }
        } catch {}
      }
      reject(new Error('No response'));
    });
  });
}

async function runAssessment() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  🛡️  KALI DEFENSE MCP SERVER — FULL HARDENING ASSESSMENT');
  console.log('  Running via MCP JSON-RPC Protocol (tools/call)');
  console.log('═══════════════════════════════════════════════════════════════\n');

  const tools = [
    { name: 'harden_sysctl_audit', args: { category: 'all' }, label: '1. Sysctl & Kernel Hardening Audit' },
    { name: 'harden_permissions_audit', args: { scope: 'all' }, label: '2. Critical File Permissions Audit' },
    { name: 'harden_service_audit', args: { show_all: false }, label: '3. Running Services Audit' },
    { name: 'firewall_iptables_list', args: { table: 'filter', verbose: false }, label: '4. Firewall Rules (iptables)' },
    { name: 'netdef_connections', args: { protocol: 'all', listening: true, process: true }, label: '5. Listening Network Connections' },
    { name: 'access_ssh_audit', args: {}, label: '6. SSH Configuration Audit' },
    { name: 'access_user_audit', args: { check_type: 'all' }, label: '7. User Account Audit' },
    { name: 'access_password_policy', args: { action: 'audit' }, label: '8. Password Policy Audit' },
    { name: 'defense_security_posture', args: { quick: true }, label: '9. Overall Security Posture' },
  ];

  const results = [];

  for (const tool of tools) {
    console.log(`\n${'─'.repeat(60)}`);
    console.log(`📋 ${tool.label}`);
    console.log(`   MCP Tool: ${tool.name}(${JSON.stringify(tool.args)})`);
    console.log(`${'─'.repeat(60)}`);

    try {
      const result = await callMcpTool(tool.name, tool.args);
      
      // Try to pretty-print JSON, otherwise raw text
      try {
        const parsed = JSON.parse(result.text);
        // For sysctl_audit, show summary
        if (tool.name === 'harden_sysctl_audit' && parsed.summary) {
          console.log(`\n   Compliance: ${parsed.summary.compliancePercent}% (${parsed.summary.compliant}/${parsed.summary.total})`);
          console.log(`   Non-compliant settings:`);
          for (const f of parsed.findings.filter(f => !f.compliant)) {
            console.log(`   ❌ ${f.key} = ${f.current} (should be ${f.recommended}) — ${f.description}`);
          }
        }
        // For permissions_audit
        else if (tool.name === 'harden_permissions_audit' && parsed.findings) {
          console.log(`\n   Total checks: ${parsed.findings.length}`);
          for (const f of parsed.findings) {
            const icon = f.status === 'PASS' ? '✅' : f.status === 'FAIL' ? '❌' : '⚠️';
            console.log(`   ${icon} ${f.file} — ${f.current} (expected: ${f.expected}) ${f.status}`);
          }
        }
        // Generic JSON
        else {
          console.log(JSON.stringify(parsed, null, 2).substring(0, 3000));
        }
      } catch {
        // Raw text output (truncated)
        console.log(result.text.substring(0, 3000));
      }
      
      if (result.isError) console.log('   ⚠️ Tool reported an error');
      results.push({ tool: tool.name, label: tool.label, success: !result.isError });
    } catch (err) {
      console.log(`   ❌ Error: ${err.message}`);
      results.push({ tool: tool.name, label: tool.label, success: false });
    }
  }

  console.log(`\n${'═'.repeat(60)}`);
  console.log('📊 ASSESSMENT SUMMARY');
  console.log(`${'═'.repeat(60)}`);
  for (const r of results) {
    console.log(`   ${r.success ? '✅' : '❌'} ${r.label} (${r.tool})`);
  }
  console.log(`\n   Total tools executed: ${results.length}`);
  console.log(`   Successful: ${results.filter(r => r.success).length}`);
  console.log(`   Failed: ${results.filter(r => !r.success).length}`);
  console.log(`${'═'.repeat(60)}`);
}

runAssessment().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
