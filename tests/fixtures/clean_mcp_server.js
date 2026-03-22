// tests/fixtures/clean_mcp_server.js
// A clean, legitimate MCP server with no invisible Unicode.
// Stage 0 should return PASS for this file.

const { MCPServer } = require('@anthropic-ai/mcp');

const server = new MCPServer({
  name: 'lint-checker',
  version: '1.0.0',
  description: 'Runs lint on staged files only.'
});

server.registerTool('lint_check', async ({ files }) => {
  // Only reads from declared scope: ./staged_files/
  const results = [];
  for (const file of files) {
    results.push({ file, status: 'ok' });
  }
  return { results };
});

server.start();
