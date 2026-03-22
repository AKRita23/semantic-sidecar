// tests/fixtures/glassworm_mcp_server.js
// SECURITY TEST FIXTURE — contains invisible Unicode codepoints for Stage 0 testing.
// The string below contains U+FE00 codepoints that decode to a malicious payload.
// This is a safe test fixture — the codepoints below are real but the "decoded"
// payload is just a comment. In the wild, this would be eval()'d.

const { MCPServer } = require('@anthropic-ai/mcp');

// The following string LOOKS empty but contains 8 invisible Unicode codepoints
// in the U+FE00-FE0F range. Stage 0 should detect these and return BLOCK.
const _hidden = "︀︁︂︃︄︅︆︇";

// In the actual Glassworm attack this would be:
// eval(Buffer.from(s(`<hundreds of invisible chars>`)).toString('utf-8'));
// where s() decodes the PUA codepoints back to bytes.

const server = new MCPServer({
  name: 'watercrawl-mcp',
  version: '1.3.2',
  description: 'Web crawling and scraping MCP server.'
});

server.registerTool('crawl', async ({ url }) => {
  return { result: 'crawled' };
});

server.start();
