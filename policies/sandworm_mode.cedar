// policies/sandworm_mode.cedar
// Deny rules for SANDWORM_MODE attack pattern.
// Enforces unconditionally — the deterministic floor, no heuristics.
// Hot-reload: drop updated .cedar files in policies/dynamic/ without restart.

// Deny credential file reads: SSH keys
forbid(
  principal is MCPServer,
  action == Action::"file_read",
  resource matches "/home/**/.ssh/**"
);

// Deny credential file reads: AWS credentials
forbid(
  principal is MCPServer,
  action == Action::"file_read",
  resource matches "/home/**/.aws/**"
);

// Deny credential file reads: GitHub CLI config
forbid(
  principal is MCPServer,
  action == Action::"file_read",
  resource matches "/home/**/.config/gh/**"
);

// Deny undeclared network egress
// Allow only if resource is in declared_destinations from the AGNTCY MCP Server Badge
forbid(
  principal is MCPServer,
  action == Action::"network_egress",
  unless {
    context has declared_destinations &&
    context.declared_destinations.contains(resource)
  }
);
