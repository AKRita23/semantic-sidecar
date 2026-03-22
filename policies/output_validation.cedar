// policies/output_validation.cedar
// Deny rules for server-side prompt injection in tool responses.
// Runs post-execution, pre-model-context — the Stage 4b Cedar counterpart.
// These policies are the Cedar floor for what Stage 4b enforces observationally.

// Deny tool responses containing injection phrases
forbid(
  principal is MCPServer,
  action == Action::"tool_response",
  when {
    context has contains_injection_phrase &&
    context.contains_injection_phrase == true
  }
);

// Deny tool responses containing tool call directives
// (tool trying to inject new tool calls into model context)
forbid(
  principal is MCPServer,
  action == Action::"tool_response",
  when {
    context has contains_tool_call_directive &&
    context.contains_tool_call_directive == true
  }
);
