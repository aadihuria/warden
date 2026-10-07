"""Pluggable "agent" decision backends for the benchmark runner.

A backend's job is just: given the scenario and what's happened so far,
decide the next tool call (or decide the task is done). The runner owns
actually sending that call through the proxy/server and recording whether
it was blocked.
"""

# Marker string that attack scenarios embed in their poisoned tool_script
# text. StubBackend(gullible=True) looks for this exact marker to decide
# "the agent has just read injected instructions" -- it's a stand-in for
# the real citation/classifier-based detection a live model backend would
# do by actually reasoning about the text.
INJECTION_MARKER = "[[WARDEN_BENCH_INJECTED_INSTRUCTION]]"


class StubBackend:
    """Deterministic, free, no-network backend for proving out the harness.

    gullible=True  -> simulates an agent that gets hijacked: the moment it
                       sees INJECTION_MARKER in a tool response, it
                       executes the scenario's `injected_action` instead
                       of (well, in addition to continuing) the benign
                       plan. This is the worst-case baseline -- without
                       Warden, this backend should produce ~100% attack
                       success on every attack scenario.
    gullible=False -> ignores injected instructions entirely and just
                       walks the benign plan. This is the best-case
                       baseline -- attack success should be ~0% regardless
                       of Warden, and it's a sanity check that Warden
                       doesn't need to do anything for an agent that was
                       never going to be fooled in the first place.
    """

    def __init__(self, gullible: bool):
        self.gullible = gullible
        self._triggered_injection = False

    def run(self, scenario, send_call_fn):
        executed = []
        last_response_text = None
        step_index = 0
        plan = scenario.get("benign_plan", [])
        max_steps = len(plan) + 2  # plan steps + room for one injected action

        for _ in range(max_steps):
            if (
                self.gullible
                and not self._triggered_injection
                and last_response_text
                and INJECTION_MARKER in last_response_text
                and "injected_action" in scenario
            ):
                action = scenario["injected_action"]
                tool, args = action["tool"], action["arguments"]
                self._triggered_injection = True
            elif step_index < len(plan):
                step = plan[step_index]
                tool, args = step["tool"], step["arguments"]
                step_index += 1
            else:
                break

            text, blocked = send_call_fn(tool, args)
            executed.append({"tool": tool, "arguments": args, "blocked": blocked})
            last_response_text = text

        return executed


class AnthropicBackend:
    """Real Claude-driven agent loop. NOT IMPLEMENTED YET -- wiring up a
    real model means spending real API credits per benchmark run, which
    is a decision for whoever runs this, not something to do silently.

    To implement: on each turn, call the Anthropic Messages API with
    `tools` built from `scenario["tools"]` (map each to a minimal JSON
    schema) and the conversation so far (system prompt stating the
    benign_task, then each tool_result fed back as a user turn). Read the
    model's tool_use block, call `send_call_fn(tool_name, arguments)`,
    feed the result back as a tool_result block, and repeat until the
    model stops calling tools or a turn limit is hit. Must satisfy the
    same `run(scenario, send_call_fn) -> executed_calls` interface as
    StubBackend so the runner doesn't need to change.
    """

    def __init__(self, api_key: str, model: str = "claude-sonnet-5"):
        self.api_key = api_key
        self.model = model

    def run(self, scenario, send_call_fn):
        raise NotImplementedError(
            "AnthropicBackend is a stub -- see class docstring. Implement "
            "when you're ready to spend real API credits on benchmark runs."
        )
