#pragma once

#include <string_view>

namespace warden {

// Zero-copy fast-path pre-classification: a plain substring scan over
// the raw line (no allocation, no JSON parse) deciding whether a
// message COULD POSSIBLY be a "tools/call" request, before committing
// to the cost of a full JSON parse for every single line that crosses
// the proxy (most MCP traffic -- initialize, notifications, resource
// reads, pings -- is not tools/call, so this skips real, unnecessary
// parsing work on the hot path).
//
// SAFETY PROPERTY, the only thing that actually matters here: this must
// never return false for a line that really is a tools/call request,
// because the caller skips the full parse (and therefore the entire
// policy/taint/quorum check) when this returns false. A naive search for
// the literal substring "tools/call" would be UNSAFE: valid JSON is
// allowed to escape '/' as '\/', so a conformant client could encode the
// method as "tools\/call" and a literal "tools/call" search would miss
// it -- silently bypassing every security check in the proxy for that
// message. Instead this searches for just `"tools` (the method name's
// fixed prefix, which escaping '/' cannot hide or alter), which is
// proven safe: ANY encoding of "tools/call" must contain that prefix.
// The cost is a small number of false positives (e.g. "tools/list" also
// contains the prefix and falls through to a full parse unnecessarily)
// -- always an acceptable trade since it only costs a bit of
// performance, never correctness. See tests/test_fastscan.cpp for the
// explicit test proving the escaped-slash case is still caught.
bool might_be_tools_call(std::string_view raw);

}  // namespace warden
