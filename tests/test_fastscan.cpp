#include "test_framework.hpp"
#include "warden/fastscan.hpp"

using namespace warden;

TEST_CASE("might_be_tools_call matches a normal unescaped tools/call method") {
    REQUIRE(might_be_tools_call(
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}})"));
}

TEST_CASE("might_be_tools_call matches an escaped-slash tools\\/call method") {
    // The safety-critical case: valid JSON may escape '/' as '\/'. A
    // naive search for the literal "tools/call" substring would MISS
    // this and silently skip the security check entirely -- this test
    // exists specifically to prove that doesn't happen.
    REQUIRE(might_be_tools_call(
        R"({"jsonrpc":"2.0","id":1,"method":"tools\/call","params":{"name":"x"}})"));
}

TEST_CASE("might_be_tools_call returns false for messages with no 'tools' prefix at all") {
    REQUIRE(!might_be_tools_call(R"({"jsonrpc":"2.0","id":1,"method":"initialize"})"));
    REQUIRE(!might_be_tools_call(R"({"jsonrpc":"2.0","method":"notifications/progress"})"));
    REQUIRE(!might_be_tools_call(""));
    REQUIRE(!might_be_tools_call("not json at all"));
}

TEST_CASE("might_be_tools_call returns true (safe false positive) for tools/list") {
    // Costs an unnecessary full parse, never a missed security check --
    // that's the correct trade-off, explicitly pinned down here.
    REQUIRE(might_be_tools_call(R"({"jsonrpc":"2.0","id":1,"method":"tools/list"})"));
}
