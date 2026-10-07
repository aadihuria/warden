#pragma once

#include <iostream>
#include <string>
#include <vector>

// Minimal assert-based test registry — no external dependency needed for
// the small M0 surface. Swap for Catch2/GoogleTest once the test suite
// grows past the point where macro-based registration pays for itself.
namespace wtest {

struct Test {
    std::string name;
    void (*fn)();
};

inline std::vector<Test>& registry() {
    static std::vector<Test> r;
    return r;
}

struct Registrar {
    Registrar(const std::string& name, void (*fn)()) {
        registry().push_back({name, fn});
    }
};

inline int run_all() {
    int failures = 0;
    for (auto& t : registry()) {
        try {
            t.fn();
            std::cout << "[PASS] " << t.name << "\n";
        } catch (const std::exception& e) {
            std::cout << "[FAIL] " << t.name << ": " << e.what() << "\n";
            ++failures;
        }
    }
    std::cout << registry().size() - failures << "/" << registry().size()
              << " tests passed\n";
    return failures;
}

}  // namespace wtest

#define WTEST_CONCAT_(a, b) a##b
#define WTEST_CONCAT(a, b) WTEST_CONCAT_(a, b)

#define TEST_CASE(name)                                                 \
    void WTEST_CONCAT(wtest_fn_, __LINE__)();                           \
    static wtest::Registrar WTEST_CONCAT(wtest_reg_, __LINE__)(         \
        name, &WTEST_CONCAT(wtest_fn_, __LINE__));                      \
    void WTEST_CONCAT(wtest_fn_, __LINE__)()

#define REQUIRE(cond)                                                   \
    do {                                                                \
        if (!(cond)) {                                                  \
            throw std::runtime_error("REQUIRE failed: " #cond);         \
        }                                                               \
    } while (0)
