#pragma once

namespace warden {

// Ensures curl_global_init() has been called exactly once, in a
// thread-safe way, before any curl_easy_init() call. libcurl's own docs
// are explicit that relying on implicit auto-init is NOT safe when
// multiple threads might call curl_easy_init() concurrently for the
// first time -- which became a real possibility once QuorumVerifier
// started dispatching verifiers concurrently (see src/quorum.cpp).
// Every call site that uses libcurl (anthropic_verifier.cpp,
// replication.cpp) must call this before curl_easy_init().
void ensure_curl_global_init();

}  // namespace warden
