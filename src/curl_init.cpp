#include "warden/curl_init.hpp"

#include <curl/curl.h>

#include <mutex>

namespace warden {

void ensure_curl_global_init() {
    static std::once_flag flag;
    std::call_once(flag, []() { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

}  // namespace warden
