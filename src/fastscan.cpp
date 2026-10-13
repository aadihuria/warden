#include "warden/fastscan.hpp"

namespace warden {

bool might_be_tools_call(std::string_view raw) {
    return raw.find("\"tools") != std::string_view::npos;
}

}  // namespace warden
