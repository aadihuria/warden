#include "warden/replication.hpp"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <sstream>

#include "json.hpp"

using json = nlohmann::json;

namespace warden {

std::string events_to_json(const std::vector<LedgerEvent>& events) {
    json arr = json::array();
    for (const auto& ev : events) {
        arr.push_back({{"replica_id", ev.replica_id},
                        {"lamport_clock", ev.lamport_clock},
                        {"prev_hash", ev.prev_hash},
                        {"payload", ev.payload},
                        {"content_hash", ev.content_hash}});
    }
    return arr.dump();
}

std::vector<LedgerEvent> events_from_json(const std::string& json_str) {
    std::vector<LedgerEvent> out;
    try {
        json arr = json::parse(json_str);
        if (!arr.is_array()) return out;
        for (const auto& item : arr) {
            LedgerEvent ev;
            ev.replica_id = item.value("replica_id", std::string());
            ev.lamport_clock = item.value("lamport_clock", uint64_t{0});
            ev.prev_hash = item.value("prev_hash", std::string());
            ev.payload = item.value("payload", std::string());
            ev.content_hash = item.value("content_hash", std::string());
            out.push_back(std::move(ev));
        }
    } catch (const std::exception&) {
        // Malformed peer response -- return whatever we parsed (possibly
        // nothing). Caller treats an empty result as "nothing new", which
        // is the safe default for a corrupt/untrusted peer response.
    }
    return out;
}

namespace {

size_t curl_write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

std::string http_response(int status, const std::string& status_text, const std::string& body) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << status << " " << status_text << "\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << body;
    return oss.str();
}

}  // namespace

ReplicationServer::ReplicationServer(int port, std::vector<std::string> peers,
                                      std::function<std::string()> get_events_json,
                                      std::function<int()> sync_now)
    : port_(port), peers_(std::move(peers)), get_events_json_(std::move(get_events_json)),
      sync_now_(std::move(sync_now)) {}

ReplicationServer::~ReplicationServer() { stop(); }

bool ReplicationServer::start() {
    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) return false;

    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // local-only: replication is
                                                       // meant for trusted peer
                                                       // Warden instances, not the
                                                       // public internet -- see
                                                       // NOTES.md.
    addr.sin_port = htons(static_cast<uint16_t>(port_));

    if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    if (listen(listen_fd_, 16) < 0) {
        close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }

    running_ = true;
    accept_thread_ = std::thread(&ReplicationServer::accept_loop, this);
    return true;
}

void ReplicationServer::stop() {
    if (!running_) return;
    running_ = false;
    if (listen_fd_ >= 0) {
        shutdown(listen_fd_, SHUT_RDWR);
        close(listen_fd_);
        listen_fd_ = -1;
    }
    if (accept_thread_.joinable()) accept_thread_.join();
}

void ReplicationServer::accept_loop() {
    while (running_) {
        int client_fd = accept(listen_fd_, nullptr, nullptr);
        if (client_fd < 0) {
            if (!running_) break;
            continue;
        }
        handle_connection(client_fd);
        close(client_fd);
    }
}

void ReplicationServer::handle_connection(int client_fd) {
    char buf[8192];
    std::string request;
    // Read until we have the blank line ending headers, or the buffer's
    // exhausted -- this server has no use for request bodies (GET takes
    // none, POST /ledger/sync takes none), so headers are all we parse.
    while (request.find("\r\n\r\n") == std::string::npos) {
        ssize_t n = read(client_fd, buf, sizeof(buf));
        if (n <= 0) break;
        request.append(buf, n);
        if (request.size() > 16384) break;  // malformed/oversized request -- bail
    }

    std::istringstream request_line_stream(request);
    std::string method, path, version;
    request_line_stream >> method >> path >> version;

    std::string body;
    int status = 200;
    std::string status_text = "OK";

    if (method == "GET" && path == "/ledger/events") {
        body = get_events_json_();
    } else if (method == "POST" && path == "/ledger/sync") {
        int merged = sync_now_();
        body = json{{"merged_new_events", merged}}.dump();
    } else {
        status = 404;
        status_text = "Not Found";
        body = json{{"error", "unknown route"}}.dump();
    }

    std::string response = http_response(status, status_text, body);
    write(client_fd, response.data(), response.size());
}

bool fetch_peer_events_json(const std::string& peer_base_url, std::string& out_json) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    std::string response_body;
    std::string url = peer_base_url + "/ledger/events";
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || http_code != 200) return false;
    out_json = response_body;
    return true;
}

}  // namespace warden
