// clang++ security_cam.cc -o brute -fopenmp -lcrypto -O3
#include <cstdio>
#include <string>
#include <fstream>
#include <atomic>
#include <vector>
#include <chrono>
#include <openssl/md5.h>
#include <omp.h>

static std::string md5_hex(const std::string& input) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const unsigned char*>(input.data()), input.size(), digest);
    char hex[33];
    for (int i = 0; i < 16; ++i)
        std::snprintf(hex + i * 2, 3, "%02x", digest[i]);
    return std::string(hex, 32);
}

int main() {
    const std::string expected = "b3539154c5b784bba2c47a1a6c7c4ab0";
    const std::string username = "user", realm = "PythonRTSP";
    const std::string nonce = "4874a055c3f4390506d99e6c51a9e3e360cbef8a62abd7079e11faddcb70a38c";
    const std::string uri = "rtsp://cns-test.idlab.uantwerpen.be:50002/video";

    const std::string HA2 = md5_hex("DESCRIBE:" + uri);

    std::ifstream file("rockyou.txt");
    std::vector<std::string> passwords;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        passwords.push_back(std::move(line));
    }
    const long total = passwords.size();
    std::printf("Loaded %ld passwords, starting...\n", total);

    std::atomic<bool> found{false};
    std::atomic<long> done{0};
    std::string result;
    const auto t0 = std::chrono::steady_clock::now();

    #pragma omp parallel for schedule(dynamic, 4096) shared(result)
    for (long i = 0; i < total; ++i) {
        if (found.load(std::memory_order_relaxed)) continue;

        const std::string HA1 = md5_hex(username + ":" + realm + ":" + passwords[i]);
        if (md5_hex(HA1 + ":" + nonce + ":" + HA2) == expected) {
            found.store(true);
            #pragma omp critical
            result = passwords[i];
        }

        const long n = done.fetch_add(1, std::memory_order_relaxed) + 1;

        // Only thread 0 prints, and only every ~2 million tries
        if (n % 2000000 == 0 && omp_get_thread_num() == 0) {
            const double pct = 100.0 * n / total;
            const double secs = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - t0).count();
            const long rate = (long)(n / secs);
            const long eta = (long)((total - n) / (double)rate);
            std::printf("\r[%5.1f%%] %ld/%ld  %ld tries/s  ETA %ldm%02lds   ",
                        pct, n, total, rate, eta / 60, eta % 60);
            std::fflush(stdout);
        }
    }

    const double secs = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();
    std::printf("\r%ld tries in %.1fs (%.0f tries/s avg)\n",
                done.load(), secs, done.load() / secs);

    if (found) std::printf("FOUND: %s\n", result.c_str());
    else       std::printf("Not found in wordlist.\n");
    return 0;
}

