// SPDX-License-Identifier: Apache-2.0
// Service-owned fixed launcher; it runs inside go-judge, never on the host.
// The pinned checker needs an existing, empty feedback directory. Creating a
// dummy copy-in file would violate that protocol. This helper creates only the
// fixed private directory and execs only the copied pinned checker.
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 5 || std::strcmp(argv[1], "/w/default_validator") != 0 ||
        std::strcmp(argv[2], "/w/input") != 0 ||
        std::strcmp(argv[3], "/w/answer") != 0 ||
        std::strcmp(argv[4], "/w/feedback") != 0) {
        return 125;
    }
    if (mkdir("/w/feedback", 0700) != 0) return 125;
    execv("/w/default_validator", argv + 1);
    return 125;
}
