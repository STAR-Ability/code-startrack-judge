// SPDX-License-Identifier: Apache-2.0
// Fixed qualification fixture. It executes only inside the reviewed sandbox.
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/statvfs.h>
#include <unistd.h>

using u64 = unsigned long long;
static u64 created = 0, allocated = 0, peak_bytes = 0, peak_inodes = 0;

static bool snapshot(const char *phase, bool denied, bool cleaned) {
    struct statvfs fs {};
    if (statvfs("/w", &fs) != 0) return false;
    u64 total = u64(fs.f_blocks) * fs.f_frsize;
    u64 used = u64(fs.f_blocks - fs.f_bfree) * fs.f_frsize;
    u64 inodes = fs.f_files, inode_used = fs.f_files - fs.f_ffree;
    if (used > peak_bytes) peak_bytes = used;
    if (inode_used > peak_inodes) peak_inodes = inode_used;
    std::printf("{\"phase\":\"%s\",\"totalBytes\":%llu,\"totalInodes\":%llu,"
                "\"createdFiles\":%llu,\"allocatedBytes\":%llu,\"peakUsedBytes\":%llu,"
                "\"peakUsedInodes\":%llu,\"allocationDenied\":%s,\"cleanupComplete\":%s}\n",
                phase, total, inodes, created, allocated, peak_bytes, peak_inodes,
                denied ? "true" : "false", cleaned ? "true" : "false");
    return std::fflush(stdout) == 0 && total == (2ULL << 30) && inodes == 262144;
}

static int inode_probe() {
    char name[64];
    bool denied = false;
    for (; created < 300000; ++created) {
        std::snprintf(name, sizeof(name), "/w/qualification-inode-%06llu", created);
        int fd = open(name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) {
            if (errno != ENOSPC || created < 250000) return 125;
            denied = true;
            break;
        }
        if (close(fd) != 0) return 125;
    }
    if (!denied || !snapshot("inode", true, false) || peak_inodes != 262144) return 125;
    for (u64 index = 0; index < created; ++index) {
        std::snprintf(name, sizeof(name), "/w/qualification-inode-%06llu", index);
        if (unlink(name) != 0) return 125;
    }
    return snapshot("inode", true, true) ? 0 : 125;
}

static int allocation_probe() {
    const char *name = "/w/qualification-allocation";
    int fd = open(name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return 125;
    static const char data[65536] = {};
    if (!snapshot("allocation", false, false)) return 125;
    for (; allocated < (3ULL << 30);) {
        ssize_t n = write(fd, data, sizeof(data));
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno != ENOSPC || allocated < (1536ULL << 20)) return 125;
            if (!snapshot("allocation", true, false)) return 125;
            if (close(fd) != 0 || unlink(name) != 0) return 125;
            return snapshot("allocation", true, true) ? 0 : 125;
        }
        if (n == 0) return 125;
        allocated += u64(n);
        if (allocated % (64ULL << 20) == 0 && !snapshot("allocation", false, false)) return 125;
    }
    return 125;
}

int main(int argc, char **argv) {
    if (argc != 2) return 125;
    if (std::strcmp(argv[1], "inode") == 0) return inode_probe();
    if (std::strcmp(argv[1], "allocation") == 0) return allocation_probe();
    return 125;
}
