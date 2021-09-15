#include <array>
#include <cstddef>
#include <rocksdb/version.h>

constexpr int minimumVersion[] = {6, 6, 4};
constexpr int version[] = {ROCKSDB_MAJOR, ROCKSDB_MINOR, ROCKSDB_PATCH};

constexpr bool compareVersion(const int *version1, const int *version2, const size_t length)
{
    for (size_t i = 0; i < length; i++) {
        if (version1[i] > version2[i]) {
            return true;
        } else if (version1[i] < version2[i]) {
            return false;
        }
    }
    return true;
}

static_assert(compareVersion(version, minimumVersion, std::size(version)));

int main()
{
    return 0;
}
