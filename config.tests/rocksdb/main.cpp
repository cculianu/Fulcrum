#include <array>
#include <cstddef>
#include <memory>
#include <rocksdb/version.h>
#include <rocksdb/merge_operator.h>

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

// If this causes an "undefined reference to `typeinfo for rocksdb::AssociativeMergeOperator'" error
// in config.log it means that the rocksdb version you are attempting to use is built without RTTI.
class ConcatOperator : public rocksdb::AssociativeMergeOperator {
public:
    bool Merge(const rocksdb::Slice&, const rocksdb::Slice*, const rocksdb::Slice&, std::string*, rocksdb::Logger*) const override { return true; }
    const char* Name() const override { return "ConcatOperator"; }
};

int main()
{
    auto op = std::make_unique<ConcatOperator>();
    return 0;
}
