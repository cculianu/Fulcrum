// This is taken from the rocksdb examples. It's a test for us that the libary links ok.
// Swap this out for main.cpp when you want to see if the library you linked actually works.
#include <cstdio>
#include <string>
#include <iostream>
#include <rocksdb/db.h>
#include <rocksdb/slice.h>
#include <rocksdb/options.h>

#ifdef NDEBUG
#undef NDEBUG
#endif

namespace {
int rocksTestBasic(const char *path);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cerr << "pass a path\n";
        return 1;
    }
    return rocksTestBasic(argv[1]);
}

namespace {
int rocksTestBasic(const char *path) {
    const std::string kDBPath(path);
    using namespace rocksdb;
    DB* db;
    rocksdb::Options options;
    // Optimize RocksDB. This is the easiest way to get RocksDB to perform well
    options.IncreaseParallelism();
    options.OptimizeLevelStyleCompaction();
    // create the DB if it's not already present
    options.create_if_missing = true;

    // open DB
    Status s = DB::Open(options, kDBPath, &db);
    assert(s.ok());

    // Put key-value
    s = db->Put(WriteOptions(), "key1", "value");
    assert(s.ok());
    std::string value;
    // get value
    s = db->Get(ReadOptions(), "key1", &value);
    assert(s.ok());
    assert(value == "value");

    // atomically apply a set of updates
    {
    WriteBatch batch;
    batch.Delete("key1");
    batch.Put("key2", value);
    s = db->Write(WriteOptions(), &batch);
    }

    s = db->Get(ReadOptions(), "key1", &value);
    assert(s.IsNotFound());

    db->Get(ReadOptions(), "key2", &value);
    assert(value == "value");

    {
    PinnableSlice pinnable_val;
    db->Get(ReadOptions(), db->DefaultColumnFamily(), "key2", &pinnable_val);
    assert(pinnable_val == "value");
    }

    {
    std::string string_val;
    // If it cannot pin the value, it copies the value to its internal buffer.
    // The intenral buffer could be set during construction.
    PinnableSlice pinnable_val(&string_val);
    db->Get(ReadOptions(), db->DefaultColumnFamily(), "key2", &pinnable_val);
    assert(pinnable_val == "value");
    // If the value is not pinned, the internal buffer must have the value.
    assert(pinnable_val.IsPinned() || string_val == "value");
    }

    PinnableSlice pinnable_val;
    db->Get(ReadOptions(), db->DefaultColumnFamily(), "key1", &pinnable_val);
    assert(s.IsNotFound());
    // Reset PinnableSlice after each use and before each reuse
    pinnable_val.Reset();
    db->Get(ReadOptions(), db->DefaultColumnFamily(), "key2", &pinnable_val);
    assert(pinnable_val == "value");
    pinnable_val.Reset();
    // The Slice pointed by pinnable_val is not valid after this point

    delete db;

    return 0;
}
}
