#include <thread>
#include <cstdio>
#include <string>
#include <iostream>
#include <iomanip>
#include <cinttypes>
#include <csignal>
#include <cstdlib>
#include <rocksdb/db.h>
//#include <db/memtable.h>
//#include "rocksdb/memtablefactory.h"
//#include <memtable/inlineskiplist.h>

using namespace std;
using namespace rocksdb;
using namespace std::chrono;

#define kDBPath "/Users/calin/tmp/DELME_rocksdata"

template<typename T>
T swap_endian(T u) {
    static_assert(CHAR_BIT == 8, "CHAR_BIT != 8");
    constexpr auto SIZE = sizeof(T);

    union {
        T u;
        unsigned char u8[SIZE];
    } source, dest;

    source.u = u;

    for (size_t k = 0; k < SIZE; ++k)
        dest.u8[k] = source.u8[SIZE - k - 1];

    return dest.u;
}

/*
rocksdb::TableFactory *makeDictionaryTableFactory() {
    auto block_opts = rocksdb::BlockBasedTableOptions{};
    block_opts.checksum = ChecksumType::kCRC32c;
    block_opts.no_block_cache = true;
    return rocksdb::NewBlockBasedTableFactory(block_opts);
}
*/

static bool sigCaught = false;

int main() {
    constexpr bool doWrite = true;

    if constexpr (doWrite)
        system("rm -rvf " kDBPath);

    DB *db;
    Options options;
    // Optimize RocksDB. This is the easiest way to get RocksDB to perform well
    options.IncreaseParallelism(8); // TESTING
    options.OptimizeLevelStyleCompaction();
    // create the DB if it's not already present

    options.create_if_missing = true;
    options.error_if_exists = false;
    //options.db_write_buffer_size = 10 * 1024 * 1024;
    options.compression = CompressionType::kNoCompression;
    //options.statistics = rocksdb::CreateDBStatistics();
    //options.write_buffer_size = 10 * 1024 * 1024;

    // testing
    options.max_open_files = 100;//50;//100;//60; //10; ///< this affects memory usage see: https://github.com/facebook/rocksdb/issues/4112. -1 means unlimited.
    options.keep_log_file_num = 5;


    // open DB
    Status s = DB::Open(options, kDBPath, &db);

    const auto ChkErr = [](const Status & s){
        if (!s.ok()) {
            std::cout << s.ToString() << "\n";
            std::exit(1);
        }
    };

    ChkErr(s);

    //ColumnFamilyOptions cf_options{};

    //cf_options.table_factory.reset(makeDictionaryTableFactory());
    //cf_options.prefix_extractor.reset(rocksdb::NewNoopTransform());
    //cf_options.memtable_prefix_bloom_size_ratio = 0;
    //cf_options.write_buffer_size = 10 * 1024 * 1024;

    //std::string name("Name");
    //ColumnFamilyHandle *cf;
    //Status status = db->CreateColumnFamily(cf_options, name, &cf);

    //ChkErr(s);

    u_int64_t *buffer = new u_int64_t[4];
    char *pointer = reinterpret_cast<char *>(buffer);
    WriteBatch writeBatch{};
    u_int64_t max = 10'000'000;

    Slice key(pointer, 32);
    Slice value(reinterpret_cast<char *>(&max), sizeof(max));

    uint64_t begin = uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(system_clock::now().time_since_epoch()).count());

    std::signal(SIGINT, [](int sig [[maybe_unused]]){
        std::cout << "\nSignal caught, aborting loop...\n";
        sigCaught = true;
    });

    constexpr u_int64_t ITERS = 1'000'000'000;//7'500'000'000ULL;//10'000'000'000ULL;
    const auto last = ITERS-1;
    bool islast = false;
    if constexpr (doWrite)
    for (u_int64_t i = 0; i < ITERS; ++i) {
        *(buffer) = swap_endian(i);
        *(buffer + 1) = i + 1;
        *(buffer + 2) = i + 2;
        *(buffer + 3) = i + 3;

        writeBatch.Put(/*cf*/nullptr, key, value);

        islast = i == last;
        if (i % 1000 == 0 || islast) {
            Status s1 = db->Write(WriteOptions(), &writeBatch);
            ChkErr(s1);
            writeBatch.Clear();
            if (sigCaught)
                break;
        }

        if ((i && i % 1'000'000 == 0) || islast) {
            uint64_t end = uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(system_clock::now().time_since_epoch()).count());
            double time = (end - begin) / 1'000'000'000LL;
            double delta = i / time;
            std::cout << "Write Speed: " << std::to_string(delta) << "  [ " << std::setprecision(3) << ((double(i+1)/ITERS)*100.) << "% ]\n";
        }
    }

    if (!sigCaught) {
        std::cout << "Reading " << ITERS << " items back ...\n";
        ReadOptions ropts{};
        begin = uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(system_clock::now().time_since_epoch()).count());
        for (u_int64_t i = 0; i < ITERS && !sigCaught; i++) {
            //std::string val;
            PinnableSlice val;
            *(buffer) = swap_endian(i);
            *(buffer + 1) = i + 1;
            *(buffer + 2) = i + 2;
            *(buffer + 3) = i + 3;

            s = db->Get(ropts, db->DefaultColumnFamily(), key, &val);
            ChkErr(s);

            if (val.size() != value.size() || std::memcmp(val.data(), value.data(), val.size()) != 0) {
                std::cout << "Error reading value " << i << ": not equal!\n";
                break;
            }
            //val.Reset();

            if ((i && i % 1'000'000UL == 0) || i == last) {
                uint64_t end = uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(system_clock::now().time_since_epoch()).count());
                double time = (end - begin) / 1'000'000'000LL;
                double delta = i / time;
                std::cout << "Read Speed: " << std::to_string(delta) << "  [ " << std::setprecision(3) << ((double(i+1)/ITERS)*100.) << "% ]\n";
            }
        }
    }

    std::cout << "Press enter to destroy db" << std::endl;
    char buf[256];
    std::cin.getline(buf, sizeof buf);

    //s = db->DestroyColumnFamilyHandle(cf);
    s = db->Close();
    ChkErr(s);
    delete db;

    std::cout << "DB destroyed, oress enter to exit" << std::endl;
    std::cin.getline(buf, sizeof buf);

    return 0;
}
