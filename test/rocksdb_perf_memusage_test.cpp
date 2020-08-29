#include <array>
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <cinttypes>
#include <csignal>
#include <functional>
#include <iomanip>
#include <iostream>
#include <list>
#include <memory>
#include <string>
#include <thread>
#include <type_traits>

#include <rocksdb/db.h>
//#include <db/memtable.h>
//#include "rocksdb/memtablefactory.h"
//#include <memtable/inlineskiplist.h>

using namespace std;
using namespace rocksdb;
using namespace std::chrono;

template<typename T>
std::enable_if_t<std::is_integral_v<T>, T>
/* T */ swap_if_big_endian(T val) {
    static_assert(CHAR_BIT == 8, "CHAR_BIT != 8");
    // test if already little endian
    if (const T test = 0x7f; reinterpret_cast<const std::byte *>(&test)[0] == std::byte{0x7f}) {
        // already little endian
        return val;
    }

    auto *ptr = reinterpret_cast<std::byte *>(&val);
    constexpr auto SIZE = sizeof(val);
    // swap the two ends
    for (size_t front = 0; front < SIZE/2; ++front) {
        const auto back = SIZE - front - 1;
        ptr[front] ^= ptr[back];
        ptr[back]  ^= ptr[front];
        ptr[front] ^= ptr[back];
    }
    return val;
}

/*
rocksdb::TableFactory *makeDictionaryTableFactory() {
    auto block_opts = rocksdb::BlockBasedTableOptions{};
    block_opts.checksum = ChecksumType::kCRC32c;
    block_opts.no_block_cache = true;
    return rocksdb::NewBlockBasedTableFactory(block_opts);
}
*/

static std::string readLine()
{
    std::array<char, 256> buf;
    std::cin.getline(buf.data(), buf.size());
    return buf.data();
}

static std::atomic_bool sigCaught = false;

int main(int argc, char *argv[]) {
    bool doWrite = true;

    auto printUsageAndExit = [argv] {
        std::cerr << "Usage: " << argv[0] << " database_path [r]" << std::endl;
        std::exit(1);
    };

    if (argc < 2 || argc > 3)
        printUsageAndExit();

    const std::string dbPath = argv[1];

    if (argc == 3) {
        if (argv[2][0] != 'r')
            printUsageAndExit();
        doWrite = false;
    }

    std::cout << "We will attempt to " << (doWrite ? "CREATE the database" : "OPEN the existing database for reading") << " at: "
              << dbPath << std::endl << std::flush;
    std::cout << "Hit enter if this is correct, Ctrl+C to abort: " << std::flush;
    readLine();

    DB *db_raw{};
    std::unique_ptr<DB> db;
    Options options;
    // Optimize RocksDB. This is the easiest way to get RocksDB to perform well
    options.IncreaseParallelism(8); // TESTING
    options.OptimizeLevelStyleCompaction();
    // create the DB if it's not already present

    options.create_if_missing = doWrite;
    options.error_if_exists = doWrite;
    //options.db_write_buffer_size = 10 * 1024 * 1024;
    options.compression = CompressionType::kNoCompression;
    //options.statistics = rocksdb::CreateDBStatistics();
    //options.write_buffer_size = 10 * 1024 * 1024;

    // testing
    options.max_open_files = 100;//50;//100;//60; //10; ///< this affects memory usage see: https://github.com/facebook/rocksdb/issues/4112. -1 means unlimited.
    options.keep_log_file_num = 5;


    // open DB
    Status s = DB::Open(options, dbPath.c_str(), &db_raw);
    if (db_raw)
        db.reset(db_raw);

    const auto ChkErr = [](const Status & s, const std::string & prefix = {}){
        if (!s.ok()) {
            if (!prefix.empty())
                std::cerr << prefix << ": ";
            std::cerr << s.ToString() << std::endl;
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
    static constexpr std::size_t KEYSIZE = 4;

    std::signal(SIGINT, [](int sig [[maybe_unused]]){
        std::cerr << "\nSignal caught, aborting loop..." << std::endl;
        sigCaught = true;
    });

    constexpr uint64_t ITERS = 250'000'000;//7'500'000'000ULL;//10'000'000'000ULL;
    if (doWrite) {
        auto lastTS = uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(system_clock::now().time_since_epoch()).count());
        uint64_t lastCt = 0;
        const auto last = ITERS-1;
        bool islast = false;
        uint64_t buffer[KEYSIZE];
        char *pointer = reinterpret_cast<char *>(buffer);
        WriteBatch writeBatch{};
        uint64_t max = 10'000'000;

        Slice key(pointer, sizeof(uint64_t) * KEYSIZE);
        Slice value(reinterpret_cast<char *>(&max), sizeof(max));
        for (uint64_t i = 0; i < ITERS; ++i) {
            *(buffer) = swap_if_big_endian(i);
            *(buffer + 1) = swap_if_big_endian(i + 1);
            *(buffer + 2) = swap_if_big_endian(i + 2);
            *(buffer + 3) = swap_if_big_endian(i + 3);

            writeBatch.Put(/*cf*/nullptr, key, value);

            islast = i == last;
            if (i % 1000 == 0 || islast) {
                const auto nIts = swap_if_big_endian(i);
                const Slice nItems{reinterpret_cast<const char *>(&nIts), sizeof(nIts)};
                writeBatch.Put(nullptr, "NUM_ITEMS", nItems);
                Status s1 = db->Write(WriteOptions(), &writeBatch);
                ChkErr(s1);
                writeBatch.Clear();
                if (sigCaught)
                    break;
            }

            if ((i && i % 1'000'000 == 0) || islast) {
                uint64_t end = uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(system_clock::now().time_since_epoch()).count());
                double time = (end - lastTS) / 1e9;
                lastTS = end;
                const auto diff = i - lastCt;
                lastCt = i;
                double delta = diff / time;
                std::cout << "Write Speed: " << std::to_string(delta) << "  [ " << std::setprecision(3) << ((double(i+1)/ITERS)*100.) << "% ]\n";
            }
        }
    }

    ReadOptions ropts{};
    uint64_t READ_ITERS = 0;
    // read back iteration count
    {
        PinnableSlice val;
        s = db->Get(ropts, db->DefaultColumnFamily(), "NUM_ITEMS", &val);
        ChkErr(s);
        if (val.size() != sizeof(READ_ITERS)) {
            std::cerr << "Error reading db NUM_ITEMS key, aborting" << std::endl;
            std::exit(1);
        }
        std::memcpy(&READ_ITERS, val.data(), sizeof(READ_ITERS));
        READ_ITERS = swap_if_big_endian(READ_ITERS);
    }

    if (!sigCaught) {
        std::atomic<uint64_t> COUNTER = 0;
        constexpr int NTHR = 2;
        std::cout << "Reading " << READ_ITERS << " items back in " << NTHR << " threads ..." << std::endl;
        std::function<void(bool)> threadFunc = [READ_ITERS, db=db.get(), ropts, &ChkErr, &COUNTER](bool printerThread) {
            uint64_t buffer[KEYSIZE];
            char *pointer = reinterpret_cast<char *>(buffer);
            uint64_t max = 10'000'000;
            Slice key(pointer, sizeof(uint64_t) * KEYSIZE);
            Slice value(reinterpret_cast<char *>(&max), sizeof(max));

            uint64_t i = printerThread ? 0 : READ_ITERS - 1;
            static_assert (!std::is_signed_v<decltype(i)>);
            const auto last = printerThread ? READ_ITERS - 1 : 0;
            using BFunc = std::function<bool()>;
            using VFunc = std::function<void()>;
            static_assert (NTHR==2); // for now we only really support 2 threads
            const BFunc loopCondition = printerThread
                                        ? BFunc{[&] { return i < READ_ITERS && !sigCaught; }}
                                        : BFunc{[&] { return i+1U != 0U && !sigCaught; }};
            const VFunc loopIncr = printerThread ? VFunc{[&] { ++i; }} : VFunc{[&] { --i; }};
            auto lastTS = uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(system_clock::now().time_since_epoch()).count());
            uint64_t lastCt = 0;
            const uint64_t totalCt = READ_ITERS * NTHR;
            for (; loopCondition(); loopIncr()) {
                //std::string val;
                PinnableSlice val;
                *(buffer) = swap_if_big_endian(i);
                *(buffer + 1) = swap_if_big_endian(i + 1);
                *(buffer + 2) = swap_if_big_endian(i + 2);
                *(buffer + 3) = swap_if_big_endian(i + 3);

                auto s = db->Get(ropts, db->DefaultColumnFamily(), key, &val);
                ChkErr(s);

                if (val.size() != value.size() || std::memcmp(val.data(), value.data(), val.size()) != 0) {
                    std::cerr << "Error reading value " << i << ": not equal!" << std::endl;;
                    break;
                }
                const auto ct = ++COUNTER;
                //val.Reset();

                if (ct == totalCt || (printerThread && ((i && i % 100'000L == 0) || i == last))) {
                    const auto end = uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(system_clock::now().time_since_epoch()).count());
                    double time = (end - lastTS) / 1e9;
                    lastTS = end;
                    const auto diffCt = ct - lastCt;
                    lastCt = ct;
                    double delta = diffCt / time;
                    std::cout << "Read Speed: " << std::to_string(delta)
                              << "  [ " << std::setprecision(3) << ((double(double(ct)+1.)/totalCt)*100.) << "% ]"
                              << std::endl;
                }
            }
        };
        std::list<std::thread> threads;
        for (int i = 0; i < NTHR; ++i)
            threads.emplace_back(threadFunc, i == 0);
        for (auto &thread : threads)
            thread.join();
    }

    std::cerr << "Press enter to close db" << std::endl;
    readLine();

    //s = db->DestroyColumnFamilyHandle(cf);
    s = db->Close();
    ChkErr(s);
    db.reset();

    std::cerr << "DB closed, oress enter to exit" << std::endl;
    readLine();

    return 0;
}
