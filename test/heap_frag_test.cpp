#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <iostream>
#include <list>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>

namespace {
    struct MemInfo {
        size_t physUsed{}, virtUsed{};
    };
    // fwddecl
    void platformInit();
    MemInfo getProcessMemUsage();
}

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

namespace {
MemInfo getProcessMemUsage() {
    PROCESS_MEMORY_COUNTERS_EX pmc;
    GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));
    return { size_t{pmc.WorkingSetSize}, size_t{pmc.PrivateUsage} };
}
bool setupLFH() {
    if (const auto *p = std::getenv("NOLFH"); p && std::string(p) != "0") {
        std::cerr << "Windows: NOLFH set in env, not force-setting LFH" << std::endl;
        return false;
    }
    HANDLE h = GetProcessHeap();
    if (!h) {
        auto err = GetLastError();
        std::cerr << "Windows: GetProcessHeap error code " << err << std::endl;
        return false;
    }
    ULONG HeapInfo = 2 /* setup LFH */;
    auto bResult = HeapSetInformation(h, HeapCompatibilityInformation, &HeapInfo, sizeof(HeapInfo));
    if (bResult != FALSE) {
        std::cerr << "Windows: The low-fragmentation heap has been enabled" << std::endl;
        return true;
    } else {
        auto err = GetLastError();
        std::cerr << "Windows: Failed to set low-fragmentation heap, error code " << err << std::endl;
        return false;
    }
}
int queryHeapInfo() {
    constexpr ULONG HEAP_STANDARD = 0;
    constexpr ULONG HEAP_LAL = 1;
    constexpr ULONG HEAP_LFH =2;
    BOOL bResult;
    HANDLE hHeap;
    ULONG HeapInformation;

    //
    // Get a handle to the default process heap.
    //
    hHeap = GetProcessHeap();
    if (hHeap == NULL) {
        auto err = GetLastError();
        std::cerr << "Windows: Failed to retrieve default process heap with LastError " << err << std::endl;
        return 1;
    }

    //
    // Query heap features that are enabled.
    //
    bResult = HeapQueryInformation(hHeap,
                                   HeapCompatibilityInformation,
                                   &HeapInformation,
                                   sizeof(HeapInformation),
                                   NULL);
    if (bResult == FALSE) {
        auto err = GetLastError();
        std::cerr << "Windows: Failed to retrieve heap features with LastError " << err << std::endl;
        return 1;
    }

    //
    // Print results of the query.
    //
    std::cerr << "Windows: HeapCompatibilityInformation is " << HeapInformation << " - ";
    switch(HeapInformation)
    {
    case HEAP_STANDARD:
        std::cerr << "The default process heap is a standard heap." << std::endl;
        break;
    case HEAP_LAL:
        std::cerr << "The default process heap supports look-aside lists." << std::endl;
        break;
    case HEAP_LFH:
        std::cerr << "The default process heap has the low-fragmentation heap enabled." << std::endl;
        break;
    default:
        std::cerr << "Unrecognized HeapInformation reported for the default process heap," << std::endl;
        return 2;
     }
    return 0;
}
void platformInit() {
    setupLFH();
    queryHeapInfo();
}
} // namespace
#elif defined(__APPLE__)
#include<mach/mach.h>
namespace {
    void platformInit() {}
    MemInfo getProcessMemUsage() {
        struct task_basic_info t_info;
        mach_msg_type_number_t t_info_count = TASK_BASIC_INFO_COUNT;

        if (KERN_SUCCESS != task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t)&t_info, &t_info_count)) {
            return {};
        }
        return { size_t{t_info.resident_size}, size_t{t_info.virtual_size} };
    }
}
#elif defined(__linux__)
#include <fstream>
#include <strings.h>
namespace {
    void platformInit() {}
    MemInfo getProcessMemUsage() {
        MemInfo ret;
        std::ifstream file("/proc/self/status", std::ios_base::in);
        if (!file) return ret;
        std::array<char, 256> buf;
        buf[0] = 0;
        // sizes are in kB
        while (file.getline(buf.data(), buf.size()) && (ret.physUsed == 0 || ret.virtUsed == 0)) {
            if (strncasecmp(buf.data(), "VmSize:", 7) == 0) {
                std::istringstream is(buf.data() + 7);
                is >> std::skipws >> ret.virtUsed;
                ret.virtUsed *= 1024;
            } else if (strncasecmp(buf.data(), "VmRSS:", 6) == 0) {
                std::istringstream is(buf.data() + 6);
                is >> std::skipws >> ret.physUsed;
                ret.physUsed *= 1024;
            }
        }
        return ret;
    }
}
#else
namespace {
    void platformInit() {}
    // Unknown platform -- this will always return 0
    MemInfo getProcessMemUsage() {
        std::cerr << "Warning: Unknown platform, " << __func__ << " returning 0!" << std::endl;
        return {};
    }
}
#endif

namespace {
template <typename Num>
std::enable_if_t<std::is_integral_v<Num>, std::string>
commaNum(Num num, bool showpos = false)
{
    std::string s;
    if (!num) {
        if (showpos) s.insert(s.begin(), '+');
        s += "0";
        return s;
    }
    bool neg{};
    if (num < 0) {
        neg = true;
        num = -num;
    }
    for (int i = 0; num;  ++i) {
        if (i && i % 3 == 0)
            s += ',';
        s += '0' + (num % 10);
        num /= 10;
    }
    if (neg) s += '-';
    else if (showpos) s += '+';
    std::reverse(s.begin(), s.end());
    return s;
}
//! Thread-safe stdout printer
class Print {
    std::ostringstream oss{};
public:
    static thread_local std::string name;
    ~Print() {
        static std::mutex mut;
        oss.flush();
        std::unique_lock g(mut);
        if (!name.empty())
            std::cout << "[" << name << "] ";
        std::cout << oss.str() << std::endl << std::flush;
    }
    template <typename T>
    auto &operator<<(T && t) { return oss << t; }
};
thread_local std::string Print::name;

inline constexpr auto MEAN = 1000, STDEV = 990, FACTOR = 100, RATIO = 8;
inline constexpr auto periter = 100'000u;
std::atomic<size_t> iterCtr = 0;
using ThreadFuncPromise = std::promise<size_t>;
using ThreadFuncFuture = std::shared_future<void>;
void threadFunc(int tnum, unsigned iters, ThreadFuncPromise promise, ThreadFuncFuture future)
{
    std::random_device rd;
    std::mt19937 rng(rd());
    std::array<std::normal_distribution<>, 2> dists = { std::normal_distribution<>{MEAN, STDEV},
                                                        std::normal_distribution<>{MEAN*FACTOR, STDEV*FACTOR} };
    static_assert  (RATIO > 0);
    auto gen = [&dists, &rng, i=0U]() mutable {
        auto &dist = dists[i++ % RATIO == 0 ? 1 : 0];
        return std::max(size_t(std::round(std::abs(dist(rng)))), size_t(1));
    };
    constexpr auto avg2 = [](auto x) { return (x*(RATIO-1) + x*FACTOR) / RATIO; };
    Print::name = dynamic_cast<std::ostringstream &&>(std::ostringstream{} << tnum).str();
    Print() << "Iterating " << commaNum(iters) << " time(s), with " << commaNum(periter)
            << " allocations per iteration, avg. size " << avg2(MEAN) << ", median size: " << MEAN;
    size_t nBytesTotal{};
    struct Buffer {
        char * const data;
        Buffer(const size_t size) : data(new char[size]) {
            if (size)
                data[size-1] = 0xef;
        }
        ~Buffer() { delete [] data; }
    };

    std::list<Buffer> allocs;
    for (auto iter = 0U; iter < iters; ++iter) {
        allocs.clear();
        Print() << "Iteration " << commaNum(iter) << ", nBytes so far: " << commaNum(nBytesTotal);
        size_t nBytes{};
        for (auto i = 0U; i < periter; ++i) {
            const auto nb = gen();
            nBytes += nb;
            nBytesTotal += nb;
            allocs.emplace_back(nb);
            iterCtr.fetch_add(1, std::memory_order::memory_order_relaxed);
        }
        Print() << "Allocated " << commaNum(nBytes) << " this iteration";
    }
    promise.set_value(nBytesTotal);
    future.wait(); // wait for main thread to tell us to clear the list
    allocs.clear();
    Print() << "Thread exited";
}
} // namespace

int main(int argc, const char *argv[])
{
    platformInit();

    using std::cout; using std::cerr; using std::endl; using std::flush;
    unsigned iters = 10, nthr = std::min(std::max(std::thread::hardware_concurrency(), 1u), 6u);
    if (argc > 1) {
        const auto usage = [prog = argv[0]] {
            cerr << "Usage: " << prog << " ITERS [NTHREADS]" << endl;
            std::exit(1);
        };
        if (argc > 3)
            usage();
        if (int val{}; std::sscanf(argv[1], "%u", &val) != 1 || val <= 0)
            usage();
        else
            iters = val;
        if (argc == 3) {
            if (int val{}; std::sscanf(argv[2], "%d", &val) != 1 || val <= 0)
                usage();
            else
                nthr = val;
        }
    }
    const auto readLine = [] {
        std::array<char, 256> buf;
        if (!std::cin.getline(buf.data(), buf.size()))
            buf[0] = 0;
        return std::string(buf.data());
    };
    const auto getMemUsedStr = [] {
        const auto [phys, virt] = getProcessMemUsage();
        std::ostringstream oss;
        oss << "Mem. usage - phys: " << commaNum(phys/1'000UL) << " kB, virt: " << commaNum(virt/1'000UL) << " kB" << flush;
        return oss.str();
    };
    const auto startingMem = getProcessMemUsage();
    {
        using TheradAndFuture = std::pair<std::thread, decltype(std::declval<ThreadFuncPromise>().get_future())>;
        std::list<TheradAndFuture> threads;
        std::promise<void> kickThreads;
        {
            auto kickSharedFut = kickThreads.get_future().share();
            cout << "Starting " << nthr << " threads" << endl;
            for (auto i = 0u; i < nthr; ++i) {
                ThreadFuncPromise p;
                auto fut = p.get_future();
                auto t = std::thread(threadFunc, i+1, iters, std::move(p), kickSharedFut);
                threads.emplace_back(std::move(t), std::move(fut));
            }
        }
        size_t nBytesTotal{};
        for (auto & [_, fut] : threads)
            nBytesTotal += fut.get();
        auto memNow = getProcessMemUsage();
        cout << "Finished!" << " Total allocated: " << commaNum(nBytesTotal/1'000UL) << " kB, iterations: "
             << commaNum(iterCtr.load())
             << endl << endl << getMemUsedStr() << endl << endl
             << "Hit enter to clear list(s): " << flush;
        readLine();
        kickThreads.set_value();
        for (auto & [thread, _] : threads)
            thread.join();
        memNow = getProcessMemUsage();
        cout << "List(s) cleared" << endl << endl << getMemUsedStr() << endl << endl << "Hit enter to exit program: " << flush;
        // scope end hopefully does even more cleanup
    }
    readLine();

    const auto endingMem = getProcessMemUsage();
    cout << endl
         << "Delta from program start - phys: " << commaNum((ssize_t(endingMem.physUsed) - ssize_t(startingMem.physUsed))/1'000L, true) << " kB, "
         << "virt: " << commaNum((ssize_t(endingMem.physUsed) - ssize_t(startingMem.physUsed))/1'000L, true) << " kB" << endl;
    return 0;
}
