#ifndef STORAGE_H
#define STORAGE_H

#include "Mgr.h"
#include "Mixins.h"
#include "Options.h"

#include <QByteArray>
#include <QFlags>

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <utility>
#include <vector>

namespace BTC { class HeaderVerifier; } // fwd decl used below. #include "BTC.h" to see this type

struct DatabaseError : public Exception { using Exception::Exception; ~DatabaseError() override; };

class Storage final : public Mgr, public ThreadObjectMixin
{
public:
    Storage(const std::shared_ptr<Options> & options);
    ~Storage() override;

    // Mgr interface
    void startup() override;
    void cleanup() override;
    // /Mgr

    // Public interface -- unless otherwise specified all functions below are thread-safe

    // some types
    using Headers = std::vector<QByteArray>; ///< each header is 80 bytes
    using RWLock = std::shared_mutex;
    using Lock = std::mutex;
    using ExclusiveLockGuard = std::unique_lock<RWLock>;
    using SharedLockGuard = std::shared_lock<RWLock>;
    using LockGuard = std::unique_lock<Lock>;

    /// Returns a reference to the headers in our memory cache, locked in exclusive mode.
    /// Be sure to keep the ExclusiveLockGuard in scope until the updates to the vector are complete in order to keep
    /// the data structure locked.
    /// This is howe we update the headers vector.
    /// Be sure to call save(Hdrs) if you have mutated the headers and want the updates saved to disk.
    std::pair<Headers &, ExclusiveLockGuard> mutableHeaders();
    /// How we read headers from our memory cache. The lock is locked in shared mode.
    std::pair<const Headers &, SharedLockGuard> headers() const;

    enum class SaveItem : uint32_t {
        Hdrs = 0x01,  ///< save headers

        All = 0xffffffff, ///< save everything
        None = 0x00, ///< No-op
    };
    Q_DECLARE_FLAGS(SaveSpec, SaveItem)

    /// Keep the returned LockGuard in scope while you use the HeaderVerifier
    std::pair<BTC::HeaderVerifier &, LockGuard> headerVerifier();

    /// schedules updates to be written to disk immediately when control returns to this
    /// object's thread's event loop.
    void save(SaveSpec = SaveItem::All);

protected:
    virtual Stats stats() const override; ///< from StatsMixin

private:
    const std::shared_ptr<Options> options;

    struct Pvt;
    std::unique_ptr<Pvt> p;

    void save_impl(); ///< may abort app on database failure (unlikely).
    void saveHeaders_impl(const Headers &); ///< caller should pass a copy of the headers or hold the lock. this may throw on database error.

    void loadHeadersFromDB(); // may throw -- called from startup()
};

Q_DECLARE_OPERATORS_FOR_FLAGS(Storage::SaveSpec)

#endif // STORAGE_H
