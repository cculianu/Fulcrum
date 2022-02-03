//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2022 Calin A. Culianu <calin.culianu@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program (see LICENSE.txt).  If not, see
// <https://www.gnu.org/licenses/>.
//
#pragma once

#include <QString>
#include <QtGlobal>

#include <condition_variable>
#include <exception>
#include <functional>
#include <future>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>

/// A lightweight "Coroutine Task" (not to be confused with C++20 coroutines). This is a thread that waits
/// for work to be submitted to it via a lambda.
class CoTask
{
public:
    const QString name;

    CoTask(const QString &name = {});
    ~CoTask();

    // A wrapper for future that automatically waits for the wrapped future on destruction.
    struct Future {
        std::future<void> future;
        Future() = default;
        Future(Future &&o) : future(std::move(o.future)) {}
        Future(std::future<void> && f) : future(std::move(f)) {}
        Future &operator=(Future &&o) {
            if (future.valid()) throw std::domain_error("Attempt to move a future onto an already-active future");
            future = std::move(o.future);
            return *this;
        }
        /// Note: This will throw if the future has an exception in it
        ~Future() noexcept(false) try {
            if (future.valid())
                future.get(); // auto-wait for the value, will throw if the worker threw
        } catch (...) {
            if (std::uncaught_exceptions()) {
                qCritical("CoTask::Future::~Future caught an exception from its future object, but the stack is in"
                          " the process of unwinding from another exception, ignoring!");
                return; // suppress rethrow in this case: if a d'tor returns in a catch clause, no rethrow happens
            }
            throw; // re-throw just to be explicit. if we didn't do this, d'tor would rethrow anyway for us (if no return statement)
        }
    };

    /// Submit a lambda to be worked-on by the worker thread associated with this instance. If work was already
    /// active when this is called, this will block. Not designed to submit more than 1 piece of work
    /// at a time.  Intended operation: Submit work, go do something else, then wait for the future, then submit again
    /// later after it's done, etc.
    template <typename Function, typename = std::enable_if_t<std::is_invocable_r_v<void, Function>>>
    [[nodiscard]] Future submitWork(Function && func) {
        std::unique_lock g(mut);
        if (work) throw std::domain_error("Attempt to submit work while work is already pending");
        work = std::forward<Function>(func);
        return submitWorkInner();
    }

private:
    std::thread thr;
    std::mutex mut;
    std::condition_variable cond;
    std::promise<void> prom;
    std::atomic_bool pleaseStop{false};
    std::function<void()> work;

    void thrFunc();
    /// requires mutex be held when called -- it's here to make the above public section less cluttered
    [[nodiscard]] Future submitWorkInner() {
        prom = std::promise<void>();
        Future ret{ prom.get_future() };
        cond.notify_one();
        return ret;
    }
};
