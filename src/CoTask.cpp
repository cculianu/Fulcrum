//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2024 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "CoTask.h"
#include "Util.h"

#include <QThread>

CoTask::CoTask(const QString &name_)
    : name{name_}
{
    thr = std::thread([this] {
        if (QThread *qthr; !name.isEmpty() && (qthr = QThread::currentThread()))
            qthr->setObjectName(name);
        thrFunc();
    });
}

CoTask::~CoTask()
{
    if (thr.joinable()) {
        DebugM(__func__, ": joining thread");
        {
            std::unique_lock g(mut);
            pleaseStop = true;
            cond.notify_all();
        }
        thr.join();
    }
}

void CoTask::thrFunc()
{
    DebugM("CoTask thread started");
    const Tic t0;
    qint64 nsecsProcessing = 0;
    unsigned ctr = 0;
    Defer d([&t0, &ctr, &nsecsProcessing] {
        DebugM("CoTask thread exited, ran ", ctr, Util::Pluralize(" job", ctr), ", processing time: ",
               QString::number(nsecsProcessing / 1e9, 'f', 3), " secs, elapsed total: ", t0.secsStr(1), " secs");
    });
    std::unique_lock lock(mut);
    for (;;) {
        if (pleaseStop)
            return;
        if (work) {
            // we do work with the lock held -- the design is 1 job can be submitted at a time
            // and if caller attempts to submit a second one, they will block
            ++ctr;
            std::function<void()> mywork;
            mywork.swap(work);
            std::promise<void> myprom;
            myprom.swap(prom);
            try {
                Tic tStart;
                mywork();
                nsecsProcessing += tStart.nsec();
                myprom.set_value();
            } catch (...) {
                myprom.set_exception(std::current_exception());
            }
        } else {
            cond.wait(lock);
        }
    }
}
