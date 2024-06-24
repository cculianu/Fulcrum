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

#include "Util.h"
#include "ZmqSubNotifier.h"

#if defined(ENABLE_ZMQ)
// real implementation
#define ZMQ_CPP11
#include <zmq.hpp>

#include <QRandomGenerator>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <iterator>
#include <stdexcept>
#include <thread>


struct ZmqSubNotifier::Pvt {
    ~Pvt();
    std::thread thr;
    zmq::context_t ctx;

    // for interruption
    zmq::socket_t interruptSock{ctx,  zmq::socket_type::pair};
    const quint32 salt = QRandomGenerator::global()->generate();
    std::atomic_bool stopFlag = false;
    QByteArray procAddress() const { return QString::asprintf("inproc://%lx%x", static_cast<long>(reinterpret_cast<std::size_t>(this)), salt).toLatin1(); }
};

ZmqSubNotifier::Pvt::~Pvt() { DebugM(__PRETTY_FUNCTION__); }

bool ZmqSubNotifier::isAvailable() { return true; }
bool ZmqSubNotifier::start(const QString &addr, const QString &topic, long retryMsec) {
    if (isRunning()) return false;
    p.reset(new Pvt);

    auto promise = std::make_unique<std::promise<bool>>();
    auto fut = promise->get_future();
    retryMsec = retryMsec <= 0 ? -1 /* forever */ : retryMsec;
    p->thr = std::thread([this, addr = addr.toLatin1(), topic = topic.toLatin1(), retryMsec, oname = objectName()](auto promise) {
        Util::ThreadName::Set(oname.isEmpty() ? "ZMQ" : oname); // set thread name for debug print
        std::size_t nMsgs = 0, nBytes = 0;
        Debug() << "thread started for addr: " << addr << " topic: " << topic << " (procaddress: " << p->procAddress() << ")";
        try {
            p->interruptSock.bind(p->procAddress());
            zmq::socket_t socket;
            int spuriousCt{};
            auto reconnect = [&] {
                spuriousCt = 0;
                socket = zmq::socket_t(p->ctx, zmq::socket_type::sub);
                socket.set(zmq::sockopt::subscribe, topic.toStdString());
                socket.set(zmq::sockopt::tcp_keepalive, 1);
                socket.connect(addr.toStdString());
            };
            reconnect();
            while (!p->stopFlag) {
                static const auto getZmqError = [](const QString &what = "zmq_poll") {
                    return QString("%1 returned an error status: %2").arg(what, zmq_strerror(zmq_errno()));
                };
                zmq::pollitem_t pitems[] = {
                    { socket, 0, ZMQ_POLLIN|ZMQ_POLLERR, 0 },
                    { p->interruptSock, 0, ZMQ_POLLIN, 0 },
                };
                const int nready = zmq::poll(pitems, std::size(pitems), std::chrono::milliseconds(promise ? 0L : retryMsec));
                if (promise) {
                    if (nready < 0)
                        // we throw here to break out of this code and tell client code that first poll failed
                        throw std::runtime_error(getZmqError("first zmq_poll").toUtf8());
                    // first time through we slept for 1 msec to ensure the thread started ok and can connect
                    promise->set_value(true); // signal started ok if no error status from poll
                    promise.reset();
                    if (nready == 0)
                        continue;
                }
                if (nready < 0) {
                    const auto err = getZmqError();
                    Warning() << err;
                    emit errored(err);
                    reconnect();
                    continue;
                } else if (nready == 0) {
                    Debug() << "Idle timeout elapsed (" << QString::number(retryMsec / 1e3, 'f', 1)
                            << " sec), reconnecting socket ...";
                    reconnect();
                    continue;
                }
                if (pitems[1].revents & ZMQ_POLLIN) {
                    // exit requested
                    Debug() << "received thread exit request, breaking out of loop ...";
                    break;
                }
                if (pitems[0].revents & ZMQ_POLLERR) { // I could never get this branch to be taken; left in for completeness...
                    // Sadly, this never triggers (even if connection lost) -- hence the need for the retry mechanism
                    const auto err = "got pollerr from socket";
                    Warning() << err;
                    emit errored(err);
                    reconnect();
                    continue;
                }
                if (!(pitems[0].revents & ZMQ_POLLIN)) {
                    // spurious wakeup?
                    Debug() << "spurious wakeup ...";
                    if (++spuriousCt >= 5) {
                        const auto err = "exceeded spurious wakeup limit";
                        Warning() << err;
                        emit errored(err);
                        reconnect();
                    }
                    continue;
                }
                spuriousCt = 0;
                ++nMsgs;
                QByteArrayList parts;
                bool keepgoing = true;
                std::size_t nBytesNow = 0;
                for (zmq::message_t msg; keepgoing && socket.recv(msg, zmq::recv_flags::dontwait); keepgoing = msg.more()) {
                    parts.append(QByteArray(msg.data<const char>(), int(msg.size())));
                    nBytesNow += msg.size();
                    TraceM("Got message part ", parts.size(), " of size ", msg.size());
                }
                nBytes += nBytesNow;
                if (!parts.empty()) {
                    DebugM("topic: \"", topic, "\", parts: ", parts.size(), ", bytes: ", nBytesNow);
                    emit gotMessage(topic, parts);
                }
            }
        } catch (const std::exception &e) {
            Debug() << "thread caught exception: " << e.what();
            emit errored(e.what());
        }

        Debug() << "thread exiting after processing " << nMsgs << " msgs, " << nBytes << " bytes ...";
        if (promise)
            // if promise is still valid, it indicates an error condition, set false
            promise->set_value(false);
    }, std::move(promise));
    bool ret = false;
    if (constexpr auto timeoutSecs = 20; fut.wait_for(std::chrono::seconds(timeoutSecs)) != std::future_status::ready) {
        // shuld never happen
        Fatal() << "ZMQ: Failed to start thread in " << timeoutSecs << " seconds!";
    } else if (!(ret = fut.get())) {
        stop();
    }
    return ret;
}

void ZmqSubNotifier::stop() {
    if (!isRunning()) return;

    if (p->thr.joinable()) {
        // interrupt thread
        p->stopFlag = true;
        try {
            zmq::socket_t sig(p->ctx, zmq::socket_type::pair);
            sig.connect(p->procAddress().constData());
            const char dummy = 1;
            sig.send(zmq::const_buffer(&dummy, sizeof(dummy)));
            Debug() << "ZMQ: Joining thread ...";
            p->thr.join();
        } catch (const std::exception &e) {
            // should never happen
            Fatal() << "ZMQ: Exception joining thread: " << e.what();
            return;
        }
    }
    p.reset();
}

/* static */
QString ZmqSubNotifier::versionString() {
    int maj{}, min{}, pat{};
    zmq_version(&maj, &min, &pat);
    return QString("libzmq version: %1.%2.%3, cppzmq version: %4.%5.%6")
            .arg(maj).arg(min).arg(pat).arg(CPPZMQ_VERSION_MAJOR).arg(CPPZMQ_VERSION_MINOR).arg(CPPZMQ_VERSION_PATCH);
}

#else
// stub implementation
struct ZmqSubNotifier::Pvt {};
/* static */ bool ZmqSubNotifier::isAvailable() { return false; }
bool ZmqSubNotifier::start(const QString &, const QString &, long) { return false; }
void ZmqSubNotifier::stop() {}
/* static */ QString ZmqSubNotifier::versionString() { return QString(); }
#endif


ZmqSubNotifier::ZmqSubNotifier(QObject *parent)
    : QObject(parent)
{}

ZmqSubNotifier::~ZmqSubNotifier() { stop(); DebugM(__func__); }
