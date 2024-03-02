//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2023 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "App.h"
#include "BlockProc.h"
#include "BitcoinD.h"
#include "BTC.h"
#include "BTC_Address.h"
#include "Controller.h"
#include "Mixins.h"
#include "PeerMgr.h"
#include "RPC.h"
#include "SrvMgr.h"
#include "SubStatus.h"

#include <QMetaType>

void App::register_MetaTypes()
{
    static bool registered = false;

    if (!registered) {
        // finish registering RPC::Message metatype so that signals/slots work. This needs to only happen
        // once in main thread at app init.
        qRegisterMetaType<RPC::Message>("RPC::Message");
        qRegisterMetaType<RPC::Message::Id>("RPC::Message::Id"); // for some reason when this is an alias for QVariant it needs this string here
        qRegisterMetaType<IdMixin::Id>("IdMixin::Id");
        qRegisterMetaType<RPC::BatchId>("RPC::BatchId");

        // Used by the Controller::putBlock signal
        qRegisterMetaType<CtlTask *>("CtlTask *");
        // Used by the Controller::putBlock signal
        qRegisterMetaType<PreProcessedBlockPtr>("PreProcessedBlockPtr");
        // Used by the Controller::putRpaIndex signal
        qRegisterMetaType<Controller::RpaOnlyModeDataPtr>("Controller::RpaOnlyModeDataPtr");

        qRegisterMetaType<QHostAddress>("QHostAddress");

        qRegisterMetaType<PeerInfo>("PeerInfo");
        qRegisterMetaType<PeerInfoList>("PeerInfoList");

        qRegisterMetaType<BTC::Address>("BTC::Address");
        qRegisterMetaType<BTC::Coin>("BTC::Coin");

        qRegisterMetaType<BitcoinDZmqNotifications>("BitcoinDZmqNotifications");

        qRegisterMetaType<SubStatus>("SubStatus");

        registered = true;
    }
}
