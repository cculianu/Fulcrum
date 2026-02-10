//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2026 Calin A. Culianu <calin.culianu@gmail.com>
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

#include "Mixins.h"

#include <QObject>
#include <QVariantMap>

/// Abstract base class of all subsystem controllers such as SrvMgr, BitcoinDMgr, etc.
/// These get created by the App on startup, based on config.
class Mgr : public QObject, public StatsMixin
{
    Q_OBJECT
public:
    explicit Mgr(QObject *parent = nullptr);
    ~Mgr() override;

    virtual void startup() noexcept(false) = 0; ///< NB: mgrs may throw Exception here, so catch it and abort if that happens.
    virtual void cleanup() = 0;
};

