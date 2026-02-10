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

#include "bitcoin/heapoptional.h"
#include "DSProof.h"

#include <QByteArray>
#include <QMetaType>
#include <QVariant>

#include <cstdint>
#include <functional> // for std::hash
#include <limits>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility> // for move
#include <variant>

/// This class is sort of like a variant/optional combination. It can store either "No Value" (!.has_value()) or
/// either a: QByteArray, DSProof or a std::optional<BlockHeight>. It is optimized for minimal memory usage in the
/// common case -- taking up as much memory as a std::optional<QByteArray> (16 bytes on 64-bit).
///
/// It is intended to be used with the SubsMgr and its subclasses.
///
/// - ScriptHashSubsMgr::getFullStatus() always returns one of these objects with the QByteArray as the active value,
///   that is, byteArray() will always be valid pointer.
///
/// - DSProofSubsMgr::getFullStatus() always returns one of these objects with the DSProof as the active value,
///   that is, dsproof() will always be a valid pointer.
///
/// - TransactionSubsMgr::getFullStatus() always returns one of these objects with the std::optional<BlockHeight> as
///   the active value, that is, blockHeight() will always be a valid optional (even if it itself !has_value()).
///
class SubStatus {
    using NoValue = std::monostate;
    using QBA = QByteArray;
    using DSP = bitcoin::HeapOptional<DSProof>;
    // we "simulate" a std::optional<BlockHeight> in this class to save memory, by making values out of the uint32_t
    // range act "as if" !block_height.has_value()
    using BH = int64_t;
    static_assert(std::is_same_v<uint32_t, BlockHeight>);

    std::variant<NoValue, QBA, DSP, BH> var;

    static constexpr bool isValidBlockHeight(BH bh) noexcept {
        return    bh >= static_cast<BH>(std::numeric_limits<BlockHeight>::min())
               && bh <= static_cast<BH>(std::numeric_limits<BlockHeight>::max());
    }

    static constexpr BH InvalidBlockHeight = static_cast<BH>(-1);

public:
    SubStatus() noexcept {}
    SubStatus(SubStatus &&o) noexcept = default;
    SubStatus(const SubStatus &o) = default;
    SubStatus(const QByteArray &oq) noexcept : var{oq} {}
    SubStatus(QByteArray &&oq) noexcept : var{std::move(oq)} {}
    SubStatus(const DSProof &od) { var.emplace<DSP>(od); }
    SubStatus(DSProof &&od) { var.emplace<DSP>(std::move(od)); }
    SubStatus(const std::optional<BlockHeight> &obh) noexcept { this->operator=(obh); }
    SubStatus(BlockHeight bh) noexcept : var{static_cast<BH>(bh)} {}

    SubStatus &operator=(const SubStatus &o) = default;
    SubStatus &operator=(SubStatus && o) = default;
    SubStatus &operator=(const QByteArray &oq) { var = oq; return *this; }
    SubStatus &operator=(QByteArray &&oq) { var = std::move(oq); return *this; }
    SubStatus &operator=(const DSProof &od) { var.emplace<DSP>(od); return *this; }
    SubStatus &operator=(DSProof &&od) { var.emplace<DSP>(std::move(od)); return *this; }
    SubStatus &operator=(const std::optional<BlockHeight> &obh) {
        static_assert(!isValidBlockHeight(InvalidBlockHeight)); /* We are forced to put this assertion here rather than
                                                                   at class-level due to C++ compile-time quirks. */
        var = obh ? static_cast<BH>(*obh) : InvalidBlockHeight;
        return *this;
    }

    bool operator==(const SubStatus &o) const { return var == o.var; }

    explicit operator bool() const noexcept { return has_value(); }

    bool has_value() const noexcept { return !std::holds_alternative<NoValue>(var); }
    void reset() { var.emplace<NoValue>(); }

    const QByteArray * byteArray() const noexcept { return std::get_if<QBA>(&var); }

    const DSProof * dsproof() const noexcept {
        auto *pdsp = std::get_if<DSP>(&var);
        return pdsp ? pdsp->get() : nullptr;
    }

    std::optional<BlockHeight> blockHeight() const noexcept {
        if (auto *p = std::get_if<BH>(&var); p && isValidBlockHeight(*p))
            return static_cast<BlockHeight>(*p);
        return std::nullopt;
    }

    /// Render this for JSON RPC (as a status result for notifications).  If !has_value() then it will be null,
    /// otherwise if it has a valid value it will be rendered as a string, or a dsproof object, or a number.
    /// Note that even if has_value(), this may still be a QVariant() (null).
    QVariant toVariant() const;
};

/// Specialization of std::hash so we can use SubStatus with std::unordered_map, std::unordered_set, etc
template <> struct std::hash<SubStatus> {
    std::size_t operator()(const SubStatus &s) const {
        if (auto *ba = s.byteArray(); ba) return HashHasher{}(*ba);
        else if (auto *dsp = s.dsproof(); dsp) return DspHash::Hasher{}(dsp->hash);
        else if (auto bh = s.blockHeight(); bh) return Util::hashForStd(*bh);
        return 0; // !this->has_value() and/or !bh->has_value() hashes to 0 always
    }
};

Q_DECLARE_METATYPE(SubStatus);
