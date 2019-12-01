#include "BTC.h"
#include "HashX.h"
#include "Util.h"

#include "bitcoin/uint256.h"

#include <cassert>

// Note: fromRawData is a cheap copy (shallow copy pointing to the same data as cs), which is ok since
// it's just an rvalue temporary.
HashX::HashX(const bitcoin::CScript &cs)
    : QByteArray(BTC::HashRev(QByteArray::fromRawData(reinterpret_cast<const char *>(cs.data()), int(cs.size())), true))
{
    assert(length() == bitcoin::uint256::width());
}

/*static*/
HashX HashX::fromCScript(const bitcoin::CScript &cs) { return HashX(cs); }
/*static*/
HashX HashX::fromHexFast(const QByteArray &definitelyHexData) { return HashX(Util::ParseHexFast(definitelyHexData)); }

QByteArray HashX::toHex() const {  return Util::ToHexFast(*this); }

auto HashX::operator=(const bitcoin::CScript &cs) -> HashX &
{
    *this = HashX(cs);
    return *this;
}

bool HashX::operator==(const HashX &o) const { return QByteArray::operator==(o); }
