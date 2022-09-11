// Copyright (c) 2022 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "utilstring.h"

namespace bitcoin {

[[nodiscard]] std::string TrimString(const std::string &str, const std::string &pattern) {
    std::string::size_type front = str.find_first_not_of(pattern);
    if (front == std::string::npos) {
        return std::string();
    }
    std::string::size_type end = str.find_last_not_of(pattern);
    return str.substr(front, end - front + 1);
}

std::string Join(const std::vector<std::string> &list, const std::string &separator) {
    return Join(list, separator, [](const std::string &i) { return i; });
}

void ReplaceAll(std::string &input, std::string const &search, std::string const &format) {
    if (search.empty()) return; // an empty string will always match in string::find - we don't want that
    for (size_t pos = input.find(search); pos != std::string::npos; pos = input.find(search, pos + format.length())) {
        input.replace(pos, search.length(), format);
    }
}

[[nodiscard]] bool ValidAsCString(const std::string &str) noexcept {
    return str.find_first_of('\0') == std::string::npos;
}

} // namespace bitcoin
