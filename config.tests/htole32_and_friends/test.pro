SOURCES = main.cpp
versionAtLeast(QT_VERSION, 6.5.0) {
    CONFIG += c++20
} else {
    # Old alias for C++20 was "c++2a"
    CONFIG += c++2a
}
