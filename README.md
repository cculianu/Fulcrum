# Shuffle Up Server
#### Author: Calin Culianu (<calin`.`culianu __ at __ gmail __**.**__ com>)

A fast shuffling server for use with Electron Cash's future "shuffle up" feature (which we haven't properly figured out a name for as yet), written in C++.

### Highlights and design goals:

- *Speed:* Server is 100% modern C++ code using multi-threaded programming techniques.
- *Flexibility:* We want to be able to modify the shuffling logic and add levels of trustlessness as we develop advanced shuffling techniques involving potentially hundreds of inputs.  As such, the server's core kernel which handles communication should be decoupled from the other parts that higher level shuffle logic.  (So far, so good.)

### Requirements

- Qt Core & Qt Networking libraries 5.11 or above (I use 5.12.3 myself).
- A modern `C++17` compiler.  `Clang` is recommended but `G++` also works.
- No other external dependencies.  All crypto functions use code imported from Bitcoin-ABC (such as `secp256k1`, etc).

### How To Compile

It's recommended you use Qt Creator.

1. Get the latest version of Qt for your platform.
2. Point the Qt Creator IDE at the `ShuffleUpServer.pro` file.
3. Hit Build.  It should "just work".

---

### Platform Notes

#### Big Endian Architectures

The code is more or less configured to assume a "little endian" architecture by default (which is what all Intel x86/x86_64 are).  If you're on a big endian machine, on Linux it should just auto-detect that fact.  However, on other OS's such as BSD, if you're on a big endian machine, you may need to uncomment this line from the `.pro` file:

    # DEFINES += WORDS_BIGENDIAN


#### Windows

I couldn't easily get MSVC versions before 2019 to actually accept legal C++17.  As such, if you're using Qt Creator on Windows -- it's recommended you select `MinGW` and/or `G++` as the compiler (which comes with the Qt distribution for Windows).

#### Linux

If you have `clang` on your system, configure the project to use it as the compiler preferentially over `G++`.  `G++` works too, but `clang` is preferred because reasons.

#### MacOS

Everything should just work (I use MacOS as my dev machine, so that's why).

---

### F.A.Q.

<br/>

**Q:** This thing isn't finished yet!

**A:** Yes, I know  It's still a work in progress.

<br/>

**Q:** Why Qt?  This isn't a GUI app!

**A:** Yes, I know.  However, Qt is a very decent, cross-platform and fast application framework.  You can use its "Core" library for console apps, servers, etc.  It has great network support and other basic things a programmer needs to get stuff done.

<br/>

---

### Donations

Sure!  Send BCH here:

[bitcoincash:qphax4s4n9h60jxj2fkrjs35w2tvgd4wzvf52cgtzc](bitcoincash:qphax4s4n9h60jxj2fkrjs35w2tvgd4wzvf52cgtzc)

[![bitcoincash:qphax4s4n9h60jxj2fkrjs35w2tvgd4wzvf52cgtzc](https://raw.githubusercontent.com/cculianu/DonateSpareChange/master/donate.png)](bitcoincash:qphax4s4n9h60jxj2fkrjs35w2tvgd4wzvf52cgtzc)
