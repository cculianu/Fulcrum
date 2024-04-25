
target_sources(Fulcrum PRIVATE
    AbstractConnection.cpp
    App.cpp
    BTC.cpp
    BTC_Address.cpp
    BitcoinD.cpp
    BitcoinD_RPCInfo.cpp
    BlockProc.cpp
    CityHash.cpp
    CoTask.cpp
    Common.cpp
    Controller.cpp
    Controller_SynchDSPsTask.cpp
    Controller_SynchMempoolTask.cpp
    DSProof.cpp
    Logger.cpp
    Mempool.cpp
    Merkle.cpp
    Mgr.cpp
    Mixins.cpp
    Options.cpp
    PackedNumView.cpp
    PeerMgr.cpp
    RPC.cpp
    RPCMsgId.cpp
    RecordFile.cpp
    RollingBloomFilter.cpp
    Rpa.cpp
    SSLCertMonitor.cpp
    ServerMisc.cpp
    Servers.cpp
    SrvMgr.cpp
    Storage.cpp
    SubStatus.cpp
    SubsMgr.cpp
    TXO.cpp
    ThreadPool.cpp
    Util.cpp
    VarInt.cpp
    Version.cpp
    WebSocket.cpp
    ZmqSubNotifier.cpp
    main.cpp
    register_MetaTypes.cpp
)

target_include_directories(Fulcrum PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(bitcoin)
add_subdirectory(Json)
