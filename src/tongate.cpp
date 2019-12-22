#include "adnl/adnl-ext-client.h"
#include "adnl/adnl-ext-connection.hpp"
#include "adnl/adnl-peer-table.h"
#include "ton/ton-types.h"
#include "ton/ton-tl.hpp"
#include "ton/ton-io.hpp"
#include "common/errorlog.h"
#include "crypto/vm/cp0.h"
#include "td/utils/filesystem.h"
#include "td/utils/overloaded.h"
#include "td/utils/OptionsParser.h"
#include "td/utils/port/path.h"
#include "td/utils/port/signals.h"
#include "td/utils/port/user.h"
#include "td/utils/port/rlimit.h"
#include "td/utils/ThreadSafeCounter.h"
#include "td/utils/TsFileLog.h"
#include "td/utils/Random.h"
#include "td/net/UdpServer.h"
#include "auto/tl/lite_api.h"
#include "dht/dht.hpp"
#include "overlay/overlays.h"
#include "overlay/overlay.hpp"

#include "server.h"

#if TD_DARWIN || TD_LINUX
#include <unistd.h>
#endif
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <set>

int main(int argc, char *argv[]) {
  SET_VERBOSITY_LEVEL(verbosity_DEBUG + 42);
  td::set_default_failure_signal_handler().ensure();

  td::unique_ptr<td::LogInterface> logger_;
  SCOPE_EXIT {
    td::log_interface = td::default_log_interface;
  };
  td::OptionsParser p;
  std::vector<std::function<void()>> acts;
  td::uint32 threads = 4;
  td::actor::ActorOwn<TonGateServer> x;

  p.set_description("Gate to the TON network");

  //
  // Common options
  //
  p.add_option('v', "verbosity", "set verbosity level", [&](td::Slice arg) {
    int v = VERBOSITY_NAME(FATAL) + (td::to_integer<int>(arg));
    SET_VERBOSITY_LEVEL(v);
    return td::Status::OK();
  });
  p.add_option('h', "help", "prints_help", [&]() {
    char b[10240];
    td::StringBuilder sb(td::MutableSlice{b, 10000});
    sb << p;
    std::cout << sb.as_cslice().c_str();
    std::exit(2);
    return td::Status::OK();
  });
  p.add_option('C', "global-config", "file to read global config", [&](td::Slice fname) {
    acts.push_back([&x, fname = fname.str()]() {
          td::actor::send_closure(x, &TonGateServer::set_global_config, fname);
        });
    return td::Status::OK();
  });
  p.add_option('D', "db", "root for dbs", [&](td::Slice fname) {
    acts.push_back([&x, fname = fname.str()]() { td::actor::send_closure(x, &TonGateServer::set_db_root, fname); });
    return td::Status::OK();
  });
  p.add_option('l', "logname", "log to file", [&](td::Slice fname) {
    logger_ = td::TsFileLog::create(fname.str()).move_as_ok();
    td::log_interface = logger_.get();
    return td::Status::OK();
  });
  p.add_option('t', "threads", PSTRING() << "number of threads (default=" << threads << ")", [&](td::Slice fname) {
    td::int32 v;
    try {
      v = std::stoi(fname.str());
    } catch (...) {
      return td::Status::Error(ton::ErrorCode::error, "bad value for --threads: not a number");
    }
    if (v < 1 || v > 256) {
      return td::Status::Error(ton::ErrorCode::error, "bad value for --threads: should be in range [1..256]");
    }
    threads = v;
    return td::Status::OK();
  });

  //
  // Operation mode
  //
  p.add_option('a', "advertise", "advertise ip:port as public address", [&](td::Slice arg) {
    td::IPAddress addr;
    TRY_STATUS(addr.init_host_port(arg.str()));
    acts.push_back([&x, addr]() { td::actor::send_closure(x, &TonGateServer::set_advertised_addr, addr); });
    return td::Status::OK();
  });
  p.add_option('s', "server", "start server at advertised address", [&]() {
    acts.push_back([&x]() { td::actor::send_closure(x, &TonGateServer::toggle_server); });
    return td::Status::OK();
  });
  p.add_option('c', "client", "start SOCKS5 gate client at ip:port", [&](td::Slice arg) {
    td::IPAddress addr;
    TRY_STATUS(addr.init_host_port(arg.str()));
    acts.push_back([&x, addr]() { td::actor::send_closure(x, &TonGateServer::set_socks_addr, addr); });
    return td::Status::OK();
  });
  // p.add_option('T', "tun", "capture packets on TUN virtual interface", [&](td::Slice arg) {
  //   acts.push_back([&x]() { td::actor::send_closure(x, &TonGate::add_tun); });
  //   return td::Status::OK();
  // });
  p.add_option('p', "ping", "ping given pubkey via ADNL", [&](td::Slice arg) {
    TRY_RESULT_PREFIX(dst_pub_slice, td::base64_decode(arg), "ADNL pubkey base64 decode failed:");
    TRY_RESULT_PREFIX(dst_pub, ton::PublicKey::import(dst_pub_slice), "ADNL pubkey import failed:");
    auto dest_id = ton::adnl::AdnlNodeIdShort{dst_pub.compute_short_id()};
    acts.push_back([&x, dest_id]() { td::actor::send_closure(x, &TonGateServer::set_ping_dest, dest_id); });
    return td::Status::OK();
  });
  p.add_option('L', "lookup", "lookup available entry points", [&]() {
    acts.push_back([&x]() { td::actor::send_closure(x, &TonGateServer::toggle_discovery); });
    return td::Status::OK();
  });

  auto S = p.run(argc, argv);
  if (S.is_error()) {
    LOG(ERROR) << "failed to parse options: " << S.move_as_error();
    std::_Exit(2);
  }

  td::actor::Scheduler scheduler({threads});
  scheduler.run_in_context([&] {
    x = td::actor::create_actor<TonGateServer>("ton-gate");
    for (auto &act : acts) {
      act();
    }
    acts.clear();
    td::actor::send_closure(x, &TonGateServer::run);
  });
  scheduler.run();

  return 0;
}
