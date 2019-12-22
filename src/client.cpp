#include "adnl/adnl-ext-client.h"
#include "adnl/adnl-ext-connection.hpp"
#include "adnl/adnl-ext-client.hpp"
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

#include "tunnel-client.hpp"

#if TD_DARWIN || TD_LINUX
#include <unistd.h>
#endif
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <set>

class TonGateClient : public td::actor::Actor {

public:
  void set_server_addr(td::IPAddress ipaddr) {
    server_ipaddr_ = ipaddr;
  }
  void set_server_public(ton::PublicKey public_key) {
    server_public_key_ = public_key;
  }
  void set_socks_addr(td::IPAddress ipaddr) {
    server_socks_ipaddr_ = ipaddr;
  }

  void run() {

    // class Callback : public ton::adnl::AdnlExtClient::Callback {
    //  public:
    //   void on_ready() override {
    //     // td::actor::send_closure(id_, &TonGateClient::conn_ready);
    //   }
    //   void on_stop_ready() override {
    //     // td::actor::send_closure(id_, &TonGateClient::conn_closed);
    //   }
    //   Callback(td::actor::ActorId<TonGateClient> id) : id_(std::move(id)) {
    //   }
    //  private:
    //   td::actor::ActorId<TonGateClient> id_;
    // };

    // client_ = ton::adnl::AdnlExtClient::create(ton::adnl::AdnlNodeIdFull{server_public_key_},
    //                                            server_ipaddr_,
    //                                            std::make_unique<Callback>(actor_id(this)));


    class Callback : public ton::adnl::TunnelClient::Callback {
     public:
      void on_ready() override {
        // td::actor::send_closure(id_, &TonGateClient::conn_ready);
      }
      void on_stop_ready() override {
        // td::actor::send_closure(id_, &TonGateClient::conn_closed);
      }
      Callback(td::actor::ActorId<TonGateClient> id) : id_(std::move(id)) {
      }
     private:
      td::actor::ActorId<TonGateClient> id_;
    };

    client_ = td::actor::create_actor<ton::adnl::TunnelClient>(
                                               "tunnel-client",
                                               ton::adnl::AdnlNodeIdFull{server_public_key_},
                                               server_ipaddr_,
                                               std::make_unique<Callback>(actor_id(this)));

    alarm_timestamp() = td::Timestamp::in(1.0 + td::Random::fast(0, 100) * 0.01);
  }

  void alarm() {

    auto b = td::BufferSlice("ext:Ahoy!");
    // auto P =
    //     td::PromiseCreator::lambda([](td::Result<td::BufferSlice> R) {
    //       if (R.is_ok()) {
    //         auto data = R.move_as_ok();
    //         std::cout << "got response: ";
    //         std::cout.write(data.as_slice().data(), data.size());
    //         std::cout << std::endl;
    //       } else {
    //         std::cout << "oops!" << std:: endl;
    //       }
    //     });

    td::actor::send_closure(client_, &ton::adnl::TunnelClient::send, std::move(b));
  }



private:
  ton::PublicKey server_public_key_;
  td::IPAddress server_ipaddr_;
  td::IPAddress server_socks_ipaddr_;
  td::actor::ActorOwn<ton::adnl::TunnelClient> client_;

};


int main(int argc, char *argv[]) {
  SET_VERBOSITY_LEVEL(verbosity_INFO);
  td::set_default_failure_signal_handler().ensure();

  td::unique_ptr<td::LogInterface> logger_;
  SCOPE_EXIT {
    td::log_interface = td::default_log_interface;
  };
  td::OptionsParser p;
  std::vector<std::function<void()>> acts;
  td::uint32 threads = 4;
  td::actor::ActorOwn<TonGateClient> tgc;

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
  // p.add_option('C', "global-config", "file to read global config", [&](td::Slice fname) {
  //   acts.push_back([&tgc, fname = fname.str()]() {
  //         td::actor::send_closure(tgc, &TonGate::set_global_config, fname);
  //       });
  //   return td::Status::OK();
  // });
  // p.add_option('D', "db", "root for dbs", [&](td::Slice fname) {
  //   acts.push_back([&tgc, fname = fname.str()]() { td::actor::send_closure(tgc, &TonGateClient::set_db_root, fname); });
  //   return td::Status::OK();
  // });
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
  p.add_option('c', "connect", "connect to server at ip:port", [&](td::Slice arg) {
    td::IPAddress addr;
    TRY_STATUS(addr.init_host_port(arg.str()));
    acts.push_back([&tgc, addr]() { td::actor::send_closure(tgc, &TonGateClient::set_server_addr, addr); });
    return td::Status::OK();
  });
  p.add_option('p', "public", "server public key", [&](td::Slice arg) {
    TRY_RESULT_PREFIX(dst_pub_slice, td::base64_decode(arg), "ADNL pubkey base64 decode failed:");
    TRY_RESULT_PREFIX(dst_pub, ton::PublicKey::import(dst_pub_slice), "ADNL pubkey import failed:");
    // auto dest_id = ton::adnl::AdnlNodeIdShort{dst_pub.compute_short_id()};
    acts.push_back([&tgc, dst_pub]() { td::actor::send_closure(tgc, &TonGateClient::set_server_public, dst_pub); });
    return td::Status::OK();
  });
  p.add_option('s', "socks", "start SOCKS5 at ip:port", [&](td::Slice arg) {
    td::IPAddress addr;
    TRY_STATUS(addr.init_host_port(arg.str()));
    acts.push_back([&tgc, addr]() { td::actor::send_closure(tgc, &TonGateClient::set_socks_addr, addr); });
    return td::Status::OK();
  });

  auto S = p.run(argc, argv);
  if (S.is_error()) {
    LOG(ERROR) << "failed to parse options: " << S.move_as_error();
    std::_Exit(2);
  }

  td::actor::Scheduler scheduler({threads});
  scheduler.run_in_context([&] {
    tgc = td::actor::create_actor<TonGateClient>("ton-gate-client");
    for (auto &act : acts) {
      act();
    }
    acts.clear();
    td::actor::send_closure(tgc, &TonGateClient::run);
  });
  scheduler.run();

  return 0;
}
