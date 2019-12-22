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

// #include "tongate.h"

#if TD_DARWIN || TD_LINUX
#include <unistd.h>
#endif
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <set>


namespace ton {
namespace adnl {

class TunnelClient;


class TunnelOutboundConnection : public AdnlExtConnection {

 public:
  class MsgCallback {
   public:
    virtual ~MsgCallback() = default;
    virtual void on_message(td::BufferSlice data) = 0;
  };

  TunnelOutboundConnection(td::SocketFd fd,
                           std::unique_ptr<AdnlExtConnection::Callback> callback,
                           std::unique_ptr<MsgCallback> message_cb,
                           AdnlNodeIdFull dst,
                           td::actor::ActorId<TunnelClient> ext_client)
      : AdnlExtConnection(std::move(fd), std::move(callback), true)
      , message_cb_(std::move(message_cb))
      , dst_(std::move(dst))
      , ext_client_(ext_client) {
  }

  void start_up() override {
    AdnlExtConnection::start_up();
    auto X = dst_.pubkey().create_encryptor();
    if (X.is_error()) {
      LOG(ERROR) << "failed to init encryptor: " << X.move_as_error();
      stop();
      return;
    }
    auto enc = X.move_as_ok();

    td::BufferSlice d{256};
    auto id = dst_.compute_short_id();
    auto S = d.as_slice();
    S.copy_from(id.as_slice());
    S.remove_prefix(32);
    S.truncate(256 - 64 - 32);
    td::Random::secure_bytes(S);
    init_crypto(S);

    auto R = enc->encrypt(S);
    if (R.is_error()) {
      LOG(ERROR) << "failed to  encrypt: " << R.move_as_error();
      stop();
      return;
    }
    auto data = R.move_as_ok();
    LOG_CHECK(data.size() == 256 - 32) << "size=" << data.size();
    S = d.as_slice();
    S.remove_prefix(32);
    CHECK(S.size() == data.size());
    S.copy_from(data.as_slice());

    send_uninit(std::move(d));
  }

  td::Status process_packet(td::BufferSlice data) override {
    message_cb_->on_message(std::move(data));
    return td::Status::OK();
  }

  td::Status process_init_packet(td::BufferSlice data) override {
    UNREACHABLE();
  }

  td::Status process_custom_packet(td::BufferSlice &data, bool &processed) override {
    if (data.size() == 12) {
      auto F = fetch_tl_object<ton_api::tcp_pong>(data.clone(), true);
      if (F.is_ok()) {
        processed = true;
        return td::Status::OK();
      }
    }
    return td::Status::OK();
  }

 private:
  AdnlNodeIdFull dst_;
  PrivateKey local_id_;
  td::actor::ActorId<TunnelClient> ext_client_;
  td::SecureString nonce_;
  bool authorization_complete_ = false;
  std::unique_ptr<MsgCallback> message_cb_;

};



class TunnelClient : public td::actor::Actor {
 public:
  class Callback {
   public:
    virtual ~Callback() = default;
    virtual void on_ready() = 0;
    virtual void on_stop_ready() = 0;
  };

  TunnelClient(AdnlNodeIdFull dst_id, td::IPAddress dst_addr, std::unique_ptr<Callback> callback)
      : dst_(std::move(dst_id)), dst_addr_(dst_addr), callback_(std::move(callback)) {
  }

  void start_up() override {
    alarm();
  }

  void conn_stopped(td::actor::ActorId<AdnlExtConnection> conn) {
    if (!conn_.empty() && conn_.get() == conn) {
      callback_->on_stop_ready();
      conn_ = {};
      alarm_timestamp() = next_create_at_;
      try_stop();
    }
  }

  void conn_ready(td::actor::ActorId<AdnlExtConnection> conn) {
    if (!conn_.empty() && conn_.get() == conn) {
      callback_->on_ready();
    }
  }

  void check_ready(td::Promise<td::Unit> promise) {
    if (conn_.empty() || !conn_.is_alive()) {
      promise.set_error(td::Status::Error(ErrorCode::notready, "not ready"));
      return;
    }
    td::actor::send_closure(td::actor::ActorId<AdnlExtConnection>{conn_.get()}, &AdnlExtConnection::check_ready_async,
                            std::move(promise));
  };

  void send_query(std::string name, td::BufferSlice data, td::Timestamp timeout,
                  td::Promise<td::BufferSlice> promise) {
    auto P = [SelfId = actor_id(this)](AdnlQueryId id) {
      td::actor::send_closure(SelfId, &TunnelClient::destroy_query, id);
    };
    auto q_id = generate_next_query_id();
    out_queries_.emplace(q_id, AdnlQuery::create(std::move(promise), std::move(P), name, timeout, q_id));
    if (!conn_.empty()) {
      auto obj = create_tl_object<lite_api::adnl_message_query>(q_id, std::move(data));
      td::actor::send_closure(conn_, &TunnelOutboundConnection::send, serialize_tl_object(obj, true));
    }
  }

  void send(td::BufferSlice data) {
    td::actor::send_closure(conn_, &TunnelOutboundConnection::send, std::move(data));
  }

  void destroy_query(AdnlQueryId id) {
    out_queries_.erase(id);
    try_stop();
  }

  void answer_query(AdnlQueryId id, td::BufferSlice data) {
    auto it = out_queries_.find(id);
    if (it != out_queries_.end()) {
      td::actor::send_closure(it->second, &AdnlQuery::result, std::move(data));
    }
  }

  void alarm() override {
    if (is_closing_) {
      return;
    }
    if (conn_.empty() || !conn_.is_alive()) {
      next_create_at_ = td::Timestamp::in(10.0);
      alarm_timestamp() = next_create_at_;

      auto fd = td::SocketFd::open(dst_addr_);
      if (fd.is_error()) {
        LOG(INFO) << "failed to connect to " << dst_addr_ << ": " << fd.move_as_error();
        return;
      }

      class Cb : public AdnlExtConnection::Callback {
      private:
        td::actor::ActorId<TunnelClient> id_;
      public:
        void on_ready(td::actor::ActorId<AdnlExtConnection> conn) {
          td::actor::send_closure(id_, &TunnelClient::conn_ready, conn);
        }
        void on_close(td::actor::ActorId<AdnlExtConnection> conn) {
          td::actor::send_closure(id_, &TunnelClient::conn_stopped, conn);
        }
        Cb(td::actor::ActorId<TunnelClient> id) : id_(id) {
        }
      };

      class MCb : public TunnelOutboundConnection::MsgCallback {
      public:
        void on_message(td::BufferSlice data) {
          std::cout << "MCb on_message" << std::endl;
          // td::actor::send_closure(id_, &TunnelClient::conn_ready, conn);
        }
      };

      conn_ = td::actor::create_actor<TunnelOutboundConnection>(td::actor::ActorOptions().with_name("outconn").with_poll(),
                                                              fd.move_as_ok(),
                                                              std::make_unique<Cb>(actor_id(this)),
                                                              std::make_unique<MCb>(),
                                                              dst_,
                                                              actor_id(this));
    }
  }

  void hangup() override {
    conn_ = {};
    is_closing_ = true;
    ref_cnt_--;
    for (auto &it : out_queries_) {
      td::actor::ActorOwn<>(it.second);  // send hangup
    }
    try_stop();
  }

  AdnlQueryId generate_next_query_id() {
    while (true) {
      AdnlQueryId q_id = AdnlQuery::random_query_id();
      if (out_queries_.count(q_id) == 0) {
        return q_id;
      }
    }
  }

 private:
  AdnlNodeIdFull dst_;
  PrivateKey local_id_;
  td::IPAddress dst_addr_;

  std::unique_ptr<Callback> callback_;

  td::actor::ActorOwn<TunnelOutboundConnection> conn_;
  td::Timestamp next_create_at_ = td::Timestamp::now_cached();

  std::map<AdnlQueryId, td::actor::ActorId<AdnlQuery>> out_queries_;

  bool is_closing_{false};
  td::uint32 ref_cnt_{1};

  void try_stop() {
    if (is_closing_ && ref_cnt_ == 0 && out_queries_.empty()) {
      stop();
    }
  }
};


}  // namespace adnl
}  // namespace ton




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
