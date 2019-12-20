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

#include "tongate.h"

#if TD_DARWIN || TD_LINUX
#include <unistd.h>
#endif
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <set>


// XXX: change to get_ip_str()
static std::string Ip4String(std::int32_t num)
{
  char buf[20];
  unsigned char addr[4];
  addr[3] = 0xFF & num;
  addr[2] = 0xFF & (num >> 8);
  addr[1] = 0xFF & (num >> 16);
  addr[0] = 0xFF & (num >> 24);
  snprintf(buf, sizeof(buf),"%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
  return std::string(buf);
}

/*
 * NAT traversal.
 */

void IdentityListener::start_up() {

  std::cout << "IdentityListener" << std::endl;

  class Callback : public td::UdpServer::Callback {
   public:
    Callback(td::actor::ActorId<TonGate> tongate, td::actor::ActorShared<IdentityListener> udp_server) :
      tongate_(std::move(tongate)),
      udp_server_(std::move(udp_server)){
    }

   private:
    td::actor::ActorId<TonGate> tongate_;
    td::actor::ActorShared<IdentityListener> udp_server_;

    void on_udp_message(td::UdpMessage udp_message) override {
      auto R = ton::PublicKey::import(udp_message.data);
      R.ensure();
      auto pub = R.move_as_ok();

      std::cout
        << "got identity from "
        << udp_message.address.get_ip_str().str() << ":"
        << udp_message.address.get_port() << " "
        << td::base64_encode(pub.export_as_slice().as_slice())
        << std::endl;

      td::actor::send_closure(tongate_, &TonGate::add_peer, pub, udp_message.address);
      udp_message.data = td::BufferSlice("ok");
      td::actor::send_closure(udp_server_, &IdentityListener::respond, std::move(udp_message));
    }
  };

  auto X = td::UdpServer::create("IdentityListener udp server", port_, std::make_unique<Callback>(tongate_, actor_shared(this)));
  X.ensure();
  in_udp_server_ = X.move_as_ok();
}

void IdentityListener::respond(td::UdpMessage message) {
  td::actor::send_closure(in_udp_server_, &td::UdpServer::send, std::move(message));
}

/*
 * Connection
 */


void TonGate::send_identity() {
  class Callback : public td::UdpServer::Callback {
   public:
    Callback(){
    }

   private:

    void on_udp_message(td::UdpMessage udp_message) override {
      std::cout
        << udp_message.address.get_ip_str().str()
        << ":" << udp_message.address.get_port()
        << " " << udp_message.data.data()
        << std::endl;
    }
  };

  auto X = td::UdpServer::create("udp server", 50042, std::make_unique<Callback>());
  X.ensure();
  udp_client_ = X.move_as_ok();

  td::UdpMessage message;
  td::IPAddress dest_ip;
  dest_ip.init_ipv4_port(advertised_ip_addr_.get_ip_str().str(), advertised_ip_addr_.get_port() + 1);
  message.address = dest_ip;
  message.data = std::move(adnl_full_.pubkey().export_as_slice());
  td::actor::send_closure(udp_client_, &td::UdpServer::send, std::move(message));
}

/*
 * Command-line option setters
 */

void TonGate::set_global_config(std::string str) {
  global_config_ = str;
}

void TonGate::set_db_root(std::string db_root) {
  db_root_ = db_root;
}

void TonGate::toggle_server() {
  toggle_server_ = true;
}

void TonGate::set_advertised_addr(td::IPAddress server_addr) {
  advertised_ip_addr_ = server_addr;
}

void TonGate::toggle_discovery() {
  toggle_discovery_ = true;
}

void TonGate::set_socks_addr(td::IPAddress socks_addr) {
  socks_ip_addr_ = socks_addr;
}

void TonGate::set_ping_dest(ton::adnl::AdnlNodeIdShort ping_dest_id) {
  ping_dest_id_ = ping_dest_id;
}

/*
 * Boot sequence
 */

void TonGate::start_up() {
  // alarm_timestamp() = td::Timestamp::in(1.0 + td::Random::fast(0, 100) * 0.01);
}

void TonGate::run() {
  td::mkdir(db_root_).ensure();
  td::mkdir(db_root_ + "/logs").ensure();
  td::mkdir(db_root_ + "/keys").ensure();
  ton::errorlog::ErrorLog::create(db_root_ + "/logs");

  auto Sr = load_global_config();
  if (Sr.is_error()) {
    LOG(ERROR) << "failed to load global config'" << global_config_ << "': " << Sr;
    std::_Exit(2);
  }

  keyring_ = ton::keyring::Keyring::create(db_root_ + "/keyring");

  // start ADNL
  adnl_network_manager_ = ton::adnl::AdnlNetworkManager::create(static_cast<td::uint16>(advertised_ip_addr_.get_port()));
  adnl_ = ton::adnl::Adnl::create(db_root_, keyring_.get());
  td::actor::send_closure(adnl_network_manager_, &ton::adnl::AdnlNetworkManager::add_self_addr, advertised_ip_addr_, 0);
  td::actor::send_closure(adnl_, &ton::adnl::Adnl::register_network_manager, adnl_network_manager_.get());

  // add source addr id
  ton::PrivateKey adnl_pk = load_or_create_key("adnl");
  ton::PublicKey adnl_pub = adnl_pk.compute_public_key();
  add_adnl_addr(adnl_pub, advertised_ip_addr_);
  adnl_id_ = ton::adnl::AdnlNodeIdShort{adnl_pub.compute_short_id()};
  adnl_full_ = ton::adnl::AdnlNodeIdFull{adnl_pub};

  // start DHT
  ton::PrivateKey dht_pk = load_or_create_key("dht");
  ton::PublicKey dht_pub = dht_pk.compute_public_key();
  ton::PublicKeyHash dht_id = dht_pk.compute_short_id();
  add_adnl_addr(dht_pub, advertised_ip_addr_);

  auto D = ton::dht::Dht::create(ton::adnl::AdnlNodeIdShort{dht_id}, db_root_, dht_config_, keyring_.get(), adnl_.get());
  D.ensure();
  dht_node_ = D.move_as_ok();
  td::actor::send_closure(adnl_, &ton::adnl::Adnl::register_dht_node, dht_node_.get());

  if (toggle_server_) {
    // subscribe(adnl_pub, "H");

    // start overlays
    overlay_manager_ = ton::overlay::Overlays::create(db_root_, keyring_.get(), adnl_.get(), dht_node_.get());

    create_overlay();

    idl_ = td::actor::create_actor<IdentityListener>("IdentityListener",
            advertised_ip_addr_.get_port() + 1, actor_id(this));
  } else {

    send_identity();
  }

  alarm_timestamp() = td::Timestamp::in(1.0 + td::Random::fast(0, 100) * 0.01);
}

void TonGate::do_discovery() {
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<ton::dht::DhtValue> res) {
    if (res.is_ok()) {
      auto v = res.move_as_ok();
      auto R = ton::fetch_tl_object<ton::ton_api::overlay_nodes>(v.value().clone(), true);
      if (R.is_ok()) {
        auto r = R.move_as_ok();
        // std::cout << ": received " << r->nodes_.size() << " nodes from overlay" << std::endl;
        // std::cout << ": nodes: " << ton::ton_api::to_string(r) << std::endl;
        std::vector<ton::overlay::OverlayNode> nodes;
        for (auto &n : r->nodes_) {
          auto N = ton::overlay::OverlayNode::create(n);
          if (N.is_ok()) {
            auto curr_node = N.move_as_ok();
            // std::cout << "got node:  " 
              // << td::base64_encode(curr_node.adnl_id_full().pubkey().export_as_slice().as_slice())
              // << std::endl;

            td::actor::send_closure(SelfId, &TonGate::adnl_to_ip, curr_node.adnl_id_full());
          }
        }
      } else {
        std::cout << ": incorrect value in DHT for overlay nodes: " << R.move_as_error().to_string() << std::endl;
      }
    } else {
      std::cout << ": can not get value from DHT: " << res.move_as_error().to_string() << std::endl;
    }
  });


  auto n = td::BufferSlice("ProxyOffers");
  auto overlay_id_full = ton::overlay::OverlayIdFull{std::move(n)};
  auto overlay_id = overlay_id_full.compute_short_id();
  td::actor::send_closure(dht_node_.get(),
                          &ton::dht::Dht::get_value,
                          ton::dht::DhtKey{overlay_id.pubkey_hash(), "nodes", 0},
                          std::move(P));
}

void TonGate::adnl_to_ip(ton::adnl::AdnlNodeIdFull adnl_id) {

  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this),
                                       adnl_id = adnl_id](td::Result<ton::dht::DhtValue> kv) {
    if (kv.is_error()) {
      std::cout << "failed to get from dht: " << kv.move_as_error().to_string() << std::endl;
      return;
    }
    auto k = kv.move_as_ok();
    auto pub = ton::adnl::AdnlNodeIdFull{k.key().public_key()};
    CHECK(pub.compute_short_id() == adnl_id.compute_short_id());

    auto F = ton::fetch_tl_object<ton::ton_api::adnl_addressList>(k.value().clone(), true);
    if (F.is_error()) {
      std::cout << "bad dht value: " << kv.move_as_error().to_string() << std::endl;
      return;
    }
    auto addr_list = F.move_as_ok();
    for (auto &addr : addr_list->addrs_) {
      ton::ton_api::downcast_call(*const_cast<ton::ton_api::adnl_Address *>(addr.get()),
                                  td::overloaded(
                                      [&](const ton::ton_api::adnl_address_udp &obj) {
                                        std::cout << "Got addr: " << Ip4String(obj.ip_) << ":" << obj.port_ << std::endl;
                                      },
                                      [&](const ton::ton_api::adnl_address_udp6 &obj) {
                                        std::cout << "Got addr6: " << obj.ip_ << ":" << obj.port_ << std::endl;
                                      }));
    }
  });

  td::actor::send_closure(dht_node_, &ton::dht::Dht::get_value,
                          ton::dht::DhtKey{adnl_id.compute_short_id().pubkey_hash(), "address", 0},
                          std::move(P));

}

void TonGate::add_peer(ton::PublicKey dst_pub, td::IPAddress dst_ip) {
  auto tladdr = ton::create_tl_object<ton::ton_api::adnl_address_udp>(dst_ip.get_ipv4(), dst_ip.get_port());
  auto addr_vec = std::vector<ton::tl_object_ptr<ton::ton_api::adnl_Address>>();
  addr_vec.push_back(std::move(tladdr));
  auto tladdrlist = ton::create_tl_object<ton::ton_api::adnl_addressList>(
    std::move(addr_vec), ton::adnl::Adnl::adnl_start_time() - 1000, 0, 0, (int)td::Time::now() + 3600);
  auto addrlist = ton::adnl::AdnlAddressList::create(tladdrlist).move_as_ok();

  td::actor::send_closure(adnl_, &ton::adnl::Adnl::add_id, ton::adnl::AdnlNodeIdFull{dst_pub}, (addrlist));
  td::actor::send_closure(adnl_, &ton::adnl::Adnl::add_peer, adnl_id_, ton::adnl::AdnlNodeIdFull{dst_pub}, (addrlist));

  std::cout << "add_peer " << dst_ip.get_ip_str().str() << std::endl;
}

void TonGate::add_adnl_addr(ton::PublicKey pub, td::IPAddress ip_addr) {
    td::uint32 ts = static_cast<td::uint32>(td::Clocks::system());
    auto tladdr = ton::create_tl_object<ton::ton_api::adnl_address_udp>(ip_addr.get_ipv4(), ip_addr.get_port());
    auto addr_vec = std::vector<ton::tl_object_ptr<ton::ton_api::adnl_Address>>();
    addr_vec.push_back(std::move(tladdr));
    auto tladdrlist = ton::create_tl_object<ton::ton_api::adnl_addressList>(
          std::move(addr_vec), ts, ton::adnl::Adnl::adnl_start_time(), 0, 0);
    auto addrlist = ton::adnl::AdnlAddressList::create(tladdrlist).move_as_ok();
    td::actor::send_closure(adnl_, &ton::adnl::Adnl::add_id, ton::adnl::AdnlNodeIdFull{pub}, std::move(addrlist));
}

void TonGate::subscribe(ton::PublicKey dht_pub, std::string prefix) {

  class Callback : public ton::adnl::Adnl::Callback {
   public:
    void receive_message(ton::adnl::AdnlNodeIdShort src, ton::adnl::AdnlNodeIdShort dst, td::BufferSlice data) override {
        std::cout << "got message" << std::endl;
    }
    void receive_query(ton::adnl::AdnlNodeIdShort src, ton::adnl::AdnlNodeIdShort dst,
                       td::BufferSlice data,
                      td::Promise<td::BufferSlice> promise) override {
      TRY_RESULT_PROMISE_PREFIX(promise, f, ton::fetch_tl_object<ton::ton_api::adnl_ping>(std::move(data), true),
                                "adnl.ping expected");
      std::cout << "got query" << std::endl;
      promise.set_value(ton::create_serialize_tl_object<ton::ton_api::adnl_pong>(f->value_));
    }
    Callback() {
    }
  };

  td::actor::send_closure(adnl_, &ton::adnl::Adnl::subscribe, ton::adnl::AdnlNodeIdShort{dht_pub.compute_short_id()},
                          prefix,
                          std::make_unique<Callback>());
}


td::Status TonGate::load_global_config() {

  TRY_RESULT_PREFIX(conf_data, td::read_file(global_config_), "failed to read: ");
  TRY_RESULT_PREFIX(conf_json, td::json_decode(conf_data.as_slice()), "failed to parse json: ");

  ton::ton_api::config_global conf;
  TRY_STATUS_PREFIX(ton::ton_api::from_json(conf, conf_json.get_object()), "json does not fit TL scheme: ");

  if (!conf.dht_) {
    return td::Status::Error(ton::ErrorCode::error, "does not contain [dht] section");
  }

  TRY_RESULT_PREFIX(dht, ton::dht::Dht::create_global_config(std::move(conf.dht_)), "bad [dht] section: ");
  dht_config_ = std::move(dht);

  return td::Status::OK();
}

ton::PrivateKey TonGate::load_or_create_key(std::string name) {
  ton::PrivateKey pk;
  std::string keypath = db_root_ + "/keys/" + name;

  auto R = td::read_file_secure(keypath);
  if (R.is_ok()) {
    pk = ton::PrivateKey::import(R.move_as_ok()).move_as_ok();
  } else {
    pk = ton::privkeys::Ed25519::random();
    auto pub_key = pk.compute_public_key();
    td::write_file(keypath, pk.export_as_slice()).ensure();
    td::write_file(keypath + ".pub", pub_key.export_as_slice().as_slice()).ensure();
  }

  td::actor::send_closure(keyring_, &ton::keyring::Keyring::add_key, std::move(pk),
                          true, [](td::Unit) {});

  std::cout << name << " pubkey: "
            << td::base64_encode(pk.compute_public_key().export_as_slice().as_slice())
            << std::endl;

  return std::move(pk);
}

void TonGate::alarm() {
    std::cout << "send_ping alarm" << std::endl;
    if (!ping_dest_id_.is_zero()) {
      auto msg = td::BufferSlice("Hi!");
      td::actor::send_closure(adnl_, &ton::adnl::Adnl::send_message, adnl_id_, ping_dest_id_, std::move(msg));
      std::cout << "ping closure sent!" << std::endl;
    }

    if (toggle_discovery_) {
      do_discovery();
    }

    if (toggle_server_) {
      auto msg = td::BufferSlice("Look at me, i'm " + 
        std::to_string(advertised_ip_addr_.get_port()) + " " +
        std::to_string(td::Time::now()));
      td::actor::send_closure(overlay_manager_.get(), &ton::overlay::Overlays::send_broadcast_ex,
                            adnl_id_, overlay_id_, adnl_id_.pubkey_hash(), ton::overlay::Overlays::BroadcastFlagAnySender(),
                            std::move(msg));
    }

    alarm_timestamp() = td::Timestamp::in(1.0 + td::Random::fast(0, 100) * 0.01);
}

void TonGate::create_overlay() {
  auto n = td::BufferSlice("ProxyOffers");
  auto overlay_id_full = ton::overlay::OverlayIdFull{std::move(n)};
  overlay_id_ = overlay_id_full.compute_short_id();
  auto rules = ton::overlay::OverlayPrivacyRules{ton::overlay::Overlays::max_fec_broadcast_size()};

  class Callback : public ton::overlay::Overlays::Callback {
   public:
    void receive_message(ton::adnl::AdnlNodeIdShort src, ton::overlay::OverlayIdShort overlay_id, td::BufferSlice data) override {
      std::cout << "got overmessage" << std::endl;
    }
    void receive_query(ton::adnl::AdnlNodeIdShort src, ton::overlay::OverlayIdShort overlay_id, td::BufferSlice data,
                       td::Promise<td::BufferSlice> promise) override {
      std::cout << "got overquery" << std::endl;
    }
    void receive_broadcast(ton::PublicKeyHash src, ton::overlay::OverlayIdShort overlay_id, td::BufferSlice data) override {
      std::cout << "got overbroadcast: ";
      std::cout.write(data.as_slice().data(), data.size());
      std::cout << std::endl;
    }
    Callback(td::actor::ActorId<TonGate> node) : node_(node) {
    }
   private:
    td::actor::ActorId<TonGate> node_;
  };

  td::actor::send_closure(overlay_manager_.get(), &ton::overlay::Overlays::create_public_overlay,
                          adnl_id_, overlay_id_full.clone(),
                          std::make_unique<Callback>(actor_id(this)), rules);
}


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
  td::actor::ActorOwn<TonGate> x;

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
          td::actor::send_closure(x, &TonGate::set_global_config, fname);
        });
    return td::Status::OK();
  });
  p.add_option('D', "db", "root for dbs", [&](td::Slice fname) {
    acts.push_back([&x, fname = fname.str()]() { td::actor::send_closure(x, &TonGate::set_db_root, fname); });
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
    acts.push_back([&x, addr]() { td::actor::send_closure(x, &TonGate::set_advertised_addr, addr); });
    return td::Status::OK();
  });
  p.add_option('s', "server", "start server at advertised address", [&]() {
    acts.push_back([&x]() { td::actor::send_closure(x, &TonGate::toggle_server); });
    return td::Status::OK();
  });
  p.add_option('c', "client", "start SOCKS5 gate client at ip:port", [&](td::Slice arg) {
    td::IPAddress addr;
    TRY_STATUS(addr.init_host_port(arg.str()));
    acts.push_back([&x, addr]() { td::actor::send_closure(x, &TonGate::set_socks_addr, addr); });
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
    acts.push_back([&x, dest_id]() { td::actor::send_closure(x, &TonGate::set_ping_dest, dest_id); });
    return td::Status::OK();
  });
  p.add_option('L', "lookup", "lookup available entry points", [&]() {
    acts.push_back([&x]() { td::actor::send_closure(x, &TonGate::toggle_discovery); });
    return td::Status::OK();
  });

  auto S = p.run(argc, argv);
  if (S.is_error()) {
    LOG(ERROR) << "failed to parse options: " << S.move_as_error();
    std::_Exit(2);
  }

  td::actor::Scheduler scheduler({threads});
  scheduler.run_in_context([&] {
    x = td::actor::create_actor<TonGate>("ton-gate");
    for (auto &act : acts) {
      act();
    }
    acts.clear();
    td::actor::send_closure(x, &TonGate::run);
  });
  scheduler.run();

  return 0;
}
