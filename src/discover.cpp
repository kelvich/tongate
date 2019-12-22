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

#include "auto/tl/lite_api.h"

// #include "memprof/memprof.h"

#include "dht/dht.hpp"
#include "overlay/overlays.h"
#include "overlay/overlay.hpp"
// #include "dht-server/dht-server.hpp"

#include "server.h"

#if TD_DARWIN || TD_LINUX
#include <unistd.h>
#endif

#include <iostream>
#include <sstream>
#include <cstdlib>
#include <set>

/*
 * Command-line option setters
 */

void TonGate::set_global_config(std::string str) {
  global_config_ = str;
}

void TonGate::set_db_root(std::string db_root) {
  db_root_ = db_root;
}

void TonGate::set_server_addr(td::IPAddress server_addr) {
  server_ip_addr_ = server_addr;
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

// XXX: use path.join
void TonGate::run() {

  std::cout << "rrrun!" << std::endl;

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
  adnl_network_manager_ = ton::adnl::AdnlNetworkManager::create(static_cast<td::uint16>(server_ip_addr_.get_port()));
  adnl_ = ton::adnl::Adnl::create(db_root_, keyring_.get());
  td::actor::send_closure(adnl_network_manager_, &ton::adnl::AdnlNetworkManager::add_self_addr, server_ip_addr_, 0);
  td::actor::send_closure(adnl_, &ton::adnl::Adnl::register_network_manager, adnl_network_manager_.get());

  // add source addr id
  ton::PrivateKey adnl_pk = load_or_create_key("adnl");
  ton::PublicKey adnl_pub = adnl_pk.compute_public_key();
  add_adnl_addr(adnl_pub, server_ip_addr_);
  adnl_id_ = ton::adnl::AdnlNodeIdShort{adnl_pub.compute_short_id()};
  adnl_short_= adnl_id_.pubkey_hash();

  // start DHT
  ton::PrivateKey dht_pk = load_or_create_key("dht");
  ton::PublicKey dht_pub = dht_pk.compute_public_key();
  ton::PublicKeyHash dht_id = dht_pk.compute_short_id();
  add_adnl_addr(dht_pub, server_ip_addr_);

  auto D = ton::dht::Dht::create(ton::adnl::AdnlNodeIdShort{dht_id}, db_root_, dht_config_, keyring_.get(), adnl_.get());
  D.ensure();
  dht_nodes_[dht_id] = D.move_as_ok();
  default_dht_node_ = dht_id;
  td::actor::send_closure(adnl_, &ton::adnl::Adnl::register_dht_node, dht_nodes_[default_dht_node_].get());

  alarm_timestamp() = td::Timestamp::in(1.0 + td::Random::fast(0, 100) * 0.01);
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

    {
      auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<ton::dht::DhtValue> res) {
        if (res.is_ok()) {
          auto v = res.move_as_ok();
          auto R = ton::fetch_tl_object<ton::ton_api::overlay_nodes>(v.value().clone(), true);
          if (R.is_ok()) {
            auto r = R.move_as_ok();
            std::cout << ": received " << r->nodes_.size() << " nodes from overlay" << std::endl;
            std::cout << ": nodes: " << ton::ton_api::to_string(r) << std::endl;
            std::vector<ton::overlay::OverlayNode> nodes;
            for (auto &n : r->nodes_) {
              auto N = ton::overlay::OverlayNode::create(n);
              if (N.is_ok()) {
                nodes.emplace_back(N.move_as_ok());
              }
            }
          } else {
            std::cout << ": incorrect value in DHT for overlay nodes: " << R.move_as_error().to_string() << std::endl;
          }
        } else {
          std::cout << ": can not get value from DHT: " << res.move_as_error().to_string() << std::endl;
        }
      });
      td::actor::send_closure(dht_nodes_[default_dht_node_].get(),
                              &ton::dht::Dht::get_value,
                              ton::dht::DhtKey{overlay_id_.pubkey_hash(), "nodes", 0},
                              std::move(P));
    }

    alarm_timestamp() = td::Timestamp::in(1.0 + td::Random::fast(0, 100) * 0.01);
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
    std::cout << "!" << std::endl;
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
  p.add_option('s', "server", "start gate server at ip:port", [&](td::Slice arg) {
    td::IPAddress addr;
    TRY_STATUS(addr.init_host_port(arg.str()));
    acts.push_back([&x, addr]() { td::actor::send_closure(x, &TonGate::set_server_addr, addr); });
    return td::Status::OK();
  });
  p.add_option('p', "ping", "ping given pubkey via ADNL", [&](td::Slice arg) {
    TRY_RESULT_PREFIX(dst_pub_slice, td::base64_decode(arg), "ADNL pubkey base64 decode failed:");
    TRY_RESULT_PREFIX(dst_pub, ton::PublicKey::import(dst_pub_slice), "ADNL pubkey import failed:");
    auto dest_id = ton::adnl::AdnlNodeIdShort{dst_pub.compute_short_id()};
    acts.push_back([&x, dest_id]() { td::actor::send_closure(x, &TonGate::set_ping_dest, dest_id); });
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
      std::cout << "act" << std::endl;
      act();
    }
    acts.clear();
    td::actor::send_closure(x, &TonGate::run);
  });
  scheduler.run();

  return 0;
}
