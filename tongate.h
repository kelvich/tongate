#pragma once

#include "adnl/adnl.h"
#include "dht/dht.h"
#include "td/actor/MultiPromise.h"
#include "ton/ton-types.h"
#include "auto/tl/ton_api_json.h"
#include "auto/tl/ton_api.hpp"

#include <set>
#include <map>

// using AdnlCategory = td::int32;

class TonGate: public td::actor::Actor {

 private:

  td::actor::ActorOwn<ton::keyring::Keyring> keyring_;
  td::actor::ActorOwn<ton::adnl::AdnlNetworkManager> adnl_network_manager_;
  td::actor::ActorOwn<ton::adnl::Adnl> adnl_;
  td::actor::ActorOwn<ton::overlay::Overlays> overlay_manager_;
  // XXX: we are using only one dht actor
  std::map<ton::PublicKeyHash, td::actor::ActorOwn<ton::dht::Dht>> dht_nodes_;

  ton::PublicKeyHash default_dht_node_ = ton::PublicKeyHash::zero();
  ton::adnl::AdnlNodesList adnl_static_nodes_;
  std::string global_config_ = "ton-global.config.json";
  std::string db_root_ = "/var/ton-work/db/";
  std::shared_ptr<ton::dht::DhtGlobalConfig> dht_config_;
  td::IPAddress server_ip_addr_;
  td::IPAddress socks_ip_addr_;
  ton::PublicKeyHash adnl_short_;
  ton::adnl::AdnlNodeIdShort adnl_id_;
  ton::adnl::AdnlNodeIdShort ping_dest_id_ = ton::adnl::AdnlNodeIdShort::zero();
  ton::overlay::OverlayIdShort overlay_id_;

  ton::PrivateKey load_or_create_key(std::string name);
  void subscribe(ton::PublicKey dht_pub, std::string prefix);
  void add_adnl_addr(ton::PublicKey pub, td::IPAddress ip_addr);
  void send_ping();
  void create_overlay();

 public:

  void set_global_config(std::string str);
  void set_db_root(std::string db_root);
  void set_server_addr(td::IPAddress server_addr);
  void set_socks_addr(td::IPAddress socks_addr);
  void set_ping_dest(ton::adnl::AdnlNodeIdShort ping_dest_id);

  TonGate() {}

  void start_up() override;
  void alarm() override;
  td::Status load_global_config();
  void run();

};


