#pragma once

#include "adnl/adnl.h"
#include "dht/dht.h"
#include "td/actor/MultiPromise.h"
#include "ton/ton-types.h"
#include "auto/tl/ton_api_json.h"
#include "auto/tl/ton_api.hpp"

#include <set>
#include <map>

using AdnlCategory = td::int32;

class TonGate: public td::actor::Actor {

 private:

  td::actor::ActorOwn<ton::keyring::Keyring> keyring_;
  td::actor::ActorOwn<ton::adnl::AdnlNetworkManager> adnl_network_manager_;
  td::actor::ActorOwn<ton::adnl::Adnl> adnl_;
  std::map<ton::PublicKeyHash, td::actor::ActorOwn<ton::dht::Dht>> dht_nodes_;
  ton::PublicKeyHash default_dht_node_ = ton::PublicKeyHash::zero();
  ton::adnl::AdnlNodesList adnl_static_nodes_;

  std::string global_config_ = "ton-global.config.json";
  std::string db_root_ = "/var/ton-work/db/";
  std::shared_ptr<ton::dht::DhtGlobalConfig> dht_config_;
  td::IPAddress dht_addr_;
  td::IPAddress socks_addr_;
  // std::set<ton::PublicKeyHash> dht_ids;
  // std::map<ton::PublicKeyHash, AdnlCategory> adnl_ids;

  ton::PrivateKey load_or_create_key(std::string name);
  void subscribe(ton::PublicKey dht_pub, std::string prefix);
  void add_adnl_addr(ton::PublicKey pub, td::IPAddress ip_addr);
  // td::Result<bool> config_add_dht_node(ton::PublicKeyHash id);

 public:

  void set_global_config(std::string str);
  void set_db_root(std::string db_root);
  void set_server_addr(td::IPAddress server_addr);
  void set_socks_addr(td::IPAddress socks_addr);

  TonGate() {}

  void start_up() override;
  td::Status load_global_config();
  void run();

};


