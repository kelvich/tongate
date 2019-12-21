#pragma once

#include "adnl/adnl.h"
#include "adnl/adnl-ext-client.h"
#include "dht/dht.h"
#include "td/actor/MultiPromise.h"
#include "ton/ton-types.h"
#include "auto/tl/ton_api_json.h"
#include "auto/tl/ton_api.hpp"

#include <set>
#include <map>


class TonGate;

class IdentityListener : public td::actor::Actor {

 private:

  td::actor::ActorId<TonGate> tongate_;
  td::actor::ActorOwn<td::UdpServer> in_udp_server_;
  td::uint16 port_;

 public:

  void start_up() override;
  void respond(td::UdpMessage message);
  IdentityListener(td::uint16 port, td::actor::ActorId<TonGate> tongate)
      : port_(port), tongate_(tongate) {
  }
};


class TonGate: public td::actor::Actor {

 private:

  td::actor::ActorOwn<ton::keyring::Keyring> keyring_;
  td::actor::ActorOwn<ton::adnl::AdnlNetworkManager> adnl_network_manager_;
  td::actor::ActorOwn<ton::adnl::Adnl> adnl_;
  td::actor::ActorOwn<ton::overlay::Overlays> overlay_manager_;
  td::actor::ActorOwn<ton::dht::Dht> dht_node_;

  std::string global_config_ = "ton-global.config.json";
  std::string db_root_ = "/var/ton-work/db/";
  
  td::IPAddress advertised_ip_addr_;
  td::IPAddress socks_ip_addr_;
  bool toggle_server_ = false;
  bool toggle_discovery_ = false;
  ton::adnl::AdnlNodeIdShort ping_dest_id_ = ton::adnl::AdnlNodeIdShort::zero();
  ton::adnl::AdnlNodeIdFull adnl_full_;

  ton::PublicKeyHash adnl_short_;
  ton::adnl::AdnlNodeIdShort adnl_id_;
  std::shared_ptr<ton::dht::DhtGlobalConfig> dht_config_;
  ton::overlay::OverlayIdShort overlay_id_;
  td::actor::ActorOwn<IdentityListener> idl_;

  td::actor::ActorOwn<td::UdpServer> udp_client_;

  td::actor::ActorOwn<ton::adnl::AdnlExtServer> ext_server_;

  ton::PrivateKey load_or_create_key(std::string name);
  void subscribe(ton::PublicKey dht_pub, std::string prefix);
  void add_adnl_addr(ton::PublicKey pub, td::IPAddress ip_addr);
  void send_ping();
  void create_overlay();
  void do_discovery();
  void created_ext_server(td::actor::ActorOwn<ton::adnl::AdnlExtServer> server);
  void adnl_to_ip(ton::adnl::AdnlNodeIdFull adnl_id);
  void start_ext_server();

  void send_identity();

 public:

  void set_global_config(std::string str);
  void set_db_root(std::string db_root);
  void set_advertised_addr(td::IPAddress server_addr);
  void set_socks_addr(td::IPAddress socks_addr);
  void set_ping_dest(ton::adnl::AdnlNodeIdShort ping_dest_id);
  void toggle_server();
  void toggle_discovery();
  void add_peer(ton::PublicKey dst_pub, td::IPAddress dst_ip);

  TonGate() {}

  void start_up() override;
  void alarm() override;
  td::Status load_global_config();
  void run();
};
