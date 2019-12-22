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

// #include "server.h"

#if TD_DARWIN || TD_LINUX
#include <unistd.h>
#endif
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <set>

namespace ton {
namespace adnl {

class TunnelInboundConnection;

class TunnelServer : public td::actor::Actor {
 public:
  class Callback {
   public:
    virtual void on_message(td::BufferSlice data);
  };

  TunnelServer(td::uint16 port, AdnlNodeIdShort local_id, td::actor::ActorId<keyring::Keyring> keyring)
      : port_(port)
      , local_id_(local_id)
      , keyring_(keyring) {
  }

  void run() {
    class Callbackx : public td::TcpListener::Callback {
     private:
      td::actor::ActorId<TunnelServer> id_;
     public:
      Callbackx(td::actor::ActorId<TunnelServer> id) : id_(id) {
      }
      void accept(td::SocketFd fd) override {
        td::actor::send_closure(id_, &TunnelServer::accepted, std::move(fd));
      }
    };

    listener_ = td::actor::create_actor<td::TcpInfiniteListener>(
        td::actor::ActorOptions().with_name("listener").with_poll(),
        port_,
        std::make_unique<Callbackx>(actor_id(this)));
  }

  void accepted(td::SocketFd fd) {
    td::actor::create_actor<TunnelInboundConnection>(td::actor::ActorOptions().with_name("inconn").with_poll(),
                                                 std::move(fd), actor_id(this))
      .release();
  }

  void decrypt_init_packet(AdnlNodeIdShort dst, td::BufferSlice data, td::Promise<td::BufferSlice> promise) {
    // td::actor::send_closure(peer_table_, &AdnlPeerTable::decrypt_message, dst, std::move(data), std::move(promise));
    td::actor::send_closure(keyring_, &keyring::Keyring::decrypt_message, local_id_.pubkey_hash(), std::move(data),
                          std::move(promise));
  }

 private:
  td::uint16 port_;
  AdnlNodeIdShort local_id_;
  td::actor::ActorId<keyring::Keyring> keyring_;
  td::actor::ActorOwn<td::TcpInfiniteListener> listener_;
};

class TunnelInboundConnection : public AdnlExtConnection {
public:
  TunnelInboundConnection(td::SocketFd fd,
                          td::actor::ActorId<TunnelServer> server)
      : AdnlExtConnection(std::move(fd), nullptr, false)
      , server_(server) {
  }

  td::Status process_init_packet(td::BufferSlice data) override {
    if (data.size() < 32) {
      return td::Status::Error(ErrorCode::protoviolation, "too small init packet");
    }
    local_id_ = AdnlNodeIdShort{data.as_slice().truncate(32)};
    data.confirm_read(32);

    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::BufferSlice> R) {
      td::actor::send_closure(SelfId, &TunnelInboundConnection::inited_crypto, std::move(R));
    });

    td::actor::send_closure(server_, &TunnelServer::decrypt_init_packet, local_id_, std::move(data),
                            std::move(P));
    stop_read();
    return td::Status::OK();
  }

  td::Status process_custom_packet(td::BufferSlice &data, bool &processed) override {
    if (data.size() == 12) {
      auto F = fetch_tl_object<ton_api::tcp_ping>(data.clone(), true);
      if (F.is_ok()) {
        auto f = F.move_as_ok();
        auto obj = create_tl_object<ton_api::tcp_pong>(f->random_id_);
        send(serialize_tl_object(obj, true));
        processed = true;
        return td::Status::OK();
      }
    }

    return td::Status::OK();
  }

  td::Status process_packet(td::BufferSlice data) override {
    // td::actor::send_closure(peer_table_, &AdnlPeerTable::deliver, remote_id_, local_id_, std::move(data));

    std::cout << "got message(TunnelInboundConnection): ";
    std::cout.write(data.as_slice().data(), data.size());
    std::cout << std::endl;

    return td::Status::OK();
  }

  void inited_crypto(td::Result<td::BufferSlice> R) {
    if (R.is_error()) {
      LOG(ERROR) << "failed to init crypto: " << R.move_as_error();
      stop();
      return;
    }
    auto S = init_crypto(R.move_as_ok().as_slice());
    if (S.is_error()) {
      LOG(ERROR) << "failed to init crypto (2): " << R.move_as_error();
      stop();
      return;
    }
    send(td::BufferSlice());
    resume_read();
    notify();
  }

private:
  td::actor::ActorId<TunnelServer> server_;
  AdnlNodeIdShort local_id_;
  // AdnlNodeIdShort remote_id_ = AdnlNodeIdShort::zero();
};


}  // namespace adnl
}  // namespace ton

