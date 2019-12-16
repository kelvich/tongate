/* 
    This file is part of TON Blockchain source code.

    TON Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TON Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TON Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give permission 
    to link the code of portions of this program with the OpenSSL library. 
    You must obey the GNU General Public License in all respects for all 
    of the code used other than OpenSSL. If you modify file(s) with this 
    exception, you may extend this exception to your version of the file(s), 
    but you are not obligated to do so. If you do not wish to do so, delete this 
    exception statement from your version. If you delete this exception statement 
    from all source files in the program, then also delete it here.

    Copyright 2017-2019 Telegram Systems LLP
*/
#include "td/actor/actor.h"
#include "td/utils/BufferedFd.h"
#include "td/utils/buffer.h"
#include "td/utils/port/IPAddress.h"
#include "td/net/UdpServer.h"
#include "td/utils/port/signals.h"
#include "td/utils/OptionsParser.h"
#include "td/utils/FileLog.h"
#include "td/utils/port/path.h"
#include "td/utils/port/user.h"
#include "td/utils/port/detail/NativeFd.h"
#include "td/utils/filesystem.h"
#include "common/checksum.h"
#include "common/errorcode.h"
#include "tl-utils/tl-utils.hpp"
#include "auto/tl/ton_api_json.h"
#include "adnl/adnl.h"

#include "td/utils/overloaded.h"

#include <map>

#include <sys/ioctl.h>         // ioctl
#include <sys/kern_control.h>  // struct socketaddr_ctl
#include <net/if_utun.h>       // UTUN_CONTROL_NAME
#include <sys/sys_domain.h>

#if TD_DARWIN || TD_LINUX
#include <unistd.h>
#endif

std::atomic<bool> rotate_logs_flags{false};
void force_rotate_logs(int sig) {
  rotate_logs_flags.store(true);
}

namespace ton {
namespace adnl {

class Callback : public adnl::Adnl::Callback {
  //  public:
  void receive_message(AdnlNodeIdShort src, AdnlNodeIdShort dst, td::BufferSlice data) override {
    fprintf(stderr, "receive_message\n");
    std::cout << "got message" << std::endl;
  }

  void receive_query(AdnlNodeIdShort src, AdnlNodeIdShort dst, td::BufferSlice data,
                     td::Promise<td::BufferSlice> promise) override {
    TRY_RESULT_PROMISE_PREFIX(promise, f, fetch_tl_object<ton_api::adnl_ping>(std::move(data), true),
                              "adnl.ping expected");

    fprintf(stderr, "receive_query\n");
    std::cout << "got query" << std::endl;

    promise.set_value(create_serialize_tl_object<ton_api::adnl_pong>(f->value_));
  }
};

}  // namespace adnl
}  // namespace ton

namespace td {

// Result<SocketFd>
// create_tun()
// {
//   NativeFd native_fd{socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)};
//   if (!native_fd) {
//     return OS_SOCKET_ERROR("Failed to create a socket");
//   }

//   struct ctl_info ctlInfo;
//   strncpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name) - 1);
//   ctlInfo.ctl_name[sizeof(ctlInfo.ctl_name) - 1] = '\0';
//   if (ioctl(native_fd.fd(), CTLIOCGINFO, &ctlInfo) == -1) {
//     auto saved_errno = errno;
//     return Status::PosixError(saved_errno, PSLICE() << "Failed ioctl CTLIOCGINFO");
//   }

//   struct sockaddr_ctl sc = {
//     .sc_id = ctlInfo.ctl_id,
//     .sc_len = sizeof(sc),
//     .sc_family = AF_SYSTEM,
//     .ss_sysaddr = AF_SYS_CONTROL,
//     .sc_unit = 0
//   };

//   int ret = connect(native_fd.socket(), (struct sockaddr *)&sc, sizeof(sc));
//   if (ret == -1) {
//     auto connect_errno = errno;
//     if (connect_errno != EINPROGRESS) {
//       return Status::PosixError(connect_errno, PSLICE() << "Failed to connect to tun");
//     }
//   }

//   return SocketFd::from_native_fd(std::move(native_fd));
// }

// TunServer
// Creates unutX interface and establishes connection with it.
class TunServer : public td::actor::Actor, td::ObserverBase {

 public:
  TunServer() {
  }

 private:
  td::BufferedFd<td::SocketFd> buffered_fd_;
  td::actor::ActorId<TunServer> self_;

  void notify() override {
    send_closure_later(self_, &TunServer::on_net);
  }

  void on_net() {
    loop();
  }

  void start_up() override {
    self_ = actor_id(this);

    NativeFd native_fd{socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)};
    if (!native_fd) {
      LOG(ERROR) << OS_SOCKET_ERROR("Failed to create a socket");
      tear_down();
      return;
    }

    struct ctl_info ctlInfo;
    strncpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name) - 1);
    ctlInfo.ctl_name[sizeof(ctlInfo.ctl_name) - 1] = '\0';
    if (ioctl(native_fd.fd(), CTLIOCGINFO, &ctlInfo) == -1) {
      auto saved_errno = errno;
      LOG(ERROR) << Status::PosixError(saved_errno, PSLICE() << "Failed ioctl CTLIOCGINFO");
      tear_down();
      return;
    }

    struct sockaddr_ctl sc = {.sc_id = ctlInfo.ctl_id,
                              .sc_len = sizeof(sc),
                              .sc_family = AF_SYSTEM,
                              .ss_sysaddr = AF_SYS_CONTROL,
                              .sc_unit = 0};

    int ret = connect(native_fd.socket(), (struct sockaddr *)&sc, sizeof(sc));
    if (ret == -1) {
      auto connect_errno = errno;
      if (connect_errno != EINPROGRESS) {
        LOG(ERROR) << Status::PosixError(connect_errno, PSLICE() << "Failed to connect to tun");
        tear_down();
        return;
      }
    }

    buffered_fd_ = BufferedFd<SocketFd>(SocketFd::from_native_fd(std::move(native_fd)).move_as_ok());
    td::actor::SchedulerContext::get()->get_poll().subscribe(buffered_fd_.get_poll_info().extract_pollable_fd(this),
                                                             td::PollFlags::ReadWrite());

    // alarm_timestamp() = td::Timestamp::now();
  }

  void tear_down() override {
    LOG(INFO) << "Close";
    td::actor::SchedulerContext::get()->get_poll().unsubscribe(buffered_fd_.get_poll_info().get_pollable_fd_ref());
  }

  void loop() override {
    auto status = [&] {
      TRY_STATUS(buffered_fd_.flush_read());
      auto &input = buffered_fd_.input_buffer();
      auto query = input.move_as_buffer_slice();
      LOG(INFO) << "Got message " << td::format::escaped(query.as_slice());

      if (td::can_close(buffered_fd_)) {
        stop();
      }
      return td::Status::OK();
    }();
    if (status.is_error()) {
      LOG(ERROR) << "Client got error " << status;
      stop();
    }
  }

  void alarm() override {
    // alarm_timestamp() = td::Timestamp::in(5);
    LOG(INFO) << "alarm!";
    // buffered_fd_.output_buffer().append("magkpingping");
    // loop();
  }
};

}  // namespace td

int main(int argc, char *argv[]) {
  SET_VERBOSITY_LEVEL(verbosity_DEBUG);

  td::IPAddress dst_addr;

  td::set_default_failure_signal_handler().ensure();

  std::unique_ptr<td::LogInterface> logger_;
  SCOPE_EXIT {
    td::log_interface = td::default_log_interface;
  };

  td::OptionsParser p;
  p.set_description("adnl pinger");
  p.add_option('v', "verbosity", "set verbosity level", [&](td::Slice arg) {
    int v = VERBOSITY_NAME(FATAL) + (td::to_integer<int>(arg));
    SET_VERBOSITY_LEVEL(v);
    return td::Status::OK();
  });
  p.add_option('l', "logname", "log to file", [&](td::Slice fname) {
    auto F = std::make_unique<td::FileLog>();
    TRY_STATUS(F->init(fname.str(), std::numeric_limits<td::uint64>::max(), true));
    logger_ = std::move(F);
    td::log_interface = logger_.get();
    return td::Status::OK();
  });
  p.add_option('a', "addr", "ip:port of instance", [&](td::Slice key) {
    TRY_STATUS(dst_addr.init_host_port(key.str()));
    return td::Status::OK();
  });

  p.run(argc, argv).ensure();

  if (!dst_addr.is_valid()) {
    LOG(FATAL) << "no --addr given";
  }

  td::actor::Scheduler scheduler({7});
  td::actor::ActorOwn<ton::keyring::Keyring> keyring;
  td::actor::ActorOwn<ton::adnl::Adnl> adnl;
  td::actor::ActorOwn<ton::adnl::AdnlNetworkManager> network_manager;

  std::cout << "a" << std::endl;

  ton::adnl::AdnlNodeIdShort src;
  ton::adnl::AdnlNodeIdShort dst;

  scheduler.run_in_context([&]() {
    keyring = ton::keyring::Keyring::create("kring");
    // td::actor::send_closure(keyring, &ton::keyring::Keyring::add_key, std::move(pk), true, [](td::Unit) {});

    adnl = ton::adnl::Adnl::create("", keyring.get());

    td::IPAddress src_addr;
    src_addr.init_host_port("127.0.0.1:6666").ensure();

    network_manager = ton::adnl::AdnlNetworkManager::create(static_cast<td::uint16>(src_addr.get_port()));

    td::actor::send_closure(network_manager, &ton::adnl::AdnlNetworkManager::add_self_addr, src_addr, 0);

    td::actor::send_closure(adnl, &ton::adnl::Adnl::register_network_manager, network_manager.get());

    std::cout << "b" << std::endl;

    // source
    auto src_pk = ton::PrivateKey{ton::privkeys::Ed25519::random()};
    std::cout << "b01" << std::endl;
    auto src_pub = src_pk.compute_public_key();
    std::cout << "b02" << std::endl;
    src = ton::adnl::AdnlNodeIdShort{src_pub.compute_short_id()};
    std::cout << "b03" << std::endl;
    td::actor::send_closure(keyring, &ton::keyring::Keyring::add_key, std::move(src_pk), true, [](td::Unit) {});
    {
      auto tladdr = ton::create_tl_object<ton::ton_api::adnl_address_udp>(src_addr.get_ipv4(), src_addr.get_port());
      auto addr_vec = std::vector<ton::tl_object_ptr<ton::ton_api::adnl_Address>>();
      addr_vec.push_back(std::move(tladdr));
      auto tladdrlist = ton::create_tl_object<ton::ton_api::adnl_addressList>(
          std::move(addr_vec), ton::adnl::Adnl::adnl_start_time(), ton::adnl::Adnl::adnl_start_time(), 0, 2000000000);
      auto addrlist = ton::adnl::AdnlAddressList::create(tladdrlist).move_as_ok();

      std::cout << "b2" << std::endl;
      td::actor::send_closure(adnl, &ton::adnl::Adnl::add_id, ton::adnl::AdnlNodeIdFull{src_pub}, std::move(addrlist));

      td::actor::send_closure(adnl, &ton::adnl::Adnl::subscribe, ton::adnl::AdnlNodeIdShort{src_pub.compute_short_id()},
                              ton::adnl::Adnl::int_to_bytestring(ton::ton_api::adnl_ping::ID),
                              std::make_unique<ton::adnl::Callback>());
    }

    // destination
    auto dst_pub_slice = td::base64_decode("xrQTSAXX6bs9vDvIgko3Dippp8gL2l8sibE69qH+ufYhJm4W").move_as_ok();
    auto dst_pub = ton::PublicKey::import(dst_pub_slice).move_as_ok();
    dst = ton::adnl::AdnlNodeIdShort{dst_pub.compute_short_id()};
    {
      auto tladdr = ton::create_tl_object<ton::ton_api::adnl_address_udp>(dst_addr.get_ipv4(), dst_addr.get_port());
      auto addr_vec = std::vector<ton::tl_object_ptr<ton::ton_api::adnl_Address>>();
      addr_vec.push_back(std::move(tladdr));
      auto tladdrlist = ton::create_tl_object<ton::ton_api::adnl_addressList>(
          std::move(addr_vec), ton::adnl::Adnl::adnl_start_time() - 1000, 0, 0, (int)td::Time::now() + 3600);
      auto addrlist = ton::adnl::AdnlAddressList::create(tladdrlist).move_as_ok();

      td::actor::send_closure(adnl, &ton::adnl::Adnl::add_id, ton::adnl::AdnlNodeIdFull{dst_pub}, (addrlist));
      td::actor::send_closure(adnl, &ton::adnl::Adnl::add_peer, src, ton::adnl::AdnlNodeIdFull{dst_pub}, (addrlist));
    }
  });

  scheduler.run_in_context([&]() {
    std::cout << "c" << std::endl;
    td::BufferSlice msg{4};
    msg.as_slice()[0] = 'H';
    msg.as_slice()[1] = 'i';
    msg.as_slice()[2] = '!';
    msg.as_slice()[3] = '\0';
    std::cout << "d" << std::endl;

    td::actor::send_closure(adnl, &ton::adnl::Adnl::send_message, src, dst, std::move(msg));
    std::cout << "sent!" << std::endl;
  });

  scheduler.run_in_context([&]() {

    td::actor::create_actor<td::TunServer>(td::actor::ActorOptions().with_name("TunServer").with_poll())
        .release();
  });

  // for (;;)
  // {
  //   unsigned char c[1500];
  //   int len;
  //   int i;

  //   len = read(utunfd, c, 1500);

  //   // First 4 bytes of read data are the AF: 2 for AF_INET, 1E for AF_INET6, etc..
  //   for (i = 4; i < len; i++)
  //   {
  //     printf("%02x ", c[i]);
  //     if ((i - 4) % 16 == 15)
  //       printf("\n");
  //   }
  //   printf("\n");
  // }

  while (scheduler.run(1)) {
    if (rotate_logs_flags.exchange(false)) {
      if (td::log_interface) {
        td::log_interface->rotate();
      }
    }
  }

  return 0;
}
