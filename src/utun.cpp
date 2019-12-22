/* 
 * Create tun interface for traffic capture.
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

/*
 * TunServer.
 *
 * Creates unutX interface and establishes connection with it.
 */
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

    td::NativeFd native_fd{socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)};
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
      LOG(ERROR) << td::Status::PosixError(saved_errno, PSLICE() << "Failed ioctl CTLIOCGINFO");
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
        LOG(ERROR) << td::Status::PosixError(connect_errno, PSLICE() << "Failed to connect to tun");
        tear_down();
        return;
      }
    }

    buffered_fd_ = td::BufferedFd<td::SocketFd>(td::SocketFd::from_native_fd(std::move(native_fd)).move_as_ok());
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
