#include "td/actor/actor.h"

#include "td/utils/BufferedFd.h"
#include "td/utils/port/SocketFd.h"
#include "td/utils/port/ServerSocketFd.h"
#include "td/utils/Observer.h"
#include "td/actor/actor.h"

#include "td/net/TcpListener.h"

#include <iostream>

class SocksInboundConn : public td::actor::Actor, td::ObserverBase {

 public:

  SocksInboundConn(td::SocketFd fd, td::uint64 conn_id): buffered_fd_(std::move(fd)), conn_id_(conn_id) {
  }

  void send(td::BufferSlice data) {
    buffered_fd_.output_buffer().append(std::move(data));
    loop();
  }
  // td::Status process_message(td::BufferSlice data) = 0;

 private:
  td::BufferedFd<td::SocketFd> buffered_fd_;
  td::actor::ActorId<SocksInboundConn> self_;

  void notify() override {
    // NB: Interface will be changed
    td::actor::send_closure_later(self_, &SocksInboundConn::on_net);
  }

  void on_net() {
    loop();
  }

  void start_up() override {
    self_ = actor_id(this);
    LOG(INFO) << "Start";
    // Subscribe for socket updates
    // NB: Interface will be changed
    td::actor::SchedulerContext::get()->get_poll().subscribe(buffered_fd_.get_poll_info().extract_pollable_fd(this),
                                                             td::PollFlags::ReadWrite());
    alarm_timestamp() = td::Timestamp::in(10);
    notify();
  }

  void tear_down() override {
    LOG(INFO) << "Close";
    // unsubscribe from socket updates
    // nb: interface will be changed
    td::actor::SchedulerContext::get()->get_poll().unsubscribe(buffered_fd_.get_poll_info().get_pollable_fd_ref());
    // on_closed(actor_id(this));
  }

  td::Status receive(td::ChainBufferReader &input, bool &exit_loop) {

    if (input.size() == 0) {
      exit_loop = true;
      return td::Status::OK();
    }

    if (current_state_ == SocksState::Greeting) {
      if (input.size() >= 2) {
        char x[2];
        td::MutableSlice s{x, 2};
        input.advance(2, s);

        version_ = (int)*s.data();
        s.remove_prefix(1);
        nmethods_ = (td::size_t)*s.data();
        s.remove_prefix(1);

        std::cout << "Socks greeting: " << version_ << ", " << nmethods_ << std::endl;
        current_state_ = SocksState::GreetingMethods;
      }
      else {
        exit_loop = true;
      }
      return td::Status::OK();

    } else if (current_state_ == SocksState::GreetingMethods) {
      if (input.size() >= nmethods_) {
        char x[nmethods_];
        td::MutableSlice s{x, nmethods_};
        input.advance(nmethods_, s);

        while (nmethods_--) {
          int method = (int)*s.data();
          s.remove_prefix(1);
          std::cout << "Asked method: " << method << std::endl;
        }

        td::BufferSlice resp{2};
        auto sl = resp.as_slice();
        sl[0] = 0x5;
        sl[1] = 0x0;
        send(std::move(resp));
        current_state_ = SocksState::Pass;
      } else {
        exit_loop = true;
      }
      return td::Status::OK();

    } else if (current_state_ == SocksState::Pass) {
      auto data = input.move_as_buffer_slice();

      
    }

    // update_timer();
    // return process_message(std::move(data));
    exit_loop = true;
    return td::Status::OK();
  }

  void loop() override {
    auto status = [&] {
      TRY_STATUS(buffered_fd_.flush_read());
      auto &input = buffered_fd_.input_buffer();
      bool exit_loop = false;
      while (!exit_loop) {
        TRY_STATUS(receive(input, exit_loop));
      }
      TRY_STATUS(buffered_fd_.flush_write());
      if (td::can_close(buffered_fd_)) {
        stop();
      }
      return td::Status::OK();
    }();
    if (status.is_error()) {
      LOG(ERROR) << "Client got error " << status;
      stop();
    } else {
      // send_ready();
    }
  }

  void alarm() override {
    LOG(INFO) << "Close because of timeout";
    stop();
  }

private:
  td::uint64 conn_id_;
  enum class SocksState {Greeting, GreetingMethods, Pass};
  td::size_t nmethods_ = 0;
  int version_ = 0;
  SocksState current_state_ = SocksState::Greeting;
};

class SocksServer : public td::actor::Actor {

 public:

  SocksServer(int port) : port_(port) {
  }

  void run() {
    class Callback : public td::TcpListener::Callback {
     private:
      td::actor::ActorId<SocksServer> id_;
     public:
      Callback(td::actor::ActorId<SocksServer> id) : id_(id) {
      }
      void accept(td::SocketFd fd) override {
        td::actor::send_closure(id_, &SocksServer::accepted, std::move(fd));
      }
    };
    listener_ = td::actor::create_actor<td::TcpListener>(td::actor::ActorOptions().with_name("SocksServer").with_poll(), port_,
                                                std::make_unique<Callback>( actor_id(this) ));
  }

  void accepted(td::SocketFd fd) {
    td::IPAddress ip;
    ip.init_peer_address(fd).ensure();

    std::cout << "Got connection from: " 
              << ip.get_ip_str().str() << ":" << ip.get_port()
              << std::endl;

    auto actor_opts = td::actor::ActorOptions().with_name("socks-connection").with_poll();
    auto c_id = next_conn_id();
    auto conn = td::actor::create_actor<SocksInboundConn>(actor_opts, std::move(fd), c_id);
    connections_.emplace(c_id, conn.release());
  }

  td::uint64 next_conn_id() {
    while (true) {
      td::uint64 c_id = td::Random::fast_uint64();
      if (connections_.count(c_id) == 0) {
        return c_id;
      }
    }
  }

 private:
  td::actor::ActorOwn<td::TcpListener> listener_;
  std::map<td::uint64, td::actor::ActorId<SocksInboundConn>> connections_;
  int port_;

};
