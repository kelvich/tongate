#include "td/actor/actor.h"

#include "td/utils/BufferedFd.h"
#include "td/utils/port/SocketFd.h"
#include "td/utils/port/ServerSocketFd.h"
#include "td/utils/Observer.h"

#include "td/net/TcpListener.h"

/*
 * Copied from tdnet/td/net/UdpServer.cpp.
 */
class TcpClient : public td::actor::Actor, td::ObserverBase {
 public:

  TcpClient(td::SocketFd fd): buffered_fd_(std::move(fd)) {
  }

  void send(td::BufferSlice data) {
    td::uint32 data_size = td::narrow_cast<td::uint32>(data.size());

    buffered_fd_.output_buffer().append(td::Slice(reinterpret_cast<char *>(&data_size), sizeof(data_size)));
    buffered_fd_.output_buffer().append(std::move(data));
   loop();
  }
  virtual void on_closed(td::actor::ActorId<>) = 0;
  virtual void on_message(td::BufferSlice data) = 0;

 private:
  td::BufferedFd<td::SocketFd> buffered_fd_;
  td::actor::ActorId<TcpClient> self_;

  void notify() override {
    // NB: Interface will be changed
    td::actor::send_closure_later(self_, &TcpClient::on_net);
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
    on_closed(actor_id(this));
  }

  void loop() override {
    auto status = [&] {
      TRY_STATUS(buffered_fd_.flush_read());
      auto &input = buffered_fd_.input_buffer();
      while (true) {
        constexpr size_t header_size = 4;
        if (input.size() < header_size) {
          break;
        }
        auto it = input.clone();
        td::uint32 data_size;
        it.advance(header_size, td::MutableSlice(reinterpret_cast<td::uint8 *>(&data_size), sizeof(data_size)));
        if (data_size > (1 << 26)) {
          return td::Status::Error("Too big packet");
        }
        if (it.size() < data_size) {
          break;
        }
        auto data = it.cut_head(data_size).move_as_buffer_slice();
        alarm_timestamp() = td::Timestamp::in(10);
        on_message(std::move(data));
        input = std::move(it);
      }

      TRY_STATUS(buffered_fd_.flush_write());
      if (td::can_close(buffered_fd_)) {
        stop();
      }
      return td::Status::OK();
    }();
    if (status.is_error()) {
      LOG(INFO) << "Client got error " << status;
      stop();
    }
  }

  void alarm() override {
    LOG(INFO) << "Close because of timeout";
    stop();
  }
};


class SocksInboundConn : public TcpClient {

public:

    void on_message(td::BufferSlice data) {

      if (!negotiated_) {

      }

    }


    void on_closed(td::actor::ActorId<>) {

    }


private:

  bool negotiated_;


};



class SocksServer : public td::actor::Actor {

public:
  SocksServer(int port) : port_(port) {
  }

  void start_up() override;
  void listen();
  void accepted(td::SocketFd fd);
  

private:
  td::actor::ActorOwn<td::TcpListener> listener_;
  int port_;

};

void SocksServer::listen() {

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

  listener_ = td::actor::create_actor<td::TcpListener>(td::actor::ActorOptions().with_name("SocksListener").with_poll(), port_,
                                               std::make_unique<Callback>());
}

void SocksServer::accepted(td::SocketFd fd) {

  td::actor::create_actor<SocksConnection>(td::actor::ActorOptions().with_name("inconn").with_poll(),
                                                 std::move(fd), peer_table_, actor_id(this))
      .release();

}


class SocksConnection : public td::actor::Actor, td::ObserverBase {
 public:
  SocksConnection(td::SocketFd fd) : buffered_fd_(std::move(fd)) {
  }

 private:
  td::BufferedFd<td::SocketFd> buffered_fd_;
  td::actor::ActorId<SocksConnection> self_;
  void notify() override {
    // NB: Interface will be changed
    send_closure_later(self_, &SocksConnection::on_net);
  }
  void on_net() {
    loop();
  }

  void start_up() override {
    self_ = actor_id(this);
    LOG(INFO) << "Start";
    td::actor::SchedulerContext::get()->get_poll().subscribe(buffered_fd_.get_poll_info().extract_pollable_fd(this),
                                                             td::PollFlags::ReadWrite());

  }

  void tear_down() override {
    LOG(INFO) << "Close";
    td::actor::SchedulerContext::get()->get_poll().unsubscribe(buffered_fd_.get_poll_info().get_pollable_fd_ref());
  }

  void loop() override {
    auto status = [&] {
      TRY_STATUS(buffered_fd_.flush_read());
      auto &input = buffered_fd_.input_buffer();
      while (input.size() >= 12) {
        auto query = input.cut_head(12).move_as_buffer_slice();
        LOG(INFO) << "Got query " << td::format::escaped(query.as_slice());
        if (query[5] == 'i') {
          LOG(INFO) << "Send ping";
          buffered_fd_.output_buffer().append("magkpongpong");
        } else {
          LOG(INFO) << "Got pong";
        }
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
    }
  }

  void alarm() override {
    LOG(INFO) << "alarm";
  }
};


