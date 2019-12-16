




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


