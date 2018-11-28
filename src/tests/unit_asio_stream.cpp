#include "tests.h"

#include <iostream>

#if defined(BOTAN_HAS_TLS)

   #include <botan/asio_stream.h>
   #include <botan/tls_callbacks.h>

#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_TLS)

struct TestState
   {
   std::size_t channel_recv_count = 0;
   std::size_t channel_send_count = 0;

   std::size_t socket_read_count = 0;
   std::size_t socket_write_count = 0;
   };

class MockChannel
   {
   public:
      MockChannel(Botan::TLS::Callbacks& callbacks) : callbacks_(callbacks) {}

   public:
      // mockable channel functions
      //
      std::size_t received_data(const uint8_t buf[], std::size_t buf_size)
         {
         return received_data_fun(buf, buf_size);
         }
      std::function<size_t(const uint8_t buf[], std::size_t buf_size)>
      received_data_fun =
      [](const uint8_t buf[], std::size_t buf_size) { return 0; };

      void send(const uint8_t buf[], std::size_t buf_size)
         {
         send_data_fun(buf, buf_size);
         }
      std::function<void(const uint8_t buf[], std::size_t buf_size)>
      send_data_fun = [](const uint8_t buf[], std::size_t buf_size) {};

      bool is_active() { return is_active_fun(); }
      std::function<bool()> is_active_fun = [] { return false; };

   public:
      // funcitons forwarding to callbacks to be triggered from the outside
      //
      void tls_emit_data(const uint8_t buf[], std::size_t buf_size)
         {
         callbacks_.tls_emit_data(buf, buf_size);
         }
      void tls_record_received(uint64_t seq_no, const uint8_t buf[],
                               std::size_t buf_size)
         {
         callbacks_.tls_record_received(seq_no, buf, buf_size);
         }

   protected:
      Botan::TLS::Callbacks& callbacks_;
   };

struct MockSocket
   {
   const std::size_t buf_size = 128;

   template <typename ConstBufferSequence>
   std::size_t write_some(
      const ConstBufferSequence& buffers,
      const boost::system::error_code& ec = boost::system::error_code())
      {
      auto size = boost::asio::buffer_size(buffers);
      return write_some_fun(buffers, ec);
      }

   std::function<std::size_t(const boost::asio::const_buffer& buffers,
                             const boost::system::error_code& ec)>
   write_some_fun = [](const boost::asio::const_buffer& buffers,
   const boost::system::error_code& ec) { return 0; };

   template <typename MutableBufferSequence>
   std::size_t read_some(
      const MutableBufferSequence& buffers,
      const boost::system::error_code& ec = boost::system::error_code())
      {
      auto size = boost::asio::buffer_size(buffers);
      return read_some_fun(buffers, ec);
      }

   std::function<std::size_t(const boost::asio::mutable_buffer& buffers,
                             const boost::system::error_code& ec)>
   read_some_fun = [](const boost::asio::mutable_buffer& buffers,
   const boost::system::error_code& ec) { return 0; };

   void set_default_read_some_fun(std::shared_ptr<TestState> s)
      {
      read_some_fun = [=](
                         const boost::asio::mutable_buffer& buffers,
                         const boost::system::error_code& ec)
         {
         s->socket_read_count += 1;
         return buf_size;
         };
      }

   void set_default_write_some_fun(std::shared_ptr<TestState> s)
      {
      write_some_fun = [=](
                          const boost::asio::const_buffer& buffers,
                          const boost::system::error_code& ec)
         {
         s->socket_write_count += 1;
         return buf_size;
         };
      }

   using lowest_layer_type = MockSocket;
   using executor_type = MockSocket;
   };

static std::shared_ptr<TestState> setupTestHandshake(MockChannel& channel,
      MockSocket& socket)
   {
   auto s = std::shared_ptr<TestState>(new TestState());

   // fake handshake initialization
   uint8_t buf[128];
   channel.tls_emit_data(buf, sizeof(buf));
   // the channel will claim to be active once it has been given 3 chunks
   // of data
   channel.is_active_fun = [&s] { return s->channel_recv_count == 3; };
   channel.received_data_fun = [&s](const uint8_t buf[],
                                    std::size_t buf_size)
      {
      s->channel_recv_count++;
      return 0;
      };

   socket.set_default_read_some_fun(s);
   socket.set_default_write_some_fun(s);

   return s;
   }

static std::shared_ptr<TestState> setupTestSyncRead(MockChannel& channel,
      MockSocket& socket)
   {
   auto s = std::shared_ptr<TestState>(new TestState());

   channel.received_data_fun = [&s, &channel](const uint8_t buf[],
                               std::size_t buf_size)
      {
      s->channel_recv_count++;
      if(s->channel_recv_count >= 3)
         {
         channel.tls_record_received(0, buf, buf_size);
         }
      return 0;
      };

   socket.set_default_read_some_fun(s);
   socket.set_default_write_some_fun(s);

   return s;
   }

static std::shared_ptr<TestState> setupTestSyncWrite(MockChannel& channel,
      MockSocket& socket)
   {
   auto s = std::shared_ptr<TestState>(new TestState());

   channel.send_data_fun = [&s, &channel](const uint8_t buf[],
                                          std::size_t buf_size)
      {
      s->channel_send_count++;
      channel.tls_emit_data(buf, buf_size);
      };

   socket.set_default_read_some_fun(s);
   socket.set_default_write_some_fun(s);

   return s;
   }
}

namespace Botan {

/**
 * A specification of StreamBase for the MockChannel used in this test. It
 * matches the specifications for StreamBase<Botan::TLS::Client> and
 * StreamBase<Botan::TLS::Server> except for the underlying channel type and the
 * simplified constructor.
 */
template <>
class StreamBase<Botan_Tests::MockChannel>
   {
   public:
      StreamBase() : channel_(core_) {}

      StreamBase(const StreamBase&) = delete;
      StreamBase& operator=(const StreamBase&) = delete;

   protected:
      detail::StreamCore core_;
      Botan::AutoSeeded_RNG rng_;
      Botan_Tests::MockChannel channel_;
   };

}  // namespace Botan

namespace Botan_Tests {

class ASIO_Stream_Tests final : public Test
   {
      using TestStream = Botan::Stream<MockSocket&, MockChannel>;

      Test::Result test_handshake()
         {
         Test::Result result("TLS handshake");

         MockSocket socket{};
         Botan::Stream<MockSocket&, MockChannel> ssl{socket};
         auto s = setupTestHandshake(ssl.channel(), socket);
         ssl.handshake();

         result.test_gt("writes on socket", s->socket_write_count, 0);
         result.test_eq("feeds data into channel until active",
                        ssl.channel().is_active(), true);
         return result;
         }

      Test::Result test_read_some()
         {
         Test::Result result("synchronous read");

         MockSocket socket{};
         Botan::Stream<MockSocket&, MockChannel> ssl{socket};

         test_read_some_basic_case(result, ssl, socket);
         test_read_some_read_nothing(result, ssl, socket);

         return result;
         }

      void test_read_some_basic_case(Test::Result& result, TestStream& ssl,
                                     MockSocket& socket)
         {
         auto s = setupTestSyncRead(ssl.channel(), socket);

         char buf[128];
         boost::system::error_code ec;
         ssl.read_some(boost::asio::buffer(buf, sizeof(buf)), ec);

         result.test_eq("some data is read", s->socket_read_count, 3);
         }

      void test_read_some_read_nothing(Test::Result& result, TestStream& ssl,
                                       MockSocket& socket)
         {
         auto s = setupTestSyncRead(ssl.channel(), socket);

         char buf[128];
         boost::system::error_code ec;
         ssl.read_some(boost::asio::buffer(buf, 0), ec);

         result.test_eq("no data is written", s->socket_write_count, 0);
         }

      Test::Result test_write_some()
         {
         Test::Result result("synchronous write_some");

         MockSocket socket{};
         Botan::Stream<MockSocket&, MockChannel> ssl{socket};

         test_write_some_basic_case(result, ssl, socket);
         test_write_some_write_nothing(result, ssl, socket);

         return result;
         }

      void test_write_some_basic_case(Test::Result& result, TestStream& ssl,
                                      MockSocket& socket)
         {
         auto s = setupTestSyncWrite(ssl.channel(), socket);

         char buf[128];
         boost::system::error_code ec;
         auto buffer = boost::asio::buffer(buf, sizeof(buf));
         ssl.write_some(buffer, ec);

         result.test_eq("some data is written", s->socket_write_count,
                        ceil((float)buffer.size() / socket.buf_size));
         }

      void test_write_some_write_nothing(Test::Result& result, TestStream& ssl,
                                         MockSocket& socket)
         {
         auto s = setupTestSyncWrite(ssl.channel(), socket);

         char buf[128];
         boost::system::error_code ec;
         auto buffer = boost::asio::buffer(buf, 0);
         ssl.write_some(buffer, ec);

         result.test_eq("no data is written", s->socket_write_count, 0);
         }

   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_handshake());
         results.push_back(test_read_some());
         results.push_back(test_write_some());

         return results;
         }
   };

#endif

BOTAN_REGISTER_TEST("asio_stream", ASIO_Stream_Tests);
}  // namespace Botan_Tests
