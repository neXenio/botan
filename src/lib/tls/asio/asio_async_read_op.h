/*
* TLS Stream Helper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_ASYNC_READ_OP_H_
#define BOTAN_ASIO_ASYNC_READ_OP_H_

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_BOOST_ASIO)

#include <boost/version.hpp>
#if BOOST_VERSION > 106600

#include <botan/internal/asio_async_base.h>
#include <botan/internal/asio_convert_exceptions.h>
#include <botan/internal/asio_includes.h>
#include <botan/internal/asio_stream_core.h>

#include <boost/asio/yield.hpp>

namespace Botan {

namespace TLS {

template <class Handler, class Stream, class MutableBufferSequence, class Allocator = std::allocator<void>>
struct AsyncReadOperation : public AsyncBase<Handler, typename Stream::executor_type, Allocator>
   {
      template <class HandlerT>
      AsyncReadOperation(HandlerT&& handler,
                         Stream& stream,
                         StreamCore& core,
                         const MutableBufferSequence& buffers,
                         const boost::system::error_code& ec = {})
         : AsyncBase<Handler, typename Stream::executor_type, Allocator>(
              std::forward<HandlerT>(handler),
              stream.get_executor())
         , m_stream(stream)
         , m_core(core)
         , m_buffers(buffers)
         , m_decodedBytes(0)
         , m_ec(ec)
         {
         }

      AsyncReadOperation(AsyncReadOperation&&) = default;

      using typename AsyncBase<Handler, typename Stream::executor_type, Allocator>::allocator_type;
      using typename AsyncBase<Handler, typename Stream::executor_type, Allocator>::executor_type;

      void operator()(boost::system::error_code ec, std::size_t bytes_transferred, bool isContinuation = true)
         {
         reenter(this)
            {
            if(ec) { m_ec = ec; }
            if(bytes_transferred > 0 && !m_ec)
               {
               boost::asio::const_buffer read_buffer{m_core.input_buffer.data(), bytes_transferred};
               try
                  {
                  m_stream.native_handle()->received_data(static_cast<const uint8_t*>(read_buffer.data()),
                                                          read_buffer.size());
                  }
               catch(const std::exception&)
                  {
                  m_ec = convertException();
                  }
               }

            if(!m_core.hasReceivedData() && !m_ec)
               {
               // we need more tls packets from the socket
               m_stream.next_layer().async_read_some(m_core.input_buffer, std::move(*this));
               return;
               }

            if(m_core.hasReceivedData() && !m_ec)
               {
               m_decodedBytes = m_core.copyReceivedData(m_buffers);
               m_ec = {};
               }

            if(!isContinuation)
               {
               yield m_stream.next_layer().async_read_some(boost::asio::mutable_buffer(), std::move(*this));
               }

            this->invoke_now(m_ec, m_decodedBytes);
            }
         }

   private:
      Stream&               m_stream;
      StreamCore&           m_core;
      MutableBufferSequence m_buffers;

      size_t                    m_decodedBytes;
      boost::system::error_code m_ec;
   };

}  // namespace TLS

}  // namespace Botan

#include <boost/asio/unyield.hpp>

#endif // BOOST_VERSION
#endif // BOTAN_HAS_TLS && BOTAN_HAS_BOOST_ASIO
#endif // BOTAN_ASIO_ASYNC_READ_OP_H_
