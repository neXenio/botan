/*
* TLS Stream Helper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_ASYNC_WRITE_OP_H_
#define BOTAN_ASIO_ASYNC_WRITE_OP_H_

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_BOOST_ASIO)

#include <boost/version.hpp>
#if BOOST_VERSION > 106600

#include <botan/internal/asio_async_base.h>
#include <botan/internal/asio_includes.h>
#include <botan/internal/asio_stream_core.h>

#include <boost/asio/yield.hpp>

namespace Botan {

namespace TLS {

template <typename Handler, class Stream, class Allocator = std::allocator<void>>
struct AsyncWriteOperation : public AsyncBase<Handler, typename Stream::executor_type, Allocator>
   {
   template <class HandlerT>
   AsyncWriteOperation(HandlerT&& handler,
                       Stream& stream,
                       StreamCore& core,
                       std::size_t plainBytesTransferred,
                       const boost::system::error_code& ec = {})
      : AsyncBase<Handler, typename Stream::executor_type, Allocator>(
           std::forward<HandlerT>(handler),
           stream.get_executor())
      , m_stream(stream)
      , m_core(core)
      , m_plainBytesTransferred(plainBytesTransferred)
      {
      this->operator()(ec, std::size_t(0), false);
      }

   AsyncWriteOperation(AsyncWriteOperation&&) = default;

   void operator()(boost::system::error_code ec, std::size_t bytes_transferred, bool isContinuation = true)
      {
      reenter(this)
         {
         m_core.consumeSendBuffer(bytes_transferred);

         if(m_core.hasDataToSend() && !ec)
            {
            m_stream.next_layer().async_write_some(m_core.sendBuffer(), std::move(*this));
            return;
            }

         if(!isContinuation)
            {
            m_ec = ec;
            yield m_stream.next_layer().async_write_some(boost::asio::const_buffer(), std::move(*this));
            ec = m_ec;
            }

         // the size of the sent TLS record can differ from the size of the payload due to TLS encryption. We need to tell
         // the handler how many bytes of the original data we already processed.
         this->complete_now(ec, m_plainBytesTransferred);
         }
      }

   Stream&     m_stream;
   StreamCore& m_core;

   std::size_t m_plainBytesTransferred;
   boost::system::error_code m_ec;
   };

}  // namespace TLS

}  // namespace Botan

#include <boost/asio/unyield.hpp>

#endif // BOOST_VERSION
#endif // BOTAN_HAS_TLS && BOTAN_HAS_BOOST_ASIO
#endif // BOTAN_ASIO_ASYNC_WRITE_OP_H_
