#pragma once
#include <botan/asio_stream_core.h>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>

namespace Botan {
namespace detail {

template <typename Handler>
struct AsyncWriteOperation
   {
   AsyncWriteOperation(StreamCore& core, Handler&& handler,
                       std::size_t plainBytesTransferred)
      : core_(core),
        handler_(std::forward<Handler>(handler)),
        plainBytesTransferred_(plainBytesTransferred) {}

   AsyncWriteOperation(AsyncWriteOperation&& right)
      : core_(right.core_),
        handler_(std::move(right.handler_)),
        plainBytesTransferred_(right.plainBytesTransferred_) {}

   ~AsyncWriteOperation() = default;
   AsyncWriteOperation(AsyncWriteOperation&) = delete;

   void operator()(boost::system::error_code ec,
                   std::size_t bytes_transferred = ~std::size_t(0))
      {
      core_.consumeSendBuffer(bytes_transferred);
      handler_(ec, plainBytesTransferred_);
      }

   StreamCore& core_;
   Handler handler_;
   std::size_t plainBytesTransferred_;
   };
}  // namespace detail
}  // namespace Botan
