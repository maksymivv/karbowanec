// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of Karbo.
//
// Karbo is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Karbo is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Karbo.  If not, see <http://www.gnu.org/licenses/>.

#include "HttpClient.h"

#include <HTTP/HttpParser.h>
#include <System/Ipv4Resolver.h>
#include <System/Ipv4Address.h>
#include <System/TcpConnector.h>
#include <System/SocketStream.h>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/stream.hpp>
#if defined(WIN32)
#include <wincrypt.h>
#endif

using boost::asio::ip::tcp;


#if defined(WIN32)
void add_windows_root_certs(boost::asio::ssl::context &ctx) {
  HCERTSTORE hStore = CertOpenSystemStore(0, "ROOT");
  if (hStore != NULL) {
    X509_STORE *store = X509_STORE_new();
    PCCERT_CONTEXT pContext = NULL;
    while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != NULL) {
      X509 *x509 = d2i_X509(NULL,
                            (const unsigned char **) &pContext->pbCertEncoded,
                            pContext->cbCertEncoded);
      if (x509 != NULL) {
        X509_STORE_add_cert(store, x509);
        X509_free(x509);
      }
    }
    CertFreeCertificateContext(pContext);
    CertCloseStore(hStore, 0);
    SSL_CTX_set_cert_store(ctx.native_handle(), store);
  }
}
#endif

namespace CryptoNote {

HttpClient::HttpClient(System::Dispatcher& dispatcher, const std::string& address, uint16_t port) :
  m_dispatcher(dispatcher), m_address(address), m_port(port) {
}

HttpClient::~HttpClient() {
  if (m_connected) {
    disconnect();
  }
}

void HttpClient::request(const HttpRequest &req, HttpResponse &res) {
  if (!m_connected) {
    connect();
  }

  try {
    std::iostream stream(m_streamBuf.get());
    HttpParser parser;
    stream << req;
    stream.flush();
    parser.receiveResponse(stream, res);
  } catch (const std::exception &) {
    disconnect();
    throw;
  }
}

void HttpClient::connect() {
  try {
    auto ipAddr = System::Ipv4Resolver(m_dispatcher).resolve(m_address);
    m_connection = System::TcpConnector(m_dispatcher).connect(ipAddr, m_port);
    m_streamBuf.reset(new System::TcpStreambuf(m_connection));
    m_connected = true;
  } catch (const std::exception& e) {
    throw ConnectException(e.what());
  }
}

bool HttpClient::isConnected() const {
  return m_connected;
}

void HttpClient::disconnect() {
  m_streamBuf.reset();
  try {
    m_connection.write(nullptr, 0); //Socket shutdown.
  } catch (std::exception&) {
    //Ignoring possible exception.
  }

  try {
    m_connection = System::TcpConnection();
  } catch (std::exception&) {
    //Ignoring possible exception.
  }

  m_connected = false;
}

ConnectException::ConnectException(const std::string& whatArg) : std::runtime_error(whatArg.c_str()) {
}

}
