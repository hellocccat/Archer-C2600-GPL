/* <!-- copyright */
/*
 * aria2 - The high speed download utility
 *
 * Copyright (C) 2009 Tatsuhiro Tsujikawa
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */
/* copyright --> */
#include "HttpServerBodyCommand.h"
#include "SocketCore.h"
#include "DownloadEngine.h"
#include "HttpServer.h"
#include "HttpHeader.h"
#include "Logger.h"
#include "LogFactory.h"
#include "RequestGroup.h"
#include "RequestGroupMan.h"
#include "RecoverableException.h"
#include "HttpServerResponseCommand.h"
#include "DelayedCommand.h"
#include "OptionParser.h"
#include "OptionHandler.h"
#include "wallclock.h"
#include "util.h"
#include "fmt.h"
#include "SocketRecvBuffer.h"
#include "json.h"
#include "DlAbortEx.h"
#include "message.h"
#include "RpcMethod.h"
#include "RpcMethodFactory.h"
#include "RpcRequest.h"
#include "RpcResponse.h"
#include "rpc_helper.h"
#include "JsonDiskWriter.h"
#include "ValueBaseJsonParser.h"
#ifdef ENABLE_XML_RPC
#  include "XmlRpcRequestParserStateMachine.h"
#  include "XmlRpcDiskWriter.h"
#endif // ENABLE_XML_RPC

namespace aria2 {

HttpServerBodyCommand::HttpServerBodyCommand
(cuid_t cuid,
 const std::shared_ptr<HttpServer>& httpServer,
 DownloadEngine* e,
 const std::shared_ptr<SocketCore>& socket)
  : Command(cuid),
    e_(e),
    socket_(socket),
    httpServer_(httpServer),
    writeCheck_(false)
{
  // To handle Content-Length == 0 case
  setStatus(Command::STATUS_ONESHOT_REALTIME);
  e_->addSocketForReadCheck(socket_, this);
  if(!httpServer_->getSocketRecvBuffer()->bufferEmpty()) {
    e_->setNoWait(true);
  }
}

HttpServerBodyCommand::~HttpServerBodyCommand()
{
  e_->deleteSocketForReadCheck(socket_, this);
  if(writeCheck_) {
    e_->deleteSocketForWriteCheck(socket_, this);
  }
}

namespace {
std::string getJsonRpcContentType(bool script)
{
  return script ? "text/javascript" : "application/json-rpc";
}
} // namespace

void HttpServerBodyCommand::sendJsonRpcResponse
(const rpc::RpcResponse& res,
 const std::string& callback)
{
  bool notauthorized = rpc::not_authorized(res);
  bool gzip = httpServer_->supportsGZip();
  std::string responseData = rpc::toJson(res, callback, gzip);
  if(res.code == 0) {
    httpServer_->feedResponse(std::move(responseData),
                              getJsonRpcContentType(!callback.empty()));
  } else {
    httpServer_->disableKeepAlive();
    int httpCode;
    switch(res.code) {
    case -32600:
      httpCode = 400;
      break;
    case -32601:
      httpCode = 404;
      break;
    default:
      httpCode = 500;
    };
    httpServer_->feedResponse(httpCode, A2STR::NIL,
                              std::move(responseData),
                              getJsonRpcContentType(!callback.empty()));
  }
  addHttpServerResponseCommand(notauthorized);
}

void HttpServerBodyCommand::sendJsonRpcBatchResponse
(const std::vector<rpc::RpcResponse>& results,
 const std::string& callback)
{
  bool notauthorized = rpc::any_not_authorized(results.begin(), results.end());
  bool gzip = httpServer_->supportsGZip();
  std::string responseData = rpc::toJsonBatch(results, callback, gzip);
  httpServer_->feedResponse(std::move(responseData),
                            getJsonRpcContentType(!callback.empty()));
  addHttpServerResponseCommand(notauthorized);
}

void HttpServerBodyCommand::addHttpServerResponseCommand(bool delayed)
{
  auto resp =
    make_unique<HttpServerResponseCommand>(getCuid(), httpServer_, e_, socket_);
  if (delayed) {
    e_->addCommand(
        make_unique<DelayedCommand>(getCuid(), e_, 1, std::move(resp), true));
    return;
  }

  e_->addCommand(std::move(resp));
  e_->setNoWait(true);
}

void HttpServerBodyCommand::updateWriteCheck()
{
  if(httpServer_->wantWrite()) {
    if(!writeCheck_) {
      writeCheck_ = true;
      e_->addSocketForWriteCheck(socket_, this);
    }
  } else if(writeCheck_) {
    writeCheck_ = false;
    e_->deleteSocketForWriteCheck(socket_, this);
  }
}

bool HttpServerBodyCommand::execute()
{
	OFFLINE_DEBUG();
    if(e_->getRequestGroupMan()->downloadFinished() || e_->isHaltRequested()) {
    	return true;
    }
	try 
	{
		
	    if(socket_->isReadable(0) || !httpServer_->getSocketRecvBuffer()->bufferEmpty() || httpServer_->getContentLength() == 0) 
		{
	        timeoutTimer_ = global::wallclock();

	        if(httpServer_->receiveBody()) 
			{
		      /* Process below. Erase the parsed part of the packet. 
		       * Comment, by WANG Wenhu, Feb9Th, 2015. 
			   */
				  
	          std::string callback;
	          std::unique_ptr<ValueBase> json;
			  
              //std::unique_ptr<json::JsonDiskWriter> dw = static_pointer_cast<json::JsonDiskWriter>(httpServer_->getBody());
              auto dw = static_cast<json::JsonDiskWriter*>(httpServer_->getBody());
			  
              ssize_t error = dw->finalize();
			  
	          if(error == 0) {
	              json = dw->getResult();
	          }
              dw->reset();
			  
	          if(error < 0) 
			  {
	              //A2_LOG_INFO(fmt("CUID#%" PRId64 " - Failed to parse JSON-RPC request", getCuid()));
	              rpc::RpcResponse res(rpc::createJsonRpcErrorResponse(-32700, "Parse error.",Null::g()));
	              sendJsonRpcResponse(res, callback);
	              return true;
	          }
			  
	          Dict* jsondict = downcast<Dict>(json);
			  
	          if(jsondict) 
			  {
				  OFFLINE_DEBUG();
	              auto res = rpc::processJsonRpcRequest(jsondict, e_);
	              sendJsonRpcResponse(res, callback);
	          } 
			  
	          return true;
			} 
			else 
			{
		        e_->addCommand(std::unique_ptr<Command>(this));
		        return false;
		    } 
	    } 
		else 
	    {
	        if(timeoutTimer_.difference(global::wallclock()) >= 15) 
			{
		        //A2_LOG_INFO("HTTP request body timeout.");
		        return true;
			} else 
			{
		        e_->addCommand(std::unique_ptr<Command>(this));
		        return false;
		    }
	    }
	} 
	catch(RecoverableException& e) 
	{
	    //A2_LOG_INFO_EX(fmt("CUID#%" PRId64 " - Error occurred while reading HTTP request body", getCuid()), e);
	    return true;
    }

}

} // namespace aria2
