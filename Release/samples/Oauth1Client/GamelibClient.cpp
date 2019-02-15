#include <iostream>
#include "cpprest/http_client.h"

using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace web::http::oauth1::experimental;

#include "boost/uuid/detail/sha1.hpp"

utility::string_t _build_body_hash(utility::string_t body) {
  boost::uuids::detail::sha1 sha1;
  unsigned int digest[5];
  sha1.process_bytes(body.c_str(), body.length());
  sha1.get_digest(digest);
  unsigned char* tmp = reinterpret_cast<unsigned char *>(digest);
  unsigned char digest_array[sizeof(digest)];
  for(int i = 0; i < 5; i++) {
    digest_array[i*4]   = tmp[i*4+3];
    digest_array[i*4+1] = tmp[i*4+2];
    digest_array[i*4+2] = tmp[i*4+1];
    digest_array[i*4+3] = tmp[i*4];
  }
  auto array = std::vector<unsigned char>(digest_array, std::end(digest_array));
  return utility::conversions::to_base64(std::move(array));
}

utility::string_t _build_gamelib_header() {
  std::map<utility::string_t, utility::string_t> queries_map;
  queries_map["authVersion"] = "1.0";
  queries_map["paymentVersion"] = "1.0";
  queries_map["appVersion"] = "1.0";
  queries_map["uaType"] = "windows-app";
  queries_map["carrier"] = "";
  queries_map["compromised"] = "false";
  queries_map["countryCode"] = "JP";
  queries_map["currencyCode"] = "JPY";
  queries_map["storeType"] = "steam";
  queries_map["policy"] = "";

  std::vector<utility::string_t> queries;
  for (const auto& query : queries_map) {
    queries.push_back(query.first + _XPLATSTR('=') + query.second);
  }
  utility::string_t result;
  if (!queries.empty()) {
    auto i = queries.begin();
    auto e = queries.end();
    result = *i;
    while (++i != e) {
      result += _XPLATSTR('&');
      result += *i;
    }
  }
  
  return uri::encode_data_string(result);
}

pplx::task<utility::string_t> InitializeAPI() {
  return pplx::create_task([=]{
    json::value params;
    params["is_test_user"] = json::value::boolean(true);
    params["device_id"] = json::value::string(U("RqGBPMxETMREQSHBgRGE2VHY1pwD00FB5NGZgDGEkpQZSWRZ"));
    params["token"] = json::value::string(U("-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALMENNlcvxt7ZIT43FLLa3wF9Tkq0PU\n/R3erG8EfEbhl8S6YS8ixYyZb+ElbCNMhsaB4EmgVKeCTaAnkwRtPdvUCAwEAAQ\n==\n-----END PUBLIC KEY-----\n"));
    
    utility::string_t param_json = params.serialize();
    
    std::cout << param_json << std::endl;
    
    std::string consumer_key("947925924698267");
    std::string consumer_secret("62bef8a7040ea05f7552b508a7765ee0");

    auto oauth_config = oauth1_config(consumer_key, consumer_secret, "", "", "", "", oauth1_methods::hmac_sha1);
    oauth_config.set_gamelib_extend(true);
    oauth_config.set_body_hash(_build_body_hash(param_json));
    oauth_config.set_requestor_id("");
    oauth_config.set_as_hash("");

    auto http_config = http_client_config();
    http_config.set_oauth1(oauth_config);
    
    http_client client("https://gl2-payment-gamelib05.dev-gamelib.gree-dev.net", http_config);
    
    http_request request(methods::POST);
    request.set_request_uri("auth/initialize");
    request.headers().add("X-GREE-GAMELIB", std::move(_build_gamelib_header()));
    request.set_body(std::move(param_json), "application/json; charset=UTF-8");
    
    return client.request(request, pplx::cancellation_token::none());

  }).then([=](http_response response) {

    if (response.status_code() == status_codes::OK) {
      // TODO
    }
    return response.extract_json();
  }).then([=](json::value json) {
    std::cout << json.serialize() << std::endl;

    if (!json["uuid"].is_null() && json["uuid"].is_string()) {
      return json["uuid"].as_string();
    } else {
      return utility::string_t();
    }
  });
}

int main() {
  try {
    auto result = InitializeAPI().get();
    std::cout << "uuid = " << result << std::endl;
  } catch (const std::exception &e) {
    std::cout << "Error " << e.what() << std::endl;
  }
  return 0;
}

