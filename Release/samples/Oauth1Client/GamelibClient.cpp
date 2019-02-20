#include "cpprest/http_client.h"
#include <iostream>

using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace web::http::oauth1::experimental;

#include <boost/locale.hpp>
#include <openssl/sha.h>

utility::string_t _build_body_hash(utility::string_t body)
{
    auto body_str = boost::locale::conv::utf_to_utf<char>(body);
    unsigned char digest_array[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)body_str.c_str(), body_str.length(), digest_array);
    auto array = std::vector<unsigned char>(digest_array, std::end(digest_array));
    return utility::conversions::to_base64(std::move(array));
}

utility::string_t _build_gamelib_header()
{
    std::map<utility::string_t, utility::string_t> queries_map;
    queries_map[U("authVersion")] = U("1.0");
    queries_map[U("paymentVersion")] = U("1.0");
    queries_map[U("appVersion")] = U("1.0");
    queries_map[U("uaType")] = U("windows-app");
    queries_map[U("carrier")] = U("");
    queries_map[U("compromised")] = U("false");
    queries_map[U("countryCode")] = U("JP");
    queries_map[U("currencyCode")] = U("JPY");
    queries_map[U("storeType")] = U("steam");
    queries_map[U("policy")] = U("");

    std::vector<utility::string_t> queries;
    for (const auto& query : queries_map)
    {
        queries.push_back(query.first + _XPLATSTR('=') + query.second);
    }
    utility::string_t result;
    if (!queries.empty())
    {
        auto i = queries.begin();
        auto e = queries.end();
        result = *i;
        while (++i != e)
        {
            result += _XPLATSTR('&');
            result += *i;
        }
    }

    return uri::encode_data_string(result);
}

pplx::task<utility::string_t> InitializeAPI()
{
    return pplx::create_task([=] {
               json::value params;
               params[U("is_test_user")] = json::value::boolean(true);
               params[U("device_id")] = json::value::string(U("RqGBPMxETMREQSHBgRGE2VHY1pwD00FB5NGZgDGEkpQZSWRZ"));
               params[U("token")] = json::value::string(
                   U("-----BEGIN PUBLIC "
                     "KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALMENNlcvxt7ZIT43FLLa3wF9Tkq0PU\n/"
                     "R3erG8EfEbhl8S6YS8ixYyZb+ElbCNMhsaB4EmgVKeCTaAnkwRtPdvUCAwEAAQ\n==\n-----END PUBLIC KEY-----\n"));

               utility::string_t param_json = params.serialize();

               ucout << param_json << std::endl;

               utility::string_t consumer_key(U("947925924698267"));
               utility::string_t consumer_secret(U("62bef8a7040ea05f7552b508a7765ee0"));

               auto oauth_config =
                   oauth1_config(consumer_key, consumer_secret, U(""), U(""), U(""), U(""), oauth1_methods::hmac_sha1);
               oauth_config.set_gamelib_extend(true);
               oauth_config.set_body_hash(_build_body_hash(param_json));
               oauth_config.set_requestor_id(U(""));
               oauth_config.set_as_hash(U(""));

               auto http_config = http_client_config();
               http_config.set_oauth1(oauth_config);

               http_client client(U("https://gl2-payment-gamelib05.dev-gamelib.gree-dev.net"), http_config);

               http_request request(methods::POST);
               request.set_request_uri(U("auth/initialize"));
               request.headers().add(U("X-GREE-GAMELIB"), std::move(_build_gamelib_header()));
               request.set_body(std::move(param_json), U("application/json"));

               return client.request(request, pplx::cancellation_token::none());
           })
        .then([=](http_response response) {
            if (response.status_code() == status_codes::OK)
            {
                // TODO
            }
            return response.extract_json();
        })
        .then([=](json::value json) {
            ucout << json.serialize() << std::endl;

            if (!json[U("uuid")].is_null() && json[U("uuid")].is_string())
            {
                return json[U("uuid")].as_string();
            }
            else
            {
                return utility::string_t();
            }
        });
}

int main()
{
    try
    {
        auto result = InitializeAPI().get();
        ucout << "uuid = " << result << std::endl;
    }
    catch (const std::exception& e)
    {
        ucout << "Error " << e.what() << std::endl;
    }
    return 0;
}
