#include "cpprest/http_client.h"
#include "steam/steam_api.h"
#include <boost/locale.hpp>
#include <chrono>
#include <thread>
#include <iostream>
#include <iomanip>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace web::http::oauth1::experimental;

#define PRIVATE_KEY_SIZE 1024
class GamelibClient
{
private:
    // Steam Callback

    STEAM_CALLBACK_MANUAL(GamelibClient,
                          OnMicroTxnAuthorizationResponse,
                          MicroTxnAuthorizationResponse_t,
                          m_CallbackMicroTxnAuthorizationResponse);

    STEAM_CALLBACK_MANUAL(GamelibClient,
                          OnGetAuthSessionTicketResponse,
                          GetAuthSessionTicketResponse_t,
                          m_CallbackGetAuthSessionTicketResponse);

    // initialize API
    utility::string_t m_private_key_pem;
    utility::string_t m_public_key_pem;
    utility::string_t m_requestor_id;

    // purchase API
    utility::nonce_generator m_nonce_generator;
    utility::string_t m_purchase_id;
    bool m_need_caution_for_minors;
    utility::string_t m_external_order_id;
  
    utility::string_t m_steam_id;
    utility::string_t m_session_ticket;
    utility::string_t m_language;
  
    bool m_commit_purchase = false;
  
    bool m_initialized = false;
  
    bool _generate_rsa_keypair(utility::string_t& private_key_pem, utility::string_t& public_key_pem)
    {
        bool ret = false;
        BIGNUM* bne = BN_new();
        RSA* rsa = RSA_new();
        EVP_PKEY* key = EVP_PKEY_new();
        BIO* private_key_bio = BIO_new(BIO_s_mem());
        BIO* public_key_bio = BIO_new(BIO_s_mem());
        int keylen;
        char* pem_key = NULL;

        // generate key pair
        if (!BN_set_word(bne, RSA_F4))
        {
            goto free_and_return;
        }
        if (!RSA_generate_key_ex(rsa, PRIVATE_KEY_SIZE, bne, NULL))
        {
            goto free_and_return;
        }

        // get private key pem
        // PKCS#1 format
        // if (PEM_write_bio_RSAPrivateKey(private_key_bio, rsa, NULL, NULL, 0, NULL, NULL) <= 0) {
        // PKCS#8 format
        if (!EVP_PKEY_set1_RSA(key, rsa))
        {
            goto free_and_return;
        }
        if (PEM_write_bio_PrivateKey(private_key_bio, key, NULL, NULL, 0, NULL, NULL) <= 0)
        {
            goto free_and_return;
        }
        keylen = BIO_pending(private_key_bio);
        pem_key = (char*)::calloc(keylen + 1, sizeof(char));
        if (BIO_read(private_key_bio, pem_key, keylen) <= 0)
        {
            ::free(pem_key);
            goto free_and_return;
        }
        private_key_pem.assign(utility::conversions::to_string_t(std::string(pem_key)));
        ::free(pem_key);

        // get public key pem
        // PKCS#1 format
        // if (PEM_write_bio_RSAPublicKey(public_key_bio, rsa) <= 0) {
        // PKCS#8 format
        if (PEM_write_bio_RSA_PUBKEY(public_key_bio, rsa) <= 0)
        {
            goto free_and_return;
        }
        keylen = BIO_pending(public_key_bio);
        pem_key = (char*)::calloc(keylen + 1, sizeof(char));
        if (BIO_read(public_key_bio, pem_key, keylen) <= 0)
        {
            ::free(pem_key);
            goto free_and_return;
        }
        public_key_pem.assign(utility::conversions::to_string_t(std::string(pem_key)));
        ::free(pem_key);
        ret = true;

    free_and_return:
        BIO_free_all(private_key_bio);
        BIO_free_all(public_key_bio);
        RSA_free(rsa);
        EVP_PKEY_free(key);
        BN_free(bne);
        return ret;
    }

    utility::string_t _build_body_hash(utility::string_t body)
    {
        auto body_str = boost::locale::conv::utf_to_utf<char>(body);
        unsigned char digest_array[SHA_DIGEST_LENGTH];
        SHA1((unsigned char*)body_str.c_str(), body_str.length(), digest_array);
        auto array = std::vector<unsigned char>(digest_array, std::end(digest_array));
        return utility::conversions::to_base64(std::move(array));
    }

    utility::string_t _generate_payment_api_token()
    {
        utility::datetime datetime = utility::datetime::utc_now();
        auto datetime_str = datetime.to_string(utility::datetime::ISO_8601);
        auto str = datetime_str.substr(0, 4) + datetime_str.substr(5, 2) + datetime_str.substr(8, 2) +
                        datetime_str.substr(11, 2) + datetime_str.substr(14, 2) + datetime_str.substr(17, 2);
        auto token_str = boost::locale::conv::utf_to_utf<char>(str);
        unsigned char digest_array[MD5_DIGEST_LENGTH];
        MD5((unsigned char*)token_str.c_str(), token_str.length(), digest_array);
        std::stringstream ss1;
        for (int i = 0; i < sizeof(digest_array); i++)
        {
            ss1 << std::setfill('0') << std::setw(2) << std::hex << +digest_array[i];
        }
        return utility::conversions::to_string_t(ss1.str());
    }

    utility::string_t _build_gamelib_header()
    {
        std::map<utility::string_t, utility::string_t> queries_map;
        queries_map[U("authVersion")] = U("1.0");
        queries_map[U("paymentVersion")] = U("1.0");
        queries_map[U("paymentApiToken")] = _generate_payment_api_token();
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

    pplx::task<json::value> _request(utility::string_t uri, http::method method, json::value params)
    {
        return pplx::create_task([=] {
                   ucout << U("==============================") << std::endl;
                   ucout << method << U(" ") << uri << std::endl;
                   auto param_json = params.is_null() ? U("") : params.serialize();
                   ucout << param_json << std::endl;
                   ucout << U("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<") << std::endl;

                   utility::string_t consumer_key(U("947925924698267"));
                   utility::string_t consumer_secret(U("62bef8a7040ea05f7552b508a7765ee0"));

                   utility::string_t oauth_method = oauth1_methods::hmac_sha1;
                   if (!m_requestor_id.empty())
                   {
                       oauth_method.assign(oauth1_methods::rsa_sha1);
                   }
                   auto oauth_config =
                       oauth1_config(consumer_key, consumer_secret, U(""), U(""), U(""), U(""), oauth_method);
                   oauth_config.set_gamelib_extend(true);
                   oauth_config.set_token(oauth1_token(U(""), m_private_key_pem));
                   oauth_config.set_body_hash(_build_body_hash(param_json));
                   oauth_config.set_requestor_id(m_requestor_id);

                   auto http_config = http_client_config();
                   http_config.set_oauth1(oauth_config);

                   http_client client(U("https://gl2-payment-gamelib05.dev-gamelib.gree-dev.net"), http_config);

                   http_request request(method);
                   request.set_request_uri(uri);
                   request.headers().add(U("Content-Type"), std::move(U("application/json; charset=UTF-8")));
                   request.headers().add(U("User-Agent"), std::move(U("Gamelib windows sdk")));
                   request.headers().add(U("X-GREE-GAMELIB"), std::move(_build_gamelib_header()));
                   if (!params.is_null())
                   {
                       request.set_body(params);
                   }

                   return client.request(request, pplx::cancellation_token::none());
               })
            .then([=](http_response response) {
                if (response.status_code() == status_codes::OK)
                {
                    // TODO response signature check
                }
                return response.extract_json();
            });
    }

public:
    void init()
    {
        m_requestor_id = U("");
        if (m_initialized) return;
        m_CallbackMicroTxnAuthorizationResponse.Register(this, &GamelibClient::OnMicroTxnAuthorizationResponse);
        m_CallbackGetAuthSessionTicketResponse.Register(this, &GamelibClient::OnGetAuthSessionTicketResponse);
        // Get Steam ID
        CSteamID steam_id = SteamUser()->GetSteamID();
        uint64 steam_id_int = steam_id.ConvertToUint64();
        ucout << "SteamID:" << steam_id_int << std::endl;
        std::string steam_id_str = std::to_string(steam_id.ConvertToUint64());
        m_steam_id = utility::conversions::to_string_t(steam_id_str); // steam ID

        // Get Session Ticket to confirm SteamID on Server
        uint8 ticket[1024];
        uint32 ticket_len = 0;
        HAuthTicket hAuthTicket = SteamUser()->GetAuthSessionTicket(ticket, sizeof(ticket), &ticket_len);
        std::stringstream ss;
        for (int i = 0; i < (int)ticket_len; i++)
        {
          ss << std::setfill('0') << std::setw(2) << std::hex << +ticket[i];
        }
        m_session_ticket = utility::conversions::to_string_t(ss.str());
        ucout << "Session Ticket:" << m_session_ticket << std::endl;
      
        // Get Current Game Language
        const char* lang = SteamApps()->GetCurrentGameLanguage();
        ucout << "Language:" << lang << std::endl;
        m_language = utility::conversions::to_string_t(std::string(lang));
        m_initialized = true;
    }

    pplx::task<utility::string_t> initializeAPI()
    {
        _generate_rsa_keypair(m_private_key_pem, m_public_key_pem);

        ucout << m_private_key_pem << std::endl;
        ucout << m_public_key_pem << std::endl;

        json::value params;
        params[U("is_test_user")] = json::value::boolean(true);
        params[U("device_id")] = json::value::string(U("RqGBPMxETMREQSHBgRGE2VHY1pwD00FB5NGZgDGEkpQZSWRZ"));
        params[U("token")] = json::value::string(m_public_key_pem);

        return _request(U("/v1.0/auth/initialize"), methods::POST, params).then([=](json::value response_json) {
            ucout << response_json.serialize() << std::endl;
            if (!response_json[U("uuid")].is_null() && response_json[U("uuid")].is_string())
            {
                m_requestor_id.assign(response_json[U("uuid")].as_string());
                return m_requestor_id;
            }
            else
            {
                return utility::string_t();
            }
        });
    }

    pplx::task<void> authorizeAPI()
    {
        return _request(U("/v1.0/auth/authorize"), methods::POST, json::value::null())
            .then([=](json::value response_json) { ucout << response_json.serialize() << std::endl; });
    }

    pplx::task<void> balanceAPI()
    {
        return _request(U("/v1.0/payment/balance"), methods::GET, json::value::null())
            .then([=](json::value response_json) { ucout << response_json.serialize() << std::endl; });
    }

    pplx::task<void> purchaseAPI()
    {
        json::value params;
        params[U("product_id")] = json::value::string(U("test1"));
        params[U("country_code")] = json::value::string(U("JP"));
        params[U("currency_code")] = json::value::string(U("JPY"));
        params[U("translated_name")] = json::value::string(U(""));
        params[U("formatted_price")] = json::value::string(U(""));
        params[U("price")] = json::value::string(U("100"));
        params[U("id_token")] = json::value::string(m_steam_id); // steam ID
      
        m_purchase_id = U("");
        m_need_caution_for_minors = false;
        m_external_order_id = U("");
        m_commit_purchase = false;
      
        return _request(U("/v1.0/payment/purchase"), methods::POST, params).then([=](json::value response_json) {
            ucout << response_json.serialize() << std::endl;
            json::value entry = response_json[U("entry")];
            m_purchase_id = entry[U("purchase_id")].as_string();
            m_need_caution_for_minors = entry[U("need_caution_for_minors")].as_bool();
            if (!entry[U("external_order_id")].is_null())
            {
				utility::stringstream_t ss;
				ss << entry[U("external_order_id")];
				m_external_order_id = utility::conversions::to_string_t(ss.str());
            }
        });
    }

    pplx::task<void> commitAPI()
    {
        json::value params;
        params[U("purchase_id")] = json::value::string(m_purchase_id);
        params[U("receipt")] = json::value::string(U(""));
        params[U("id_token")] = json::value::string(m_steam_id); // steam ID

        return _request(U("/v1.0/payment/purchase/commit"), methods::POST, params).then([=](json::value response_json) {
            ucout << response_json.serialize() << std::endl;
        });
    }

    bool isCommitPurchase() { return m_commit_purchase; }
};

void GamelibClient::OnMicroTxnAuthorizationResponse(MicroTxnAuthorizationResponse_t* pCallback)
{
    ucout << U("OnMicroTxnAuthorizationResponse!") << std::endl;
    ucout << U("AppID:") << pCallback->m_unAppID << std::endl;
    ucout << U("OrderID:") << pCallback->m_ulOrderID << std::endl;
    ucout << U("Authorized:") << pCallback->m_bAuthorized << std::endl;
  
    auto order_id = utility::conversions::to_string_t(std::to_string(pCallback->m_ulOrderID));
    if (pCallback->m_bAuthorized && m_external_order_id == order_id) {
        m_commit_purchase = true;
    }
}

void GamelibClient::OnGetAuthSessionTicketResponse(GetAuthSessionTicketResponse_t* pCallback)
{
    ucout << U("GetAuthSessionTicketResponse!") << std::endl;
}

GamelibClient gamelibclient;

int PurchaseFlow()
{
    // The dialog to open. Valid options are: "friends", "community", "players", "settings", "officialgamegroup", "stats", "achievements".
    // SteamFriends()->ActivateGameOverlay( "community" );
    try
    {
        gamelibclient.init();
        // initizalize & authorize API
        auto tasks = gamelibclient.initializeAPI()
                         .then([&](utility::string_t uuid) {
                             ucout << U("uuid=") << uuid << std::endl;
                             return gamelibclient.authorizeAPI();
                         })
                         .then([&] { return gamelibclient.balanceAPI(); })
                         .then([&] { return gamelibclient.purchaseAPI(); })
                         .then([&] {
                             // wait for OnMicroTxnAuthorizationResponse callback
                             ucout << "Wait for OnMicroTxnAuthorizationResponse..." << std::endl;
                             do
                             {
                                 SteamAPI_RunCallbacks();
                                 std::this_thread::sleep_for(std::chrono::milliseconds(100));
                             } while (!gamelibclient.isCommitPurchase());
                         })
                         .then([&] { return gamelibclient.commitAPI(); })

                         ;
 
        //tasks.wait();
    }
    catch (const std::exception& e)
    {
        ucout << "Error " << e.what() << std::endl;
    }
    //SteamAPI_Shutdown();
    return 0;
}
