#include "cpprest/http_client.h"
#include <iostream>
#include <boost/locale.hpp>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace web::http::oauth1::experimental;

#define PRIVATE_KEY_SIZE      1024
class GamelibClient {
private:
    utility::string_t m_private_key_pem;
    utility::string_t m_public_key_pem;
    
    utility::string_t m_requestor_id;

    bool _generate_rsa_keypair(utility::string_t &private_key_pem, utility::string_t &public_key_pem) {
        bool ret = false;
        BIGNUM *bne = BN_new();
        RSA *rsa = RSA_new();
        EVP_PKEY* key = EVP_PKEY_new();
        BIO *private_key_bio = BIO_new(BIO_s_mem());
        BIO *public_key_bio = BIO_new(BIO_s_mem());
        int keylen;
        char *pem_key = NULL;

        // generate key pair
        if (!BN_set_word(bne, RSA_F4)) {
            goto free_and_return;
        }
        if (!RSA_generate_key_ex(rsa, PRIVATE_KEY_SIZE, bne, NULL)) {
            goto free_and_return;
        }

        // get private key pem
        // PKCS#1 format
        // if (PEM_write_bio_RSAPrivateKey(private_key_bio, rsa, NULL, NULL, 0, NULL, NULL) <= 0) {
        // PKCS#8 format
        if (!EVP_PKEY_set1_RSA(key, rsa)) {
             goto free_and_return;
        }
        if (PEM_write_bio_PrivateKey(private_key_bio, key, NULL, NULL, 0, NULL, NULL) <= 0) {
            goto free_and_return;
        }
        keylen = BIO_pending(private_key_bio);
        pem_key = (char *)::calloc(keylen, sizeof(char));
        if (BIO_read(private_key_bio, pem_key, keylen) <= 0) {
            ::free(pem_key);
            goto free_and_return;
        }
        private_key_pem.assign(pem_key);
        ::free(pem_key);

        // get public key pem
        //  PKCS#1 format
        //if (PEM_write_bio_RSAPublicKey(public_key_bio, rsa) <= 0) {
        // PKCS#8 format
        if (PEM_write_bio_RSA_PUBKEY(public_key_bio, rsa) <= 0) {
            goto free_and_return;
        }
        keylen = BIO_pending(public_key_bio);
        pem_key = (char *)::calloc(keylen, sizeof(char));
        if (BIO_read(public_key_bio, pem_key, keylen) <= 0) {
            ::free(pem_key);
            goto free_and_return;
        }
        public_key_pem.assign(pem_key);
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

    utility::string_t _build_body_hash(utility::string_t body) {
        auto body_str = boost::locale::conv::utf_to_utf<char>(body);
        unsigned char digest_array[SHA_DIGEST_LENGTH];
        SHA1((unsigned char*)body_str.c_str(), body_str.length(), digest_array);
        auto array = std::vector<unsigned char>(digest_array, std::end(digest_array));
        return utility::conversions::to_base64(std::move(array));
    }

    utility::string_t _build_gamelib_header() {
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

    pplx::task<json::value> _request(utility::string_t uri, http::method method, json::value params) {
        return pplx::create_task([=] {
                ucout << U("==============================") << std::endl;
                ucout << method << U(" ") << uri << std::endl;
                auto param_json = params.is_null() ? U("") : params.serialize();
                ucout << param_json << std::endl;
                ucout << U("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<") << std::endl;

                utility::string_t consumer_key(U("947925924698267"));
                utility::string_t consumer_secret(U("62bef8a7040ea05f7552b508a7765ee0"));

                utility::string_t oauth_method = oauth1_methods::hmac_sha1;
                if (!m_requestor_id.empty()) {
                  oauth_method.assign(oauth1_methods::rsa_sha1);
                }
                auto oauth_config = oauth1_config(consumer_key, consumer_secret, U(""), U(""), U(""), U(""), oauth_method);
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
                if (!params.is_null()) {
                    request.set_body(params);
                }

                return client.request(request, pplx::cancellation_token::none());
            })
            .then([=](http_response response) {
                if (response.status_code() == status_codes::OK) {
                    //TODO response signature check
                }
                return response.extract_json();
            });
    }

public:
    pplx::task<utility::string_t> initializeAPI() {
        _generate_rsa_keypair(m_private_key_pem, m_public_key_pem);

        ucout << m_private_key_pem << std::endl;
        ucout << m_public_key_pem << std::endl;

        json::value params;
        params[U("is_test_user")] = json::value::boolean(true);
        params[U("device_id")] = json::value::string(U("RqGBPMxETMREQSHBgRGE2VHY1pwD00FB5NGZgDGEkpQZSWRZ"));
        params[U("token")] = json::value::string(m_public_key_pem);

        return _request(U("/v1.0/auth/initialize"), methods::POST, params)
            .then([=](json::value response_json) {
                ucout << response_json.serialize() << std::endl;
                if (!response_json[U("uuid")].is_null() && response_json[U("uuid")].is_string()) {
                    m_requestor_id.assign(response_json[U("uuid")].as_string());
                    return m_requestor_id;
                } else {
                    return utility::string_t();
                }
            });
    }

    pplx::task<void> authorizeAPI() {
        return _request(U("/v1.0/auth/authorize"), methods::POST, json::value::null())
            .then([=](json::value response_json) {
                ucout << response_json.serialize() << std::endl;
            });
    }

    pplx::task<void> balanceAPI() {
        return _request(U("/v1.0/payment/balance"), methods::GET, json::value::null())
            .then([=](json::value response_json) {
                ucout << response_json.serialize() << std::endl;
            });
    }
};

int main(int argc, char *argv[]) {

    try {
        GamelibClient client;
        // initizalize & authorize API
        auto tasks = client.initializeAPI()
            .then([&](utility::string_t uuid) {
                ucout << U("uuid=") << uuid << std::endl;
                return client.authorizeAPI();
            })
            .then([&] {
                return client.balanceAPI();
            });
        tasks.wait();

    } catch (const std::exception& e) {
        ucout << "Error " << e.what() << std::endl;
    }
    return 0;
}
