#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iostream>

#include <evse_security/crypto/openssl/openssl_crypto_supplier.hpp>
#include <evse_security/crypto/openssl/openssl_provider.hpp>

using namespace evse_security;

namespace {

static std::string getFile(const std::string name) {
    std::ifstream file(name);
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

class OpenSSLSupplierPKCSTest : public testing::Test {
protected:
    static void SetUpTestSuite() {
        std::system("./create-pki.sh pkcs11");
    }
};

TEST_F(OpenSSLSupplierPKCSTest, supports_provider_custom) {
    OpenSSLProvider::cleanup();
    ASSERT_FALSE(OpenSSLProvider::supports_provider_custom());
    // calculates
    OpenSSLProvider provider;
    // returns cached
    ASSERT_TRUE(OpenSSLProvider::supports_provider_custom());
}

TEST_F(OpenSSLSupplierPKCSTest, generate_key_EC_prime256v1) {
	setenv("OPENSSL_CONF", "/etc/ssl/openssl.cnf", 1);
    KeyGenerationInfo info = {
        CryptoKeyType::EC_prime256v1, true, std::nullopt, std::nullopt, std::nullopt,
    };
    KeyHandle_ptr key;
    auto res = OpenSSLSupplier::generate_key(info, key);
    ASSERT_TRUE(res);
}

TEST_F(OpenSSLSupplierPKCSTest, load_certificates) {
    auto file = getFile("pkcs11_pki/cert_path.pem");
    auto res = OpenSSLSupplier::load_certificates(file, EncodingFormat::PEM);
    ASSERT_EQ(res.size(), 2);
}

TEST_F(OpenSSLSupplierPKCSTest, x509_check_private_key) {
    auto cert_leaf = getFile("pkcs11_pki/server_cert.pem");
    auto res_leaf = OpenSSLSupplier::load_certificates(cert_leaf, EncodingFormat::PEM);
    auto cert = res_leaf[0].get();
    auto key = getFile("pkcs11_pki/server_priv.pem");
    auto res = OpenSSLSupplier::x509_check_private_key(cert, key, std::nullopt);
    ASSERT_EQ(res, KeyValidationResult::Valid);
}

TEST_F(OpenSSLSupplierPKCSTest, x509_verify_certificate_chain) {
    auto cert_path = getFile("pkcs11_pki/cert_path.pem");
    auto cert_leaf = getFile("pkcs11_pki/server_cert.pem");

    auto res_path = OpenSSLSupplier::load_certificates(cert_path, EncodingFormat::PEM);
    auto res_leaf = OpenSSLSupplier::load_certificates(cert_leaf, EncodingFormat::PEM);

    std::vector<X509Handle*> parents;

    for (auto& i : res_path) {
        parents.push_back(i.get());
    }

    auto res = OpenSSLSupplier::x509_verify_certificate_chain(res_leaf[0].get(), parents, {}, true, std::nullopt,
                                                              "pkcs11_pki/root_cert.pem");
    ASSERT_EQ(res, CertificateValidationResult::Valid);
}

} // namespace
