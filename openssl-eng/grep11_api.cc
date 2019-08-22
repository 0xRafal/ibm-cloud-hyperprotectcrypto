
#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>
#include "../cxx/grpc/server.grpc.pb.h"
#include "../cxx/grpc/server.pb.h"
#include "../cxx/util/typemaps.h"
#include "../cxx/util/credentials.h"
#include <openssl/sha.h>
using namespace std;

std::string instance = "13ba9eaa-96a9-4105-94da-05c80dd60566";
std::string endpoint = "https://iam.test.cloud.ibm.com";
std::string apiKey = "pn8tuYQ-xXfBIRiAz9OWK0VqlEbhBCSYh3GeUtp0siX2";
std::string url = "ep11.us-east.hs-crypto.test.cloud.ibm.com:9195";

#define  ASN_EC_P256        "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
#define  ASN_EC_P256_BYTES  10

std::string sha256(std::string data) {
    unsigned char buffer[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    int rc = SHA256_Init(&ctx);
    if (rc != 1) {
        return "";
    }
    rc = SHA256_Update(&ctx, data.c_str(), data.length());
    if (rc != 1) {
        return "";
    }
    rc = SHA256_Final(buffer, &ctx);
    if (rc != 1) {
        return "";
    }
    return std::string((char*)buffer, SHA256_DIGEST_LENGTH);
}
extern "C" {
void PrintBuf(const char * header, const unsigned char* data, size_t len)
{
	size_t i;
	if (data == NULL || len == 0) {
		printf("Invalid parameter [%p][%l]", data, len);
		return;
	}
	if (header != NULL) {
		printf("---%s---\n", header);
	}
	for (i = 1; i<= len; i++) {
		printf("%02X:", data[i-1]);
		if (i % 16 == 0) {
			printf("\n");
		}
	}
	printf("\n\n");
}

const unsigned char * GetCoordPointer(const unsigned char * SPKI, size_t leng, size_t* remainderLen)
{
	const unsigned char * p = SPKI;

	if (SPKI == NULL || remainderLen == NULL) {
		return NULL;
	}
	size_t leftlen = leng;
	//skip first sequence
	if (*p != 0x30 || p[1] + 2 > leftlen) {
		return NULL;
	}
	leftlen -= 2;
	p += 2; //skip first sequence

	if (*p != 0x30 || p[1] + 2 > leftlen) {
		return NULL;
	}
	leftlen -= 2 + p[1];
	p += 2 + p[1]; //skip embedded sequence: 2 oid

	//this is coordinates bit string
	if (*p != 0x03 || p[1] + 2 > leftlen) {
		return NULL;
	}
	leftlen -= 3;
	p += 3; //skip 03:42:00 before coordinates bytes
	*remainderLen = leftlen;
	return p;
}
int RemoteGenerateECDSAKeyPair(const unsigned char *curveOIDData, size_t curveOIDLength,
		unsigned char *privateKey, size_t *privateKeyLen, unsigned char *pubKey, size_t *pubKeyLen)
{
    auto call_credentials = new grep11::IAMPerRPCCredentials(instance, endpoint, apiKey);
    auto creds = grpc::CompositeChannelCredentials(
        grpc::SslCredentials(grpc::SslCredentialsOptions()),
        grpc::MetadataCredentialsFromPlugin(std::unique_ptr<grpc::MetadataCredentialsPlugin>(call_credentials)));
    auto client = std::shared_ptr<grep11::Crypto::Stub>(grep11::Crypto::NewStub(grpc::CreateChannel(url, creds)));

    grpc::ClientContext context1;
    grep11::GenerateKeyPairRequest generateECKeypairRequest;
    grep11::GenerateKeyPairResponse generateKeyPairResponse;

    (*generateECKeypairRequest.mutable_pubkeytemplate()) = grep11::ep11Attributes{
		{CKA_EC_PARAMS, ASN_EC_P256, ASN_EC_P256_BYTES},
		{CKA_VERIFY, true},
    };
    (*generateECKeypairRequest.mutable_privkeytemplate()) = grep11::ep11Attributes{
		{CKA_SIGN, true},
		{CKA_EXTRACTABLE, false},
    };
    (*generateECKeypairRequest.mutable_mech()) = grep11::ep11Mechanism(CKM_EC_KEY_PAIR_GEN);

    grpc::Status status = client->GenerateKeyPair(&context1, generateECKeypairRequest, &generateKeyPairResponse);
    if (!status.ok() ) {
        std::cout << "Error in GeneratedKey "<< status.error_message() << std::endl;
        return 0;
    }
    //copy private key data back
    string str = generateKeyPairResponse.privkey();
   	//PrintBuf("Private key", (const unsigned char *)str.c_str(), str.length());
    if (str.length() <= *privateKeyLen) {
    	memcpy(privateKey, str.c_str(), str.length());
    	*privateKeyLen = str.length();
     } else {
    	printf("Private key length [%d] is longer than buffer size [%d]\n",
    			str.length(), *privateKeyLen);
    	return 0;
    }
    //copy SPKI coordinates back
    size_t remain = 0;
    str = generateKeyPairResponse.pubkey();
	PrintBuf("SPKI data", (const unsigned char *)str.c_str(), str.length());
    const unsigned char * p = GetCoordPointer((const unsigned char *)str.c_str(), str.length(), &remain);
    if (p != NULL && remain >= *pubKeyLen) {
    	//there may be extra data after SPKI
    	memcpy(pubKey, p, *pubKeyLen);
    	PrintBuf("Public SPKI coordinates", p, *pubKeyLen);
    } else {
    	printf("Invalid SPKI data\n");
    	return 0;
    }
    std::cout << "Generated ECDSA key pair" << std::endl;
	return 1;
}
int RemoteSignSingle(const unsigned char * privateKeyBlob, size_t keyBlobLen,
		const unsigned char * dgst, size_t dgstLen, unsigned char * signature, size_t *signatureLen)
{
    auto call_credentials = new grep11::IAMPerRPCCredentials(instance, endpoint, apiKey);
    auto creds = grpc::CompositeChannelCredentials(
        grpc::SslCredentials(grpc::SslCredentialsOptions()),
        grpc::MetadataCredentialsFromPlugin(std::unique_ptr<grpc::MetadataCredentialsPlugin>(call_credentials)));
    auto client = std::shared_ptr<grep11::Crypto::Stub>(grep11::Crypto::NewStub(grpc::CreateChannel(url, creds)));

    grpc::ClientContext context2;
    grep11::SignSingleRequest signSingleRequest;
    grep11::SignSingleResponse signSingleResponse;

    (*signSingleRequest.mutable_mech()) = grep11::ep11Mechanism(CKM_ECDSA);
    signSingleRequest.set_privkey((const char*)privateKeyBlob, keyBlobLen);
    signSingleRequest.set_data((const char*)dgst, dgstLen);

    grpc::Status status = client->SignSingle(&context2, signSingleRequest, &signSingleResponse);
	if (!status.ok() ) {
        std::cout << "Error in SignSingle "<< status.error_message() << std::endl;
        return 0;
    }

	size_t retSignaturelen = signSingleResponse.signature().length();
	if (*signatureLen < retSignaturelen) {
        printf("Signature returned [%ld] is longer than signature buffer size [%ld]\n",
        		retSignaturelen, *signatureLen);
        return 0;
	}
	*signatureLen = retSignaturelen;
	memcpy(signature, signSingleResponse.signature().c_str(), retSignaturelen);
	PrintBuf("Signature", signature, *signatureLen);

	std::cout << "Data signed" << std::endl;
	return 1;
}

int testECDSASignature(std::shared_ptr<grep11::Crypto::Stub> client){
    grpc::ClientContext context1;
    grep11::GenerateKeyPairRequest generateECKeypairRequest;
    grep11::GenerateKeyPairResponse generateKeyPairResponse;

    (*generateECKeypairRequest.mutable_pubkeytemplate()) = grep11::ep11Attributes{
		{CKA_EC_PARAMS, ASN_EC_P256, ASN_EC_P256_BYTES},
		{CKA_VERIFY, true},
    };
    (*generateECKeypairRequest.mutable_privkeytemplate()) = grep11::ep11Attributes{
		{CKA_SIGN, true},
		{CKA_EXTRACTABLE, false},
    };
    (*generateECKeypairRequest.mutable_mech()) = grep11::ep11Mechanism(CKM_EC_KEY_PAIR_GEN);

    grpc::Status status = client->GenerateKeyPair(&context1, generateECKeypairRequest, &generateKeyPairResponse);
    if (!status.ok() ) {
        std::cout << "Error in GeneratedKey "<< status.error_message() << std::endl; 
        return 1;
    }
    std::cout << "Generated ECDSA key pair" << std::endl; 

	// Sign data
    grpc::ClientContext context2;
    grep11::SignInitRequest signInitRequest;
    grep11::SignInitResponse signInitResponse;

    (*signInitRequest.mutable_mech()) = grep11::ep11Mechanism(CKM_ECDSA);
    signInitRequest.set_privkey(generateKeyPairResponse.privkey());

    status = client->SignInit(&context2, signInitRequest, &signInitResponse);
	if (!status.ok() ) {
        std::cout << "Error in SignInit "<< status.error_message() << std::endl; 
        return 1;
    }

    grpc::ClientContext context3;
    grep11::SignRequest signRequest;
    grep11::SignResponse signResponse;

	std::string signData = sha256("This data needs to be signed");
    signRequest.set_state(signInitResponse.state());
    signRequest.set_data(signData);
 
    status = client->Sign(&context3, signRequest, &signResponse);
    if (!status.ok() ) {
        std::cout << "Error in Sign "<< status.error_message() << std::endl; 
        return 1;
    }
	std::cout << "Data signed" << std::endl;

    grpc::ClientContext context4;
    grep11::VerifyInitRequest verifyInitRequest;
    grep11::VerifyInitResponse verifyInitResponse;

    (*verifyInitRequest.mutable_mech()) = grep11::ep11Mechanism(CKM_ECDSA);
    verifyInitRequest.set_pubkey(generateKeyPairResponse.pubkey());

    status = client->VerifyInit(&context4, verifyInitRequest, &verifyInitResponse);
    if (!status.ok() ) {
        std::cout << "Error in VerifyInit "<< status.error_message() << std::endl; 
        return 1;
    }

    grpc::ClientContext context5;
    grep11::VerifyRequest verifyRequest;
    grep11::VerifyResponse verifyResponse;

    verifyRequest.set_data(signData);
    verifyRequest.set_state(verifyInitResponse.state());
    verifyRequest.set_signature(signResponse.signature());
	
    status = client->Verify(&context5, verifyRequest, &verifyResponse);
    if (!status.ok() ) {
        grep11::Grep11Error ep11Error;
        grep11::convertError(status, &ep11Error);
        if (ep11Error.code() == CKR_SIGNATURE_INVALID) {
            std::cout << "Invalid Signature in Verify "<< status.error_message() << std::endl; 
        } else {
            std::cout << "Error in Verify "<< status.error_message() << std::endl; 
        }
        return 1;
    }
	std::cout << "Verified" << std::endl;

    grpc::ClientContext context6;
    std::string corruptData = signData;
    corruptData.at(2) = '6';
    verifyRequest.set_data(corruptData);
    verifyRequest.set_state(verifyInitResponse.state());
    verifyRequest.set_signature(signResponse.signature());
	
    status = client->Verify(&context6, verifyRequest, &verifyResponse);
    grep11::Grep11Error ep11Error;
    grep11::convertError(status, &ep11Error);
    if (ep11Error.code() != CKR_SIGNATURE_INVALID ) {
        std::cout << "Expected Error in Verify: "<< ep11Error.detail() << std::endl; 
        return 1;
    }

    return 0;
}
}
