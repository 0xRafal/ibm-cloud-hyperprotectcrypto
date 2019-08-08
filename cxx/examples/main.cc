/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>

#include "grpc/server.grpc.pb.h"
#include "grpc/server.pb.h"
#include "util/credentials.h"

std::string instance = "ed1548cc-d4eb-4938-85ee-5f1c3274df64";
std::string endpoint = "https://iam.test.cloud.ibm.com";
std::string apiKey = "1FHfWIVM5Hv54-NIkK5RJLFqH1ftSlnO3eu8y9l_J0Ce";
std::string url = "ep11.us-south.hs-crypto.test.cloud.ibm.com:9266";

typedef int test(std::shared_ptr<grep11::Crypto::Stub> client);

test testGenerateRandom;
test testECDSASignature;

struct oneTest {
    public:
    oneTest(std::string testName, test *runTest) : runTest(runTest), testName(testName){}

    test *runTest;
    std::string testName;
};

oneTest allTests[] = {
    {"testGenerateRandom", testGenerateRandom},
    {"testECDSASignature", testECDSASignature}
};

int main(int argc, char** argv) {
    auto call_credentials = new grep11::IAMPerRPCCredentials(instance, endpoint, apiKey);
    auto creds = grpc::CompositeChannelCredentials(
        grpc::SslCredentials(grpc::SslCredentialsOptions()),
        grpc::MetadataCredentialsFromPlugin(std::unique_ptr<grpc::MetadataCredentialsPlugin>(call_credentials)));
    auto client = std::shared_ptr<grep11::Crypto::Stub>(grep11::Crypto::NewStub(grpc::CreateChannel(url, creds)));

    int numTests = sizeof(allTests)/sizeof(oneTest);
    for (int i = 0; i < numTests; i++) {
        std::cout << "=== RUN   " << allTests[i].testName << std::endl;
        int rc = allTests[i].runTest(client);
        if (rc == 0) {
            std::cout << "--- PASS: " << allTests[i].testName << std::endl;
        } else {
            std::cout << "--- FAIL: " << allTests[i].testName << std::endl;
        }
    }
}

int testGenerateRandom(std::shared_ptr<grep11::Crypto::Stub> client){
    grpc::ClientContext context;
    grep11::GenerateRandomRequest request;
    grep11::GenerateRandomResponse response;

    request.set_len(20);

    grpc::Status status = client->GenerateRandom(&context, request, &response);
    if (status.ok() && response.rnd().length() == request.len()) {
      return 0;
    } else {
      return 1;
    }
}
