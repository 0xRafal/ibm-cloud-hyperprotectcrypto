# Overview

1. [Install Golang](https://golang.org/doc/install)
2. [Change GREP11 server address](https://github.com/Vincent26-Chen/ibm-cloud-hyperprotectcrypto/blob/master/golang/examples/server_test.go#L22) in `examples/server_test.go` file
3. cd `$GOPATH/src/github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/examples`
4. Execute the example by issuing the command `go test -v`
5. You will see similiar output as the following from the sample program:

    ```Bash
    === RUN   Example_getMechnismInfo
    --- PASS: Example_getMechnismInfo (0.74s)
    === RUN   Example_encryptAndecrypt
    --- PASS: Example_encryptAndecrypt (0.05s)
    === RUN   Example_digest
    --- PASS: Example_digest (0.02s)
    === RUN   Example_signAndVerifyUsingRSAKeyPair
    --- PASS: Example_signAndVerifyUsingRSAKeyPair (0.65s)
    === RUN   Example_wrapAndUnwrapKey
    --- PASS: Example_wrapAndUnwrapKey (0.64s)
    === RUN   Example_deriveKey
    --- PASS: Example_deriveKey (0.11s)
    PASS
    ok  	github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/examples	2.250s
    ```

## Things to consider

This example does not use TLS. If you would like to experiment with TLS, review https://grpc.io/docs/guides/auth.html on how to implement TLS with GRPC.

## TODO

- The mock server needs to be implemented
- Implement language bindings for other languages