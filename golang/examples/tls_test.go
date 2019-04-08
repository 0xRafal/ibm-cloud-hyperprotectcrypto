package examples

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"

	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
	pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/util"
	grpc "google.golang.org/grpc"
)

//OpenEp11Connection open GRPC connection
func OpenEp11Connection(address string) (*grpc.ClientConn, error) {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("Cannot connect: %s", err)
	}
	return conn, nil
}

//SignSingle do SignSingle call to ep11 server and return signature byte array
func SignSingle(cryptoClient pb.CryptoClient, keyBlob []byte, digest []byte) ([]byte, error) {

	//Sign data
	SignSingleRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: keyBlob,
		Data:    digest,
	}
	SignSingleResponse, err := cryptoClient.SignSingle(context.Background(), SignSingleRequest)
	if err != nil {
		return nil, fmt.Errorf("SignSingle Error: %s", err)
	}
	return SignSingleResponse.Signature, nil
}

//GenerateECDSAKeyPair generate ECDSA key pair
func GenerateECDSAKeyPair(cryptoClient pb.CryptoClient, nBits int32) ([]byte, []byte, error) {
	oidNamedCurve := util.GetCurveOIDFromNumBits(nBits)
	if oidNamedCurve == nil {
		return nil, nil, fmt.Errorf("Unsupported bits of curve: %d", nBits)
	}
	ecParameters, err := asn1.Marshal(oidNamedCurve)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable To Encode Parameter OID: %s", err)
	}

	publicKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_EC_PARAMS, ecParameters),
		util.NewAttribute(ep11.CKA_VERIFY, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	privateKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_SIGN, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	generateECKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  publicKeyECTemplate,
		PrivKeyTemplate: privateKeyECTemplate,
	}
	var ecKeypairResponse *pb.GenerateKeyPairResponse
	ecKeypairResponse, err = cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("Generate Alice EC Key Pair Error: %s", err)
	}
	return ecKeypairResponse.PrivKey, ecKeypairResponse.PubKey, nil
}

//ECDSAPrivateKey MUST implement crypto.Signer interface so that tls crypt/tls package can take as ECDSAPrivateKey in
//tls.Certificate: https://golang.org/pkg/crypto/tls/#Certificate
type ECDSAPrivateKey struct {
	algorithmOID  asn1.ObjectIdentifier
	namedCurveOID asn1.ObjectIdentifier
	keyBlob       []byte
	pubKey        ecdsa.PublicKey
	cryptoClient  pb.CryptoClient
}

type ECDSASignature struct {
	R, S *big.Int
}

//Sign returns signature in ASN1 format
//Reference code crypto/ecdsa.go, func (priv *PrivateKey) Sign() ([]byte, error)
func (priv *ECDSAPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signature, err := SignSingle(priv.cryptoClient, priv.keyBlob, digest)
	if err != nil {
		return nil, fmt.Errorf("SignSingle failed: %s", err)
	}
	//ep11 return raw signature byte array, which must be encoded to ASN1 for tls package usage.
	var sigLen = len(signature)
	if sigLen%2 != 0 {
		return nil, fmt.Errorf("Signature length is not even[%d]", sigLen)
	}
	r := new(big.Int)
	s := new(big.Int)

	r.SetBytes(signature[0 : sigLen/2])
	s.SetBytes(signature[sigLen/2:])
	return asn1.Marshal(ECDSASignature{r, s})
}

//Public implement crypto.Signer interface
func (priv *ECDSAPrivateKey) Public() crypto.PublicKey {
	return &priv.pubKey
}

func newECDSASigner(cryptoClient pb.CryptoClient, nBits int32) (*ECDSAPrivateKey, error) {
	priv := new(ECDSAPrivateKey)
	priv.cryptoClient = cryptoClient
	priv.algorithmOID = util.OIDECPublicKey
	priv.pubKey.Curve, priv.namedCurveOID = util.GetNamedCurveAndOIDFromNumBits(nBits)
	if priv.pubKey.Curve == nil {
		return nil, fmt.Errorf("Unsupported bits of curve: %d", nBits)
	}

	privKeyBlob, pubKeyBlob, err := GenerateECDSAKeyPair(cryptoClient, nBits)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate ECDSA key pair: %s", err)
	}
	priv.keyBlob = make([]byte, len(privKeyBlob))
	copy(priv.keyBlob, privKeyBlob)
	priv.pubKey, err = util.GetECPubKeyFromSPKIBlob(priv.namedCurveOID, pubKeyBlob)
	if err != nil {
		return nil, fmt.Errorf("Failed to get public coordinates: %s", err)
	}

	return priv, nil
}

func createECDSASelfSignedCert(privKey *ECDSAPrivateKey, commonName string,
	sigAlg x509.SignatureAlgorithm) ([]byte, error) {

	template := x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		Issuer: pkix.Name{
			CommonName: commonName,
		},
		SignatureAlgorithm:    sigAlg,
		PublicKeyAlgorithm:    x509.ECDSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		AuthorityKeyId:        []byte{1, 2, 3, 4, 5}, //for self-signed certificate, AuthorityKeyId MUST match SubjectKeyId
	}

	certDERBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, privKey.Public(), privKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to create certificate: %s", err)
	}
	return certDERBytes, nil
}

//ECDSAPrivateKeyTypeASN1 defines EC key type
type ECDSAPrivateKeyTypeASN1 struct {
	KeyTypeOID asn1.ObjectIdentifier
	CurveOID   asn1.ObjectIdentifier
}

//ECDSAPrivateKeyASN1 defines asn1 encoding
type ECDSAPrivateKeyASN1 struct {
	Version int
	KeyType ECDSAPrivateKeyTypeASN1
	KeyBlob []byte
}

//functions for test
var httpAddr = ":4321"

func httpHandler(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte("Hello"))
}

//StartServer starts https server
func CreateServer(tlsCert tls.Certificate) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", httpHandler)

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	httpServer := &http.Server{
		Addr:      httpAddr,
		Handler:   mux,
		TLSConfig: &tlsConfig,
	}
	return httpServer
}

func StartServer(httpServer *http.Server) {
	httpServer.ListenAndServeTLS("", "")
}

type httpTestClient struct {
	httpClient *http.Client
	serverAddr string
}

func newHTTPTestClient(caCertDER []byte, tlsCert tls.Certificate) *httpTestClient {
	x509Cert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		fmt.Printf("x509.ParseCertificate failed: %s\n", err)
		return nil
	}
	clientCertPool := x509.NewCertPool()
	// Append the client certificates from the CA
	clientCertPool.AddCert(x509Cert)

	// Create the TLS credentials for transport
	clientTLSCfg := tls.Config{
		ServerName:   "localhost",
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      clientCertPool,
	}
	transport := http.Transport{
		TLSClientConfig: &clientTLSCfg,
	}
	testClient := &httpTestClient{
		httpClient: &http.Client{Transport: &transport},
		serverAddr: "https://localhost" + httpAddr,
	}
	return testClient
}

func (client *httpTestClient) ping() (string, error) {
	resp, err := client.httpClient.Get(client.serverAddr)
	if err != nil {
		return "", fmt.Errorf("Http client get failed: %s", err)
	}
	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("ioutil.ReadAll failed: %s", err)
	}
	return string(data), nil
}

//Example_tls tests TLS communication between client and server, where certificate and private key are generated on the fly
func Example_tls() {
	conn, err := OpenEp11Connection(address)
	if err != nil {
		fmt.Printf("OpenEp11Connection err: %s\n", err)
		return
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

	//create signer and raw certificate to build up TLS certificate
	priv, err := newECDSASigner(cryptoClient, 256)
	if err != nil {
		fmt.Printf("newECDSASigner err: %s\n", err)
		return
	}
	certDER, err := createECDSASelfSignedCert(priv, "localhost", x509.ECDSAWithSHA256)
	if err != nil {
		fmt.Printf("createECDSASelfSignedCert err: %s\n", err)
		return
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	//start server thread
	httpServer := CreateServer(tlsCert)
	go StartServer(httpServer)

	time.Sleep(1 * time.Second)

	//create TLS client
	client := newHTTPTestClient(certDER, tlsCert)
	strResp, err := client.ping()
	if err != nil {
		fmt.Printf("Ping failed: %s\n", err)
	} else {
		fmt.Printf("Response data from https server: [%s]\n", strResp)
	}

	httpServer.Shutdown(context.Background())
	return

	// Output:
	// Response data from https server: [Hello]
}
