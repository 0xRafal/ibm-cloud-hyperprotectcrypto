package main

import (
	"context"
	"encoding/asn1"
	"fmt"
	"reflect"

	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
	pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/util"
	uuid "github.com/satori/go.uuid"
	grpc "google.golang.org/grpc"
)

const (
	address = "zlxcn002.torolab.ibm.com:9876"
)

func getMechnismInfo() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		panic(fmt.Errorf("did not connect: %v", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	mechanismListRequest := &pb.GetMechanismListRequest{}
	mechanismListResponse, err := cryptoClient.GetMechanismList(context.Background(), mechanismListRequest)
	if err != nil {
		panic(fmt.Errorf("Get mechanism list error: %s", err))
	}
	fmt.Printf("Get mechanism list successfully:\n%v ...\n", mechanismListResponse.Mechs[:8])

	mechanismInfoRequest := &pb.GetMechanismInfoRequest{
		Mech: ep11.CKM_RSA_PKCS,
	}
	mechanismInfoResponse, err := cryptoClient.GetMechanismInfo(context.Background(), mechanismInfoRequest)
	if err != nil {
		panic(fmt.Errorf("Get mechanism info error: %s", err))
	}
	fmt.Printf("Get CKM_RSA_PKCS mechanism info successfully: %v\n", mechanismInfoResponse.MechInfo)

	// Output:
	// [ CKM_RSA_PKCS CKM_RSA_PKCS_KEY_PAIR_GEN CKM_RSA_X9_31_KEY_PAIR_GEN CKM_RSA_PKCS_PSS CKM_SHA1_RSA_X9_31 CKM_SHA1_RSA_PKCS CKM_SHA1_RSA_PKCS_PSS CKM_SHA256_RSA_PKCS] ...
	// Get CKM_RSA_PKCS mechanism info successfully: MinKeySize:512 MaxKeySize:4096 Flags:404224
}

func encryptAndecrypt() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		panic(fmt.Errorf("did not connect: %v", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)
	keyLen := 128
	keyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_VALUE_LEN, (uint64)(keyLen/8)),
		util.NewAttribute(ep11.CKA_WRAP, false), // will you call wrap/unwrap?
		util.NewAttribute(ep11.CKA_UNWRAP, false),
		util.NewAttribute(ep11.CKA_ENCRYPT, true),
		util.NewAttribute(ep11.CKA_DECRYPT, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false), // set to false!
		util.NewAttribute(ep11.CKA_TOKEN, true),        // ignored by EP11
	)

	keygenmsg := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: keyTemplate,
		KeyId:    uuid.NewV4().String(), //optional
	}

	generateKeyStatus, err := cryptoClient.GenerateKey(context.Background(), keygenmsg)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}
	fmt.Println("Generated AES Key")

	rngTemplate := &pb.GenerateRandomRequest{
		Len: (uint64)(ep11.AES_BLOCK_SIZE),
	}
	rng, err := cryptoClient.GenerateRandom(context.Background(), rngTemplate)
	if err != nil {
		panic(fmt.Errorf("GenerateRandom Error: %s", err))
	}
	iv := rng.Rnd[:ep11.AES_BLOCK_SIZE]
	fmt.Println("Generated IV succefully")

	encipherInitInfo := &pb.EncryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: iv},
		Key:  generateKeyStatus.Key, // you may want to store this out
	}
	cipherStateInit, err := cryptoClient.EncryptInit(context.Background(), encipherInitInfo)
	if err != nil {
		panic(fmt.Errorf("Failed EncryptInit [%s]", err))
	}

	plain := []byte("Hello, this is a very long and creative message without any imagination")

	encipherDataUpdate := &pb.EncryptUpdateRequest{
		State: cipherStateInit.State,
		Plain: plain[:20],
	}
	encipherStateUpdate, err := cryptoClient.EncryptUpdate(context.Background(), encipherDataUpdate)
	if err != nil {
		panic(fmt.Errorf("Failed Encrypt [%s]", err))
	}

	ciphertext := encipherStateUpdate.Ciphered[:]
	encipherDataUpdate = &pb.EncryptUpdateRequest{
		State: encipherStateUpdate.State,
		Plain: plain[20:],
	}
	encipherStateUpdate, err = cryptoClient.EncryptUpdate(context.Background(), encipherDataUpdate)
	if err != nil {
		panic(fmt.Errorf("Failed Encrypt [%s]", err))
	}

	ciphertext = append(ciphertext, encipherStateUpdate.Ciphered...)
	encipherDataFinal := &pb.EncryptFinalRequest{
		State: encipherStateUpdate.State,
	}
	encipherStateFinal, err := cryptoClient.EncryptFinal(context.Background(), encipherDataFinal)
	if err != nil {
		panic(fmt.Errorf("Failed EncryptFinal [%s]", err))
	}

	ciphertext = append(ciphertext, encipherStateFinal.Ciphered...)
	fmt.Println("Encrypted message")

	decipherInitInfo := &pb.DecryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: iv},
		Key:  generateKeyStatus.Key, // you may want to store this out
	}
	decipherStateInit, err := cryptoClient.DecryptInit(context.Background(), decipherInitInfo)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptInit [%s]", err))
	}

	decipherDataUpdate := &pb.DecryptUpdateRequest{
		State:    decipherStateInit.State,
		Ciphered: ciphertext[:16],
	}
	decipherStateUpdate, err := cryptoClient.DecryptUpdate(context.Background(), decipherDataUpdate)
	if err != nil {
		panic(fmt.Errorf("Failed Encrypt [%s]", err))
	}

	plaintext := decipherStateUpdate.Plain[:]
	decipherDataUpdate = &pb.DecryptUpdateRequest{
		State:    decipherStateUpdate.State,
		Ciphered: ciphertext[16:],
	}
	decipherStateUpdate, err = cryptoClient.DecryptUpdate(context.Background(), decipherDataUpdate)
	if err != nil {
		panic(fmt.Errorf("Failed Encrypt [%s]", err))
	}
	plaintext = append(plaintext, decipherStateUpdate.Plain...)

	decipherDataFinal := &pb.DecryptFinalRequest{
		State: decipherStateUpdate.State,
	}
	decipherStateFinal, err := cryptoClient.DecryptFinal(context.Background(), decipherDataFinal)
	if err != nil {
		panic(fmt.Errorf("Failed EncryptFinal [%s]", err))
	}
	plaintext = append(plaintext, decipherStateFinal.Plain...)

	if !reflect.DeepEqual(plain, plaintext) {
		panic(fmt.Errorf("Failed comparing plain text of cipher single"))
	}

	fmt.Printf("Decrypted message\n%s\n", plaintext)

	// Output:
	// Generated AES Key
	// Generated IV
	// Encrypted message
	// Decrypted message
	// Hello, this is a very long and creative message without any imagination
}

func digest() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		panic(fmt.Errorf("did not connect: %v", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	digestData := []byte("This is the data longer than 64 bytes so that multiple digest operation is needed")
	digestInitRequest := &pb.DigestInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_SHA_1},
	}
	digestInitResponse, err := cryptoClient.DigestInit(context.Background(), digestInitRequest)
	if err != nil {
		panic(fmt.Errorf("Digest init error: %s", err))
	}
	digestRequest := &pb.DigestRequest{
		State: digestInitResponse.State,
		Data:  digestData,
	}
	digestResponse, err := cryptoClient.Digest(context.Background(), digestRequest)
	if err != nil {
		panic(fmt.Errorf("Digest error: %s", err))
	} else {
		fmt.Printf("Digest data using single digest operation: %x\n", digestResponse.Digest)
	}
	//Digest using mutiple operations
	digestInitResponse, err = cryptoClient.DigestInit(context.Background(), digestInitRequest)
	if err != nil {
		panic(fmt.Errorf("Digest init error: %s", err))
	}
	digestUpdateRequest := &pb.DigestUpdateRequest{
		State: digestInitResponse.State,
		Data:  digestData[:64],
	}
	digestUpdateResponse, err := cryptoClient.DigestUpdate(context.Background(), digestUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("Digest update error: %s", err))
	}
	digestUpdateRequest = &pb.DigestUpdateRequest{
		State: digestUpdateResponse.State,
		Data:  digestData[64:],
	}
	digestUpdateResponse, err = cryptoClient.DigestUpdate(context.Background(), digestUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("Digest Update Error: %s", err))
	}
	digestFinalRequestInfo := &pb.DigestFinalRequest{
		State: digestUpdateResponse.State,
	}
	digestFinalResponse, err := cryptoClient.DigestFinal(context.Background(), digestFinalRequestInfo)
	if err != nil {
		panic(fmt.Errorf("Digest Final Error: %s", err))
	} else {
		fmt.Printf("Digest data using multiple operations: %x\n", digestFinalResponse.Digest)
	}

	// Output:
	// Digest data using single digest operation: 294f19f8adf4d0276a51f56bd91dc2638e76524a
	// Digest data using multiple operations: 294f19f8adf4d0276a51f56bd91dc2638e76524a
}

func signAndVerifyUsingRSAKeyPair() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		panic(fmt.Errorf("did not connect: %v", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	//Generate RSA key pairs
	publicExponent := []byte{0x11}
	publicKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_ENCRYPT, true),
		util.NewAttribute(ep11.CKA_VERIFY, true), //to verify a signature
		util.NewAttribute(ep11.CKA_MODULUS_BITS, uint64(2048)),
		util.NewAttribute(ep11.CKA_PUBLIC_EXPONENT, publicExponent),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	privateKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_PRIVATE, true),
		util.NewAttribute(ep11.CKA_SENSITIVE, true),
		util.NewAttribute(ep11.CKA_DECRYPT, true),
		util.NewAttribute(ep11.CKA_SIGN, true), //to generate signature
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS_KEY_PAIR_GEN},
		PubKeyTemplate:  publicKeyTemplate,
		PrivKeyTemplate: privateKeyTemplate,
		PrivKeyId:       uuid.NewV4().String(),
		PubKeyId:        uuid.NewV4().String(),
	}
	generateKeyPairStatus, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair Error: %s", err))
	}
	fmt.Println("Generated RSA PKCS key pairs successfully")

	//Sign data
	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_SHA1_RSA_PKCS},
		PrivKey: generateKeyPairStatus.PrivKey,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit Error: %s", err))
	}
	signData := []byte("These data need to be signed")
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData,
	}
	SignResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign Error: %s", err))
	}
	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_SHA1_RSA_PKCS},
		PubKey: generateKeyPairStatus.PubKey,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit Error: %s", err))
	}
	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      signData,
		Signature: SignResponse.Signature,
	}
	_, err = cryptoClient.Verify(context.Background(), verifyRequest)
	if err != nil {
		panic(fmt.Errorf("Verify Error: %s", err))
	}
	fmt.Println("Verify successfully")

	// Output:
	// Generated RSA PKCS key pairs successfully
	// Data signed
	// Verify successfully
}

func wrapAndUnwrapKey() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		panic(fmt.Errorf("did not connect: %v", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	//Generate a DES3 key
	desKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_VALUE_LEN, (uint64)(128/8)),
		util.NewAttribute(ep11.CKA_ENCRYPT, true),
		util.NewAttribute(ep11.CKA_DECRYPT, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, true), // must be true to be wrapped
	)
	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_DES3_KEY_GEN},
		Template: desKeyTemplate,
		KeyId:    uuid.NewV4().String(), //optional
	}
	generateNewKeyStatus, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Generate DES3 Key Error: %s", err))
	}
	fmt.Printf("Generated DES3 key with checksum %v\n", generateNewKeyStatus.CheckSum[:3])

	//Generate RSA key pairs
	publicExponent := []byte{0x11}
	publicKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_ENCRYPT, true),
		util.NewAttribute(ep11.CKA_WRAP, true), //to wrap a key
		util.NewAttribute(ep11.CKA_MODULUS_BITS, uint64(2048)),
		util.NewAttribute(ep11.CKA_PUBLIC_EXPONENT, publicExponent),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	privateKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_PRIVATE, true),
		util.NewAttribute(ep11.CKA_SENSITIVE, true),
		util.NewAttribute(ep11.CKA_DECRYPT, true),
		util.NewAttribute(ep11.CKA_UNWRAP, true), //to unwrap a key
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS_KEY_PAIR_GEN},
		PubKeyTemplate:  publicKeyTemplate,
		PrivKeyTemplate: privateKeyTemplate,
		PrivKeyId:       uuid.NewV4().String(),
		PubKeyId:        uuid.NewV4().String(),
	}
	generateKeyPairStatus, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair Error: %s", err))
	}
	fmt.Println("Generated PKCS key pairs successfully")

	wrapKeyRequest := &pb.WrapKeyRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		KeK:  generateKeyPairStatus.PubKey,
		Key:  generateNewKeyStatus.Key,
	}
	wrapKeyResponse, err := cryptoClient.WrapKey(context.Background(), wrapKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Wrap DES3 key error: %s", err))
	}
	fmt.Println("Wrap DES3 key successfully")

	desUnwrapKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_CLASS, ep11.CKO_SECRET_KEY),
		util.NewAttribute(ep11.CKA_KEY_TYPE, ep11.CKK_DES3),
		util.NewAttribute(ep11.CKA_VALUE_LEN, (uint64)(128/8)),
		util.NewAttribute(ep11.CKA_ENCRYPT, true),
		util.NewAttribute(ep11.CKA_DECRYPT, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, true), // must be true to be wrapped
	)
	unwrapRequest := &pb.UnwrapKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		KeK:      generateKeyPairStatus.PrivKey,
		Wrapped:  wrapKeyResponse.Wrapped,
		Template: desUnwrapKeyTemplate,
	}
	unWrapedResponse, err := cryptoClient.UnwrapKey(context.Background(), unwrapRequest)
	if err != nil {
		panic(fmt.Errorf("Unwrap DES3 key error: %s", err))
	}
	fmt.Printf("Unwrap DES3 key successfully with checksum %v\n", unWrapedResponse.CheckSum[:3])

	// Output:
	// Generated DES3 key with checksum [...]
	// Generated PKCS key pairs successfully
	// Wrap DES3 key successfully
	// Unwrap DES3 key successfully with checksum [...]
}

//algorithmIdentifier is defined in RFC5480, section 2
type algorithmIdentifier struct {
	OID  asn1.ObjectIdentifier
	Para asn1.ObjectIdentifier `asn:"optional"`
}

//subjectPublicKeyInfo is defined in RFC5480, section 2
type subjectPublicKeyInfo struct {
	AlgorithmID algorithmIdentifier
	Ycodinator  asn1.BitString
}

//getYByECSPKI extracts Y coordinate from public key in SPKI format
func getYByECSPKI(spki []byte) []byte {
	pubKey := new(subjectPublicKeyInfo)
	_, err := asn1.Unmarshal(spki, pubKey)
	if err != nil {
		fmt.Printf("Unmarshal error %v\n", err)
		return nil
	}
	return pubKey.Ycodinator.Bytes
}

func deriveKey() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		panic(fmt.Errorf("did not connect: %v", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	//Generate ECDH key pairs for Alice and Bob
	ecParameters := []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
	publicKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_EC_PARAMS, ecParameters),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	privateKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_DERIVE, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	generateECKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  publicKeyECTemplate,
		PrivKeyTemplate: privateKeyECTemplate,
		PrivKeyId:       uuid.NewV4().String(),
		PubKeyId:        uuid.NewV4().String(),
	}
	aliceECKeypairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("Generate Alice EC Key Pair Error: %s", err))
	}
	fmt.Println("Generated Alice EC key pairs successfully")
	bobECKeypairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("Generate Bob EC Key Pair Error: %s", err))
	}
	fmt.Println("Generated Bob EC key pairs successfully")

	//Derive AES key for Alice
	deriveKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_CLASS, uint64(ep11.CKO_SECRET_KEY)),
		util.NewAttribute(ep11.CKA_KEY_TYPE, uint64(ep11.CKK_AES)),
		util.NewAttribute(ep11.CKA_VALUE_LEN, (uint64)(128/8)),
		util.NewAttribute(ep11.CKA_ENCRYPT, true),
		util.NewAttribute(ep11.CKA_DECRYPT, true),
	)
	aliceDerivekeyRequest := &pb.DeriveKeyRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_ECDH1_DERIVE, Parameter: getYByECSPKI(bobECKeypairResponse.PubKey)},
		//pubkey cannot be used here, instead, the Y cordinator bit string shall be used as parameter
		Template: deriveKeyTemplate,
		BaseKey:  aliceECKeypairResponse.PrivKey,
	}
	aliceDerivekeyResponse, err := cryptoClient.DeriveKey(context.Background(), aliceDerivekeyRequest)
	if err != nil {
		panic(fmt.Errorf("Alice EC Key Derive Error: %s", err))
	}
	fmt.Printf("Alice AES key derives successfully with checksum %v\n", aliceDerivekeyResponse.CheckSum)

	//Derive AES key for Bob
	bobDerivekeyRequest := &pb.DeriveKeyRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_ECDH1_DERIVE, Parameter: getYByECSPKI(aliceECKeypairResponse.PubKey)},
		//pubkey cannot be used here, instead, the Y cordinator bit string shall be used as parameter
		Template: deriveKeyTemplate,
		BaseKey:  bobECKeypairResponse.PrivKey,
	}
	bobDerivekeyResponse, err := cryptoClient.DeriveKey(context.Background(), bobDerivekeyRequest)
	if err != nil {
		panic(fmt.Errorf("Bob EC Key Derive Error: %s", err))
	}
	fmt.Printf("Bob AES key derives successfully with checksum %v\n", bobDerivekeyResponse.CheckSum)

	return

	// Output:
	// Generated Alice EC key pairs successfully
	// Generated Bob EC key pairs successfully
	// Alice EC key derive successfully with checksum [...]
	// Bob EC key derive successfully with checksum [...]
}

func main() {
	getMechnismInfo()
	encryptAndecrypt()
	digest()
	signAndVerifyUsingRSAKeyPair()
	wrapAndUnwrapKey()
	deriveKey()
}
