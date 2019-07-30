#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <internal/evp_int.h>
#include <internal/asn1_int.h>
#include <internal/x509_int.h>

#include <evp/evp_locl.h>
#include <ec/ec_lcl.h>
#include <asn1/asn1_locl.h>

//ep11 API
int RemoteGenerateECDSAKeyPair(const unsigned char *curveOIDData, size_t curveOIDLength, unsigned char *privateKey, size_t *privateKeyLen, 
    unsigned char *pubKey, size_t *pubKeyLen);
int RemoteSignSingle(const unsigned char * privateKeyBlob, size_t keyBlobLen, const unsigned char * dgst, size_t dgstLen, unsigned char * signature, size_t *signatureLen);

const static int KEYBLOB_HEADER_LEN = sizeof(size_t);
//openssl functions, not in .h files
EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);

//openssl functions implementation, not exported
//set public key from oct string
EC_KEY *o2i_ECPublicKey(EC_KEY **a, const unsigned char **in, long len)
{
    EC_KEY *ret = NULL;

    if (a == NULL || (*a) == NULL || (*a)->group == NULL) {
        /*
         * sorry, but a EC_GROUP-structur is necessary to set the public key
         */
        ECerr(EC_F_O2I_ECPUBLICKEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    ret = *a;
    if (ret->pub_key == NULL &&
        (ret->pub_key = EC_POINT_new(ret->group)) == NULL) {
        ECerr(EC_F_O2I_ECPUBLICKEY, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!EC_POINT_oct2point(ret->group, ret->pub_key, *in, len, NULL)) {
        ECerr(EC_F_O2I_ECPUBLICKEY, ERR_R_EC_LIB);
        return 0;
    }
    /* save the point conversion form */
    ret->conv_form = (point_conversion_form_t) (*in[0] & ~0x01);
    *in += len;
    return ret;
}

static ECDSA_SIG *my_ossl_ecdsa_sign_sig(const unsigned char *dgst, int dgst_len,
                               const BIGNUM *in_kinv, const BIGNUM *in_r,
                               EC_KEY *eckey)
{
    int ok = 0, i; 
    BIGNUM /* *kinv = NULL, *s,*/ *m = NULL;
    const BIGNUM *order = NULL;
    //BN_CTX *ctx = NULL;
    const EC_GROUP *group;
    ECDSA_SIG *ret;
    const BIGNUM *priv_key;
    
    size_t keyBlobLen = 0;
    unsigned char *ext_data = NULL, *keyBlobData = NULL;
    unsigned char sig[140]; // the biggest signature is (521+7)/8 * 2 = 132 bytes
    size_t siglen = 0;

    group = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);

    if (group == NULL || priv_key == NULL) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (!EC_KEY_can_sign(eckey)) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING);
        return NULL;
    }

    ret = ECDSA_SIG_new();
    if (ret == NULL) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->r = BN_new();
    ret->s = BN_new();
    if (ret->r == NULL || ret->s == NULL) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    /*s = ret->s;

    if ((ctx = BN_CTX_new()) == NULL
        || (m = BN_new()) == NULL) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_MALLOC_FAILURE);
        goto err;
    }*/

    order = EC_GROUP_get0_order(group);
    i = BN_num_bits(order);
    /*
     * Need to truncate digest if it is too long: first truncate whole bytes.
     * According to https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm, only
     * L leftmost bits of HASH is used to generate signature, where L is the bit length of the group order
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7) / 8;
    if (!BN_bin2bn(dgst, dgst_len, m)) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
        goto err;
    }
    /* If still too long, truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7))) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
        goto err;
    }

    ext_data = EC_KEY_get_ex_data(eckey, CRYPTO_EX_INDEX_EC_KEY);
    if (ext_data == NULL) {
        ECDSAerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_EC_LIB);
        printf("EC_EX_DATA_get_data failed\n");
        goto err;
    }
    memcpy(&keyBlobLen, ext_data, KEYBLOB_HEADER_LEN);
    keyBlobData = OPENSSL_malloc(keyBlobLen);
    if (keyBlobData == NULL) {
        ECDSAerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_MALLOC_FAILURE);
        printf("my_ossl_ecdsa_sign_sig OPENSSL_malloc %d bytes failed\n", (int)keyBlobLen);
        goto err;
    }
    memcpy(keyBlobData, ext_data + KEYBLOB_HEADER_LEN, keyBlobLen);

    siglen = sizeof(sig);
    int retRemote = RemoteSignSingle(keyBlobData, keyBlobLen, dgst, dgst_len, sig, &siglen);
    if (retRemote <= 0) {
        ECDSAerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_ENGINE_LIB);
        printf("RemoteSignSingle failed\n");
        goto err;
    }
    if (siglen % 2 != 0) {
        ECDSAerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_ENGINE_LIB);
        printf("Signature length is not even\n");
        goto err;
    }
    if (BN_bin2bn(sig, siglen/2, ret->r) == NULL) {
        ECDSAerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
        printf("BN_bin2bn for r failed\n");
        goto err;
    }
    if (BN_bin2bn(sig + siglen/2, siglen/2, ret->s) == NULL) {
        ECDSAerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
        printf("BN_bin2bn for s failed\n");
        goto err;
    }    

    ok = 1;
 err:
    if (!ok) {
        ECDSA_SIG_free(ret);
        ret = NULL;
    }
    //BN_CTX_free(ctx);
    BN_clear_free(m);
    //BN_clear_free(kinv);
    if (keyBlobData)
        OPENSSL_free(keyBlobData);
    return ret;
}

static EC_KEY_METHOD openssl_ec_key_method = {
    "my EC_KEY method",
    0,
    0,0,0,0,0,0, //These are 0s, same as crypto/ec/ec_kmeth.c static const EC_KEY_METHOD openssl_ec_key_method
    NULL, //ossl_ec_key_gen,
    NULL, //ossl_ecdh_compute_key,
    NULL, //ossl_ecdsa_sign,
    NULL, //ossl_ecdsa_sign_setup,
    my_ossl_ecdsa_sign_sig, //ossl_ecdsa_sign_sig,
    NULL, //ossl_ecdsa_verify,
    NULL, //ossl_ecdsa_verify_sig  
};

static const EC_KEY_METHOD *get_ec_key_method()
{
	const EC_KEY_METHOD *default_methods = EC_KEY_get_default_method();

    int (*psign)(int type, const unsigned char *dgst,
            int dlen, unsigned char *sig,
            unsigned int *siglen,
            const BIGNUM *kinv, const BIGNUM *r,
            EC_KEY *eckey);
    int (*psign_setup)(EC_KEY *eckey, BN_CTX *ctx_in,
            BIGNUM **kinvp, BIGNUM **rp);
            
    int (*pverify)(int type, const unsigned
            char *dgst, int dgst_len,
            const unsigned char *sigbuf,
            int sig_len, EC_KEY *eckey);
    int (*pverify_sig)(const unsigned char *dgst,
            int dgst_len,
            const ECDSA_SIG *sig,
            EC_KEY *eckey);

    int (*pck)(unsigned char **pout,
            size_t *poutlen,
            const EC_POINT *pub_key,
            const EC_KEY *ecdh);
            
    int (*pkeygen)(EC_KEY *key);
                                            
    EC_KEY_METHOD_get_sign(default_methods, &psign, &psign_setup, NULL);
    EC_KEY_METHOD_get_verify(default_methods, &pverify, &pverify_sig);
    EC_KEY_METHOD_get_compute_key(default_methods, &pck);
    EC_KEY_METHOD_get_keygen(default_methods, &pkeygen);
    
    openssl_ec_key_method.sign = psign;
    openssl_ec_key_method.sign_setup = psign_setup;
    openssl_ec_key_method.verify = pverify;
    openssl_ec_key_method.verify_sig = pverify_sig;
    openssl_ec_key_method.compute_key = pck;
    openssl_ec_key_method.keygen = pkeygen;
    
	return &openssl_ec_key_method;
}

//======PKEY_METHODS for EC
static EVP_PKEY_METHOD pkey_method;

static int get_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid)
{
    static int pkey_nids[] = {
        EVP_PKEY_EC,
        0};

    if (!pmeth){ /* get the list of supported nids */
        *nids = pkey_nids;
        return sizeof(pkey_nids) / sizeof(int) - 1;
    }

    /* get the EVP_PKEY_METHOD */
    switch (nid)
    {
    case EVP_PKEY_EC:
        *pmeth = &pkey_method;
        return 1; /* success */
    }
    printf("Unexpeced nid %d\n", nid);
    *pmeth = NULL;
    return 0;
}

//reference ec_key_simple_generate_key() in ec_key.c
static int my_ec_key_simple_generate_key(EC_KEY *eckey)
{
    int ok = 0;
    //BN_CTX *ctx = NULL;
    BIGNUM *priv_key = NULL;
    const BIGNUM *order = NULL;
    EC_POINT *pub_key = NULL;
    
    //added declarations
    EC_KEY * ret_ec_key = NULL;   
    unsigned char privateKey[640]; //keyblob is lower than 600 bytes
    unsigned char *pubKeyCoordinates = NULL;
    unsigned char * blobLenAndData = NULL;
    size_t privateKeyLen = 0;
    size_t pubKeyLen = 0;
    int success = 0, ret = 0;

    const EC_GROUP *group = NULL;
    const ASN1_OBJECT * curve_OID = NULL;
    unsigned char full_OID[64] = {0};

    if (eckey->priv_key == NULL) {
        priv_key = BN_new();
        if (priv_key == NULL)
            goto err;
    } else
        priv_key = eckey->priv_key;

    if (eckey->pub_key == NULL) {
        pub_key = EC_POINT_new(eckey->group);
        if (pub_key == NULL)
            goto err;
    } else
        pub_key = eckey->pub_key;

    eckey->priv_key = priv_key;
    eckey->pub_key = pub_key;
 
    //get curve OID
    group = EC_KEY_get0_group(eckey);
    if (group == NULL) {
        ECDSAerr(EC_F_PKEY_EC_KEYGEN, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }
    if (EC_GROUP_get_asn1_flag(group)) {
        int curve_name = EC_GROUP_get_curve_name(group);
        if (curve_name) {
            curve_OID = OBJ_nid2obj(curve_name);
            if (curve_OID == NULL) {
                ECDSAerr(EC_F_PKEY_EC_KEYGEN, EC_R_ASN1_ERROR);
                goto err;
            }
            //OBJ_nid2obj() returns internal static data and no need to free.
            //curve_OID is raw bytes without asn1 type and length, now we add them
            if (curve_OID->length + 2 > sizeof(full_OID)) {
                ECDSAerr(EC_F_PKEY_EC_KEYGEN, EC_R_ASN1_ERROR);
                goto err; 
            }
            memcpy(&full_OID[2], curve_OID->data, curve_OID->length);
            full_OID[0] = 0x06; //type is object identifier
            full_OID[1] = curve_OID->length;
        } 
        else {
            ECDSAerr(EC_F_PKEY_EC_KEYGEN, EC_R_INVALID_CURVE);
            goto err;
        }
    } 
    else {
        ECDSAerr(EC_F_PKEY_EC_KEYGEN, EC_R_ASN1_ERROR);
        goto err;
    }
    
    //get order bit size
    if ((order = EC_GROUP_get0_order(group)) == NULL) {
        ECDSAerr(EC_F_PKEY_EC_KEYGEN, EC_R_INVALID_GROUP_ORDER);
        goto err;
    }
    int bits = BN_num_bits(order);
    privateKeyLen = sizeof(privateKey);
    pubKeyLen = 2 * (bits+7)/8 + 1; //there is one header byte, "04" as uncompressed 
    pubKeyCoordinates = OPENSSL_malloc(pubKeyLen); 
    if (pubKeyCoordinates == NULL) {
        printf("my_ec_key_simple_generate_key OPENSSL_malloc %d failed\n", (int)pubKeyLen);
        goto err;       
    }
    success = RemoteGenerateECDSAKeyPair((const unsigned char *)full_OID, curve_OID->length + 2, privateKey, &privateKeyLen, pubKeyCoordinates, &pubKeyLen);
    if (success == 0) {
        printf("RemoteGenerateECDSAKeyPair failed\n");
        goto err;
    }

    //save privateKeyBlob.
    blobLenAndData = OPENSSL_malloc(privateKeyLen + KEYBLOB_HEADER_LEN);
    if (blobLenAndData == NULL) {
        printf("OPENSSL_malloc failed to allocate %d bytes\n", (int)(privateKeyLen + KEYBLOB_HEADER_LEN));
        goto err;
    }
    memcpy(blobLenAndData, &privateKeyLen, KEYBLOB_HEADER_LEN);
    memcpy(blobLenAndData + KEYBLOB_HEADER_LEN, privateKey, privateKeyLen);
    ret = EC_KEY_set_ex_data(eckey, CRYPTO_EX_INDEX_EC_KEY, (void *)blobLenAndData);
    if (ret <= 0) {
        printf("EC_KEY_set_ex_data failed\n");
        goto err;
    }
    //save public key to EC_KEY public key structure
    ret_ec_key = o2i_ECPublicKey(&eckey, (const unsigned char **)&pubKeyCoordinates, pubKeyLen);
    if (ret_ec_key != NULL) {
        pubKeyCoordinates -= pubKeyLen; //o2i_ECPublicKey change input pointer pubKeyCoordinates, need to change it back to free
        ok = 1;
    }
    else {
        EC_KEY_set_ex_data(eckey, CRYPTO_EX_INDEX_EC_KEY, NULL);
        printf("o2i_ECPublicKey return NULL\n");
    }
err:
    if (pubKeyCoordinates) {
        OPENSSL_free(pubKeyCoordinates);
    }
    if (ok <= 0 && blobLenAndData) {
        OPENSSL_free(blobLenAndData);
    }   
    return ok;
}

//reference pkey_ec_keygen() in ec_pmeth.c
static int my_pkey_ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    //openssl struct EC_PKEY_CTX defined in ec_pmeth.c, not in .h file
    typedef struct {
        /* Key and paramgen group */
        EC_GROUP *gen_group;
        /* message digest */
        const EVP_MD *md;
        /* Duplicate key if custom cofactor needed */
        EC_KEY *co_key;
        /* Cofactor mode */
        signed char cofactor_mode;
        /* KDF (if any) to use for ECDH */
        char kdf_type;
        /* Message digest to use for key derivation */
        const EVP_MD *kdf_md;
        /* User key material */
        unsigned char *kdf_ukm;
        size_t kdf_ukmlen;
        /* KDF output length */
        size_t kdf_outlen;
    } EC_PKEY_CTX;
    
    int ret = 0;
    EC_KEY *ec = NULL;
    EC_PKEY_CTX *dctx = ctx->data;
    if (ctx->pkey == NULL && dctx->gen_group == NULL) {
        ECerr(EC_F_PKEY_EC_KEYGEN, EC_R_NO_PARAMETERS_SET);
        return 0;
    }
    ec = EC_KEY_new();
    if (ec == NULL)
        return 0;
    if (!EVP_PKEY_assign_EC_KEY(pkey, ec)) {
        EC_KEY_free(ec);
        return 0;
    }
    /* Note: if error is returned, we count on caller to free pkey->pkey.ec */
    if (ctx->pkey != NULL)
        ret = EVP_PKEY_copy_parameters(pkey, ctx->pkey);
    else
        ret = EC_KEY_set_group(ec, dctx->gen_group);   
    if (ret == 0) {
        return 0;
    }
    //reference EC_KEY_generate_key() in ec_key.c
    ec->priv_key = BN_new();
    ec->pub_key = EC_POINT_new(ec->group); 
    return my_ec_key_simple_generate_key(ec);  
}
//======PKEY_METHODS for EC ends

//======PKEY_ASN1_METHODS for EC
static EVP_PKEY_ASN1_METHOD pkey_asn1_method;

static int get_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **pmeth, const int **nids, int nid)
{
    static int pkey_asn1_nids[] = {
        EVP_PKEY_EC,
        0};

    if (!pmeth){ /* get the list of supported nids */
        *nids = pkey_asn1_nids;
        return sizeof(pkey_asn1_nids) / sizeof(int) - 1;
    }
    switch (nid)
    {
    case EVP_PKEY_EC:
        *pmeth = &pkey_asn1_method;
        return 1; /* success */
    }
    printf("Unexpeced nid %d\n", nid);
    *pmeth = NULL;
    return 0;
}

static char* my_pem_str = "EC";

//reference ec_ameth.c, removed V_ASN1_SEQUENCE part
static EC_KEY *eckey_type2param(int ptype, const void *pval)
{
    EC_KEY *eckey = NULL;
    EC_GROUP *group = NULL;

    if (ptype == V_ASN1_OBJECT) {
        const ASN1_OBJECT *poid = pval;

        /*
         * type == V_ASN1_OBJECT => the parameters are given by an asn1 OID
         */
        if ((eckey = EC_KEY_new()) == NULL) {
            ECerr(EC_F_ECKEY_TYPE2PARAM, ERR_R_MALLOC_FAILURE);
            goto ecerr;
        }
        group = EC_GROUP_new_by_curve_name(OBJ_obj2nid(poid));
        if (group == NULL)
            goto ecerr;
        EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
        if (EC_KEY_set_group(eckey, group) == 0)
            goto ecerr;
        EC_GROUP_free(group);
    } else {
        ECerr(EC_F_ECKEY_TYPE2PARAM, EC_R_DECODE_ERROR);
        goto ecerr;
    }

    return eckey;

 ecerr:
    EC_KEY_free(eckey);
    EC_GROUP_free(group);
    return NULL;
}

static int my_priv_decode (EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)
{
    X509_ALGOR *pkeyalg = p8->pkeyalg;
    ASN1_OCTET_STRING *blobData = p8->pkey;
    unsigned char * blobLenAndData = NULL;

    if (blobData == NULL) {
        printf("p8->pkey is NULL\n");
        return 0;
    } else if (blobData->data == NULL) {
        printf("p8->pkey->data is NULL\n");
        return 0;       
    }

    unsigned char *keyBlobRaw = blobData->data;
    size_t keyBlobRawLen = blobData->length;

    //reference eckey_priv_decode() in ec_ameth.c 
    const void *pval = NULL;
    int ptype;
    EC_KEY *eckey = NULL;

    X509_ALGOR_get0(NULL, &ptype, &pval, pkeyalg);
    eckey = eckey_type2param(ptype, pval);
    if (!eckey){
        printf("eckey_type2param failed\n");
        goto ecliberr;
    }

    //setup EC Private key
    if (eckey->priv_key) {
        BN_free(eckey->priv_key);
    }
    eckey->priv_key = BN_new();

    //setup keyBlob
    blobLenAndData = OPENSSL_malloc(keyBlobRawLen + KEYBLOB_HEADER_LEN);
    if (blobLenAndData == NULL) {
        printf("my_priv_decode OPENSSL_malloc %d bytes failed\n", (int)(keyBlobRawLen + KEYBLOB_HEADER_LEN));
        goto ecliberr;
    }
    memcpy(blobLenAndData, &keyBlobRawLen, KEYBLOB_HEADER_LEN);
    memcpy(blobLenAndData + KEYBLOB_HEADER_LEN, keyBlobRaw, keyBlobRawLen);
    int ret = EC_KEY_set_ex_data(eckey, CRYPTO_EX_INDEX_EC_KEY, (void *)blobLenAndData);
    if (ret <= 0) {
        printf("EC_KEY_set_ex_data in my_priv_decode failed\n");
        goto ecliberr;       
    } else {
        blobLenAndData = NULL;
    }

    EVP_PKEY_assign_EC_KEY(pkey, eckey);
    pkey->type = EVP_PKEY_EC;
    return 1;

 ecliberr:
    ECerr(EC_F_ECKEY_PRIV_DECODE, EC_R_DECODE_ERROR);
    if (eckey)
        EC_KEY_free(eckey);
    if (blobLenAndData) {
        OPENSSL_free(blobLenAndData);
    }
    return 0;
}

static int my_priv_encode (PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk)
{
    int ok = 0;
    EC_KEY *ec_key = pk->pkey.ec;
    unsigned char *ext_data, *keyBlobData = NULL;
    int ptype;
    size_t keyBlobLen = 0;

    //get group parameter first. get reference code from ec_asn1.c
    ASN1_OBJECT* pval = NULL;
    const EC_GROUP *group;
    int nid;

    if ((group = EC_KEY_get0_group(ec_key)) == NULL) {
        ECerr(EC_F_ECKEY_PARAM2TYPE, EC_R_UNKNOWN_GROUP);
        return 0;
    }
    if ((nid = EC_GROUP_get_curve_name(group)) != 0){
        pval = OBJ_nid2obj(nid);
        ptype = V_ASN1_OBJECT; //set ptype = V_ASN1_UNDEF; if want the PEM file not including algorithm information
    }
    else {
        printf("get group parameters failed: %d\n", nid);
        return 0;
    }

    unsigned int old_flags = EC_KEY_get_enc_flags(ec_key);
    EC_KEY_set_enc_flags(ec_key, old_flags | EC_PKEY_NO_PUBKEY);

    //copy keyblob data into memory
    ext_data = EC_KEY_get_ex_data(ec_key, CRYPTO_EX_INDEX_EC_KEY);
    if (ext_data == NULL) {
        printf("Get ec_key ext data failed\n");
        return 0;
    }
    memcpy(&keyBlobLen, ext_data, KEYBLOB_HEADER_LEN); //length of keyblob
    keyBlobData = OPENSSL_malloc(keyBlobLen);
    if (keyBlobData == NULL) {
        printf("OPENSSL_malloc failed to allocate %d bytes\n", (int)keyBlobLen);
        return 0;
    }
    memcpy(keyBlobData, ext_data + KEYBLOB_HEADER_LEN, keyBlobLen);
    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_X9_62_id_ecPublicKey), 0, ptype, pval, keyBlobData, (int)keyBlobLen)) {
        printf("PKCS8_pkey_set0 failed\n");
        goto encode_err;
    }
    if (ec_key->priv_key) {
        BN_zero(ec_key->priv_key);
    }
    ok = 1;

encode_err:
    if (ok <= 0 && keyBlobData) {
        OPENSSL_free(keyBlobData);
    }
    return ok;
}

/*this function is called when reading private key
 "openssl ec -engine xxx.so -in prikey-my.pem" -text -noout
 */
static int my_priv_print (BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)
{
    BIO_printf(out, "HSM EC key\n");
    return 1;
}

//function called in EVP_PKEY_cmp() when loading private key and certificate. Must return 1 for successful match
static int my_pub_cmp (const EVP_PKEY *a, const EVP_PKEY *b)
{
    return 1;
}
//function called in EVP_PKEY_cmp() when loading private key and certificate. Must return 1 for successful match
static int my_param_cmp (const EVP_PKEY *a, const EVP_PKEY *b)
{
    return 1;
}

//======PKEY_ASN1_METHODS for EC ends

//======Load private key
static EVP_PKEY *load_privkey(ENGINE *engine, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
    //reference openssl_load_privkey() in eng_openssl.c
    BIO *in;
    EVP_PKEY *key;
    in = BIO_new_file(s_key_id, "r");
    if (!in)
        return NULL;
    key = PEM_read_bio_PrivateKey(in, NULL, 0, NULL);
    BIO_free(in);
    return key;
}
//======Load private key ends

//=====Engine bind
static const char *engine_id = "grep11";
static const char *engine_name = "grep11 engine";
static int bind_helper(ENGINE *e, const char *id)
{
    int ret = 0;

    //setup pkey methods
    EVP_PKEY_METHOD *orig_meth = (EVP_PKEY_METHOD *)EVP_PKEY_meth_find(EVP_PKEY_EC);
    if (orig_meth != NULL){
        pkey_method.pkey_id = orig_meth->pkey_id;
        EVP_PKEY_meth_copy(&pkey_method, orig_meth);
        pkey_method.keygen = my_pkey_ec_keygen;
    }
    else{
        printf("Failed to get built-in EC pkey method\n");
    }

    //setup pkey asn1 methods
    const EVP_PKEY_ASN1_METHOD * orig_asn1_meth = EVP_PKEY_asn1_find(NULL, EVP_PKEY_EC);
    if (orig_asn1_meth != NULL) {
        pkey_asn1_method.pkey_id = orig_asn1_meth->pkey_id;
        pkey_asn1_method.pkey_base_id = orig_asn1_meth->pkey_base_id;
        pkey_asn1_method.pem_str = my_pem_str; //without this pem_str value, openssl will get crashed

        EVP_PKEY_asn1_copy(&pkey_asn1_method, orig_asn1_meth);
        //EVP_PKEY_asn1_copy() in 1.1.1c missed a few questions
        EVP_PKEY_asn1_set_security_bits(&pkey_asn1_method, orig_asn1_meth->pkey_security_bits);
        EVP_PKEY_asn1_set_public_check(&pkey_asn1_method, orig_asn1_meth->pkey_public_check);
        EVP_PKEY_asn1_set_param_check(&pkey_asn1_method, orig_asn1_meth->pkey_param_check);
        EVP_PKEY_asn1_set_set_pub_key(&pkey_asn1_method, orig_asn1_meth->set_pub_key);
        EVP_PKEY_asn1_set_get_pub_key(&pkey_asn1_method, orig_asn1_meth->get_pub_key);
        EVP_PKEY_asn1_set_set_priv_key(&pkey_asn1_method, NULL);
        EVP_PKEY_asn1_set_get_priv_key(&pkey_asn1_method, NULL);
        
        //overload functions
        EVP_PKEY_asn1_set_private(&pkey_asn1_method, my_priv_decode, my_priv_encode, my_priv_print);
        pkey_asn1_method.pub_cmp = my_pub_cmp;
        pkey_asn1_method.param_cmp = my_param_cmp;
    }
    else {
        printf("Failed to get builtin EC pkey ASN1 method\n");
    }

    const EC_KEY_METHOD * ec_methods = get_ec_key_method();
    if (ec_methods == NULL) {
        printf("get_ec_key_method failed\n");
        goto end;       
    }
    if (ENGINE_set_EC(e, ec_methods) <= 0) {
        printf("ENGINE_set_EC failed\n");
        goto end;       
    }

    //setup engine
    if (!ENGINE_set_id(e, engine_id)){
        printf("ENGINE_set_id failed\n");
        goto end;
    }
    if (!ENGINE_set_name(e, engine_name)){
        printf("ENGINE_set_name failed\n");
        goto end;
    }
    if (!ENGINE_set_pkey_meths(e, get_pkey_meths) ||
        !ENGINE_set_pkey_asn1_meths(e, get_pkey_asn1_meths) ||        
        !ENGINE_set_load_privkey_function(e, load_privkey)
        ){
        printf("ENGINE_set failed\n");
        goto end;
    }
    ret = 1;
end:
    return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
IMPLEMENT_DYNAMIC_CHECK_FN()
