CREATE OR REPLACE PACKAGE APEX_JWT_RS256 AS 

    /*
    Package to do various things with JWT that is signed with RS256.
    2023 Ilmar Kerm
    https://ilmarkerm.eu
    
    Privileges:
    grant execute on dbms_crypto;
    grant execute on dbms_lock;
    
    Tables:
    create table jwks_key_cache(
        kid varchar2(50) primary key,
        pkcs1 raw(500) not null,
        alg varchar2(20) not null,
        kty varchar2(20) not null,
        e varchar2(10) not null,
        n varchar2(500) not null
    ) ORGANIZATION INDEX
    INCLUDING pkcs1 OVERFLOW;
    */ 

    -- Implementing Base64URL docede - URL safe Base64
    FUNCTION BASE64URL_DECODE(p_input IN varchar2) RETURN RAW DETERMINISTIC PARALLEL_ENABLE;
    -- Convert RSA modulus (n) and exponent (e) that JWKS returns into Base64 encoded PKCS1 public key format that DBMS_CRYPTO expects
    FUNCTION MAKE_PKCS1_RSA_KEY(v_key_modulus_binary IN RAW /* raw(256) 2048 bits*/, v_public_key_exponent_binary IN RAW /* raw(3) 24 bits*/) RETURN RAW DETERMINISTIC PARALLEL_ENABLE;
    -- Go to ISS and fetch the public keys
    PROCEDURE UPDATE_JWKS_KEY_CACHE(p_iss IN VARCHAR2);
    -- Returns FALSE if there are problems with validation or signature, TRUE if JWT is valid (not expired, correct ISS) and signature is valid
    FUNCTION DECODE_AND_VALIDATE(p_jwt IN VARCHAR2, p_iss IN VARCHAR2, p_payload OUT VARCHAR2) RETURN boolean;

END APEX_JWT_RS256;
/
