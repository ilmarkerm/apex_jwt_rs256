CREATE OR REPLACE PACKAGE BODY APEX_JWT_RS256 AS
    /*
    Package to do various things with JWT that is signed with RS256.
    2023 Ilmar Kerm
    https://ilmarkerm.eu
    */ 

    FUNCTION BASE64URL_DECODE(p_input IN varchar2) RETURN RAW DETERMINISTIC PARALLEL_ENABLE AS
        PRAGMA UDF;
        v_pad_count NUMBER(1);
    BEGIN
        -- This decodes Base64URL encoded value to RAW
        v_pad_count:= 4 - mod(length(p_input), 4);
        IF v_pad_count = 4 THEN
            v_pad_count:= 0;
        END IF;
        RETURN utl_encode.base64_decode(
            UTL_I18N.STRING_TO_RAW(
                replace(
                    replace(
                        rpad(p_input, length(p_input) + v_pad_count, '=')
                    , '_', '/')
                , '-', '+')
            , 'AL32UTF8')
        );
    END BASE64URL_DECODE;

    FUNCTION MAKE_PKCS1_RSA_KEY(v_key_modulus_binary IN RAW /* raw(256) 2048 bits*/, v_public_key_exponent_binary IN RAW /* raw(3) 24 bits*/) RETURN RAW DETERMINISTIC PARALLEL_ENABLE AS
        PRAGMA UDF;
        c_tag_INTEGER raw(1) := hextoraw('02'); -- ASN.1 Universal Primitive Tag: 02 (INTEGER)
        c_tag_SEQUENCE raw(1) := hextoraw('30'); -- ASN.1 Universal Constructed Tag: 16 (SEQUENCE)
        c_2_LENGTH_BYTES_NEEDED raw(1) := hextoraw('82');
        c_3_VALUE_BYTES raw(1) := hextoraw('03');
        c_257_VALUE_BYTES raw(2) := hextoraw('0101');
        c_266_VALUE_BYTES raw(2) := hextoraw('010A');
        c_LEADING_ZERO_OF_INTEGER raw(1) := hextoraw('00');
    BEGIN
        -- From https://asktom.oracle.com/pls/apex/asktom.search?tag=plsql-only-ways-to-do-json-token-validation#9547303400346607729
        -- https://stackoverflow.com/questions/18039401/how-can-i-transform-between-the-two-styles-of-public-key-format-one-begin-rsa
        -- RSA (256) PKCS#1
        RETURN utl_encode.base64_encode(
            utl_raw.concat(
                r1 => c_tag_SEQUENCE -- 1 byte Tag
                , r2 => c_2_LENGTH_BYTES_NEEDED -- 1 byte Length Bytes
                , r3 => c_266_VALUE_BYTES -- 2 bytes Length
                , r4 => c_tag_INTEGER -- 1 byte Tag
                , r5 => c_2_LENGTH_BYTES_NEEDED -- 1 byte Length Bytes
                , r6 => c_257_VALUE_BYTES -- 2 bytes Length
                , r7 => c_LEADING_ZERO_OF_INTEGER -- 1 byte
                , r8 => v_key_modulus_binary -- 256 bytes
                , r9 => c_tag_INTEGER -- 1 byte Tag
                , r10 => c_3_VALUE_BYTES -- 1 byte Length
                , r11 => v_public_key_exponent_binary -- 3 bytes
            )
        );
    END MAKE_PKCS1_RSA_KEY;
    
    PROCEDURE UPDATE_JWKS_KEY_CACHE(p_iss IN VARCHAR2) AS
        PRAGMA AUTONOMOUS_TRANSACTION;
        v_url varchar2(300);
        v_lock_handle varchar2(128);
    BEGIN
        -- This updates local jwks_key_cache from IDP
        -- Executed when JWT signing key is not found from local key cache
        -- Tested only with AWS cognito jwks.json
        --
        -- First we don't want to have multiple copies of this code running, let one process fetch and others wait
        dbms_lock.allocate_unique('APEX_JWT_RS256_JWKS_UPDATE', v_lock_handle);
        IF dbms_lock.request(lockhandle=>v_lock_handle, timeout=>6, release_on_commit=>true) IN (0,4) THEN
            -- Update JWKS cache
            v_url:= p_iss||'/.well-known/jwks.json';
            merge into jwks_key_cache t
            using (
                select * from
                    json_table(
                        apex_web_service.make_rest_request(v_url, 'GET', p_transfer_timeout=>5)
                        , '$.keys[*]' columns (
                            alg varchar2(20) path '$.alg',
                            e varchar2(20) path '$.e',
                            kid varchar2(100) path '$.kid',
                            kty varchar2(20) path '$.kty',
                            n varchar2(4000) path '$.n'
                        )
                    )) s
            ON (s.kid = t.kid)
            when not matched then
                insert (kid, alg, kty, e, n, pkcs1)
                values (s.kid, s.alg, s.kty, s.e, s.n,
                    make_pkcs1_rsa_key(base64url_decode(s.n), base64url_decode(s.e)));
            commit;
        END IF;
    END UPDATE_JWKS_KEY_CACHE;
    
    FUNCTION DECODE_AND_VALIDATE(p_jwt IN VARCHAR2, p_iss IN VARCHAR2, p_payload OUT VARCHAR2) RETURN boolean IS
        v_token apex_jwt.t_token;
        v_keys apex_t_varchar2;
        v_json_content json_object_t;
        v_kid jwks_key_cache.kid%type;
        v_key jwks_key_cache.pkcs1%type;
    BEGIN
        -- This will split and decode JWT token
        v_token := apex_jwt.decode(p_jwt);
        -- This will check if token has not expired and is issued by provider (ISS) we expect to see
        apex_jwt.validate(p_token => v_token, p_iss => p_iss);
        -- Parsing the header to see if it is signed using RS256
        v_json_content:= json_object_t.parse(v_token.header);
        IF v_json_content.get_string('alg') != 'RS256' THEN
            raise_application_error(-20501, 'This package only handles RS256 signed JWT tokens');
        END IF;
        -- Try fetching the key from cache.
        v_kid:= v_json_content.get_string('kid');
        FOR i IN 1..2 LOOP
            -- If first time key is not in cache, then update key cache from ISS.
            -- If second time key is also not present, then something is wrong and just fail.
            BEGIN
                SELECT pkcs1 INTO v_key FROM jwks_key_cache WHERE kid = v_kid;
                EXIT;
            EXCEPTION
                WHEN no_data_found THEN
                    IF i = 1 THEN
                        update_jwks_key_cache(p_iss);
                    ELSE
                        raise_application_error(-20500, 'Required key not found in JWKS cache even after updating the cache');
                    END IF;
            END;
        END LOOP;
        -- Validate the signature
        IF NOT DBMS_CRYPTO.VERIFY(
                src => UTL_I18N.STRING_TO_RAW(
                        SUBSTR(p_jwt, 1, INSTR(p_jwt, '.', 1, 2)-1) -- Operate on the input string itself, since v_token is already decoded, but JWT signs the encoded message
                    , 'al32utf8'), 
                sign => base64url_decode(v_token.signature),
                pub_key => v_key,
                pubkey_alg => dbms_crypto.KEY_TYPE_RSA,
                sign_alg => dbms_crypto.SIGN_SHA256_RSA)
        THEN
            raise_application_error(-20502, 'JWT signature failed cryptographic verification');
        END IF;
        -- Signature was valid, finish successfully
        p_payload:= v_token.payload;
        RETURN true;
    EXCEPTION
        WHEN others THEN
            -- In case of any exception, usually from APEX_JWT.validate or DBMS_CRYPTO - fail
            apex_debug.error(DBMS_UTILITY.format_error_stack);
            RETURN false;
    END;

END APEX_JWT_RS256;
/
