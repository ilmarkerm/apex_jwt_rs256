# apex_jwt_rs256

PL/SQL package to validate RS256 signed JWT tokens. Pure 19c PL/SQL, no other languages used.
Tested with Oracle RDBMS EE 19.19+, APEX 23.1 and AWS Cognito issued JWT tokens.
Requires APEX installed (for its API packages) and is intended to be used within APEX flow.

2023 Ilmar Kerm
https://ilmarkerm.eu
ilmar.kerm@gmail.com

# Installation

As SYS add grants to package owner:
```
grant execute on dbms_crypto to package_owner;
grant execute on dbms_lock to package_owner;
```

Create table for JWKS key cache under package owner schema:

```
create table jwks_key_cache(
    kid varchar2(50) primary key,
    alg varchar2(20) not null,
    kty varchar2(20) not null,
    e varchar2(10) not null,
    n varchar2(500) not null,
    pkcs1 raw(500) not null
) organization index;
```

Install package under package owner schema:

```
@@apex_jwt_rs256.pks
@@apex_jwt_rs256.pkb
```

# Security

To update JWKS key cache, PL/SQL needs to make REST call, highly likely using HTTPS - so it does need database firewall to be open and truststore (instance wallet) configured in APEX.

First it needs APEX instance wallet to be configured (under APEX internal workspace). This is a truststore for HTTPS calls. To use Linux system truststore (with Mozilla approved CA-s), check this blog post:
https://ilmarkerm.eu/blog/2023/08/convert-linux-system-ca-trust-store-to-oracle-wallet-file/

PL/SQL also needs to be able to make REST calls to the identity provider in order to fetch the public keys used to verify JWT signatures.
If you are using AWS Cognito userpool from eu-central-1, then here is an example for opening database firewall for HTTPS calls to that endpoint.

```
declare
    l_username varchar2(30) := 'PUBLIC'; -- you are welcome to restrict it to only APEX engine
begin
    dbms_network_acl_admin.append_host_ace(
        host => 'cognito-idp.eu-central-1.amazonaws.com',
        lower_port => 443,
        ace  =>  xs$ace_type(
                    privilege_list => xs$name_list('connect'),
                    principal_name => l_username,
                    principal_type => xs_acl.ptype_db)
        );
    commit;
end;
/
```

# Example APEX authentication scheme

Create custom authentication scheme and as page sentry function refer to a function like that below. Below is just an example.

```
create or replace FUNCTION JWT_PAGE_SENTRY RETURN BOOLEAN AS 
    v_required_group varchar2(30):= 'important_people'; -- Group needed to access the app
    v_iss varchar2(200):= 'https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_ZZxxZZxx11'; -- ISS that issued the JWT, YOU MUST CHANGE THIS to point to your own ISS
    jwt_cookie owa_cookie.cookie;
    v_jwt_payload varchar2(2000);
    v_jwt_json json_object_t;
    v_groups json_array_t;
    v_group_found boolean:= false;
BEGIN
    -- Do JWT token validation and check that correct group is granted to user
    -- 2023 Ilmar Kerm
    jwt_cookie:= owa_cookie.get('JWT_COOKIE_NAME');
    IF jwt_cookie.vals.COUNT = 0 THEN
        apex_debug.error('JWT session cookie not found');
        RETURN false;
    END IF;
    IF apex_jwt_rs256.decode_and_validate(jwt_cookie.vals(1), v_iss, v_jwt_payload) THEN
        -- JWT validated, now check the required group
        v_jwt_json:= json_object_t.parse(v_jwt_payload);
        v_groups:= v_jwt_json.get_array('cognito:groups');
        FOR i IN 0..v_groups.get_size - 1 LOOP
            IF v_groups.get_string(i) = v_required_group THEN
                v_group_found:= true;
                EXIT;
            END IF;
        END LOOP;
        IF NOT v_group_found THEN
            apex_debug.error('Required group is missing from JWT: '||v_required_group);
            RETURN false;
        END IF;
        IF V('APP_USER') IS NULL OR V('APP_USER') = 'nobody' OR V('APP_USER') != v_jwt_json.get_string('username') THEN
            APEX_CUSTOM_AUTH.DEFINE_USER_SESSION(
                p_user => v_jwt_json.get_string('username'),
                p_session_id => APEX_CUSTOM_AUTH.GET_NEXT_SESSION_ID
            );
        END IF;
        RETURN true;
    ELSE
        RETURN false;
    END IF;
END JWT_PAGE_SENTRY;
```
