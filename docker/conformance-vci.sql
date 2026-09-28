-- Clients for the OpenID4VCI issuer test plan (oid4vci-1_0-issuer-test-plan), loaded after conformance.sql.
--
-- They are kept apart from the OpenID Connect plans' clients, so that neither plan changes a client the
-- other relies on, and they answer to their own conformance suite alias, simplesamlphp-module-oidc-vci,
-- which is the alias in conformance-tests/conformance-vci-issuer.json. The suite authenticates both with
-- private_key_jwt, signing with the private halves of these keys held in that file; the secret only
-- satisfies the schema. Both keys are EC P-256: the suite also signs its credential key proofs with the
-- client's key, and reads that key as an EC key. The one scope is the one the credential configuration in docker/ssp/module_oidc.php
-- names, which is what the suite requests. The suite sends client 2's requests from the callback with a
-- query string added (?dummy1=lorem&dummy2=ipsum), to check that it is compared exactly, so client 2 has
-- those redirect URIs too.
INSERT INTO oidc_client (id, secret, name, description, auth_source, redirect_uri, scopes, is_enabled, is_confidential, jwks, registration_type)
VALUES (
    '_3eaf06703ec3a31c4b5b5577427f28ee5e76e83f5f',
    '_bf006de01bc96562eac88bd2a13c052a3618e7e430',
    'VCI Conformance Client 1',
    'Client 1 for the OpenID4VCI issuer test plan',
    'example-userpass',
    '["https:\/\/localhost.emobix.co.uk:8443\/test\/a\/simplesamlphp-module-oidc-vci\/callback","https:\/\/www.certification.openid.net\/test\/a\/simplesamlphp-module-oidc-vci\/callback"]',
    '["ResearchAndScholarshipCredentialDcSdJwt"]',
    1,
    1,
    '{"keys":[{"kty":"EC","use":"sig","crv":"P-256","kid":"vci-example-key-1","x":"yHNp8QgNiVSxSxIH_n_nH23dpUDlNhbgvLKSrjK1hDs","y":"3_rlpW_FXqghp8dKPpkjfvbfACQQFLFZwJXxOr319Ac","alg":"ES256"}]}',
    'manual'
);
INSERT INTO oidc_client (id, secret, name, description, auth_source, redirect_uri, scopes, is_enabled, is_confidential, jwks, registration_type)
VALUES (
    '_6aaba246b47b522de2eb46ac22cf54ed82b948848f',
    '_91a3eeb54e0fe6b04a6c99469dfc73c1f9b00cb97c',
    'VCI Conformance Client 2',
    'Client 2 for the OpenID4VCI issuer test plan, used by its multiple clients test',
    'example-userpass',
    '["https:\/\/localhost.emobix.co.uk:8443\/test\/a\/simplesamlphp-module-oidc-vci\/callback","https:\/\/localhost.emobix.co.uk:8443\/test\/a\/simplesamlphp-module-oidc-vci\/callback?dummy1=lorem&dummy2=ipsum","https:\/\/www.certification.openid.net\/test\/a\/simplesamlphp-module-oidc-vci\/callback","https:\/\/www.certification.openid.net\/test\/a\/simplesamlphp-module-oidc-vci\/callback?dummy1=lorem&dummy2=ipsum"]',
    '["ResearchAndScholarshipCredentialDcSdJwt"]',
    1,
    1,
    '{"keys":[{"kty":"EC","use":"sig","crv":"P-256","kid":"vci-conformance-client-2","x":"rPyeMbaj5YghbJLlBI4XUTi1bNazW4MJN5H5Na1UDpc","y":"mLSi9IXjY1Tdf8qZy28FEnnhBpzkskeSKuUUQ5XBmMo","alg":"ES256"}]}',
    'manual'
);
