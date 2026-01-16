## Docker command:
```
docker run --name ssp-oidc-dev \
  -v "$(pwd)":/var/simplesamlphp/staging-modules/oidc:ro \
  -e STAGINGCOMPOSERREPOS=oidc \
  -e COMPOSER_REQUIRE="simplesamlphp/simplesamlphp-module-oidc:@dev" \
  -e SSP_ADMIN_PASSWORD=secret1 \
  -v "$(pwd)/docker/ssp/module_oidc.php":/var/simplesamlphp/config/module_oidc.php:ro \
  -v "$(pwd)/docker/ssp/authsources.php":/var/simplesamlphp/config/authsources.php:ro \
  -v "$(pwd)/docker/ssp/config-override.php":/var/simplesamlphp/config/config-override.php:ro \
  -v "$(pwd)/docker/ssp/oidc_module.crt":/var/simplesamlphp/cert/oidc_module.crt:ro \
  -v "$(pwd)/docker/ssp/oidc_module.key":/var/simplesamlphp/cert/oidc_module.key:ro \
  -v "$(pwd)/docker/apache-override.cf":/etc/apache2/sites-enabled/ssp-override.cf:ro \
  -p 443:443 cirrusid/simplesamlphp:v2.4.4
```


## Insert test token

Run database migration before!

```
docker exec -it ssp-oidc-dev bash
```

```
cat > /tmp/insert_client.php << 'EOF'
<?php
$db = new PDO("sqlite:/var/simplesamlphp/data/mydb.sq3");

// Insert a test client
$stmt = $db->prepare("INSERT OR IGNORE INTO oidc_client (id, secret, name, description, auth_source, redirect_uri, scopes, is_enabled, is_confidential) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");

$stmt->execute([
    'test-client-123',
    'test-secret-456',
    'Test Client',
    'Client for testing introspection',
    'example-userpass',
    '["https://localhost/callback"]',
    '["openid","profile","email"]',
    1,
    1
]);

echo "Client inserted!\n";

// Verify
$result = $db->query("SELECT id, name FROM oidc_client")->fetchAll(PDO::FETCH_ASSOC);
echo "Clients in database:\n";
foreach ($result as $row) {
    echo "  - " . $row['id'] . " (" . $row['name'] . ")\n";
}
EOF

php /tmp/insert_client.php
```


```
cat > /tmp/test.php << 'EOF'
<?php
$db = new PDO("sqlite:/var/simplesamlphp/data/mydb.sq3");

// Insert user with prepared statement
$stmt = $db->prepare("INSERT OR IGNORE INTO oidc_user (id, claims) VALUES (?, ?)");
$stmt->execute(["test-user-123", '{"sub":"test-user-123","name":"Test User"}']);

// Get first client
$client = $db->query("SELECT id FROM oidc_client LIMIT 1")->fetch(PDO::FETCH_ASSOC);
echo "Using client: " . $client["id"] . "\n";

// Generate token ID
$tokenId = "test-token-" . bin2hex(random_bytes(8));
echo "Token ID: " . $tokenId . "\n";

// Insert access token
$stmt = $db->prepare("INSERT INTO oidc_access_token (id, scopes, expires_at, user_id, client_id, is_revoked) VALUES (?, ?, datetime('now', '+1 hour'), ?, ?, 0)");
$stmt->execute([$tokenId, '["openid","profile","email"]', "test-user-123", $client["id"]]);

// Generate JWT
$header = rtrim(strtr(base64_encode(json_encode(["alg" => "RS256", "typ" => "JWT"])), "+/", "-_"), "=");
$payload = rtrim(strtr(base64_encode(json_encode(["jti" => $tokenId, "iat" => time(), "exp" => time() + 3600, "sub" => "test-user-123"])), "+/", "-_"), "=");
$jwt = "$header.$payload." . rtrim(strtr(base64_encode("sig"), "+/", "-_"), "=");

echo "\nGenerated JWT:\n";
echo $jwt . "\n";
echo "\nTest with:\n";
echo "curl -X POST \"https://localhost/simplesaml/module.php/oidc/introspect\" -H \"Content-Type: application/x-www-form-urlencoded\" -H \"Authorization: Bearer test\" -d \"token=$jwt\" -k\n";
EOF
```

```
php /tmp/test.php
```


## Single command (not tested)

```
docker exec -i ssp-oidc-dev bash -c '
cat > /tmp/insert_client.php << "EOF"
<?php
$db = new PDO("sqlite:/var/simplesamlphp/data/mydb.sq3");

// Insert a test client
$stmt = $db->prepare("INSERT OR IGNORE INTO oidc_client (id, secret, name, description, auth_source, redirect_uri, scopes, is_enabled, is_confidential) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");

$stmt->execute([
    "test-client-123",
    "test-secret-456",
    "Test Client",
    "Client for testing introspection",
    "example-userpass",
    "[\"https://localhost/callback\"]",
    "[\"openid\",\"profile\",\"email\"]",
    1,
    1
]);

echo "Client inserted!\n";

// Verify
$result = $db->query("SELECT id, name FROM oidc_client")->fetchAll(PDO::FETCH_ASSOC);
echo "Clients in database:\n";
foreach ($result as $row) {
    echo "  - " . $row["id"] . " (" . $row["name"] . ")\n";
}
EOF

php /tmp/insert_client.php

cat > /tmp/test.php << "EOF"
<?php
$db = new PDO("sqlite:/var/simplesamlphp/data/mydb.sq3");

// Insert user
$stmt = $db->prepare("INSERT OR IGNORE INTO oidc_user (id, claims) VALUES (?, ?)");
$stmt->execute(["test-user-123", "{\"sub\":\"test-user-123\",\"name\":\"Test User\"}"]);

// Get first client
$client = $db->query("SELECT id FROM oidc_client LIMIT 1")->fetch(PDO::FETCH_ASSOC);
echo "Using client: " . $client["id"] . "\n";

// Generate token ID
$tokenId = "test-token-" . bin2hex(random_bytes(8));
echo "Token ID: " . $tokenId . "\n";

// Insert access token
$stmt = $db->prepare("INSERT INTO oidc_access_token (id, scopes, expires_at, user_id, client_id, is_revoked) VALUES (?, ?, datetime('now', '+1 hour'), ?, ?, 0)");
$stmt->execute([$tokenId, "[\"openid\",\"profile\",\"email\"]", "test-user-123", $client["id"]]);

// Generate fake JWT
$header = rtrim(strtr(base64_encode(json_encode(["alg" => "RS256", "typ" => "JWT"])), "+/", "-_"), "=");
$payload = rtrim(strtr(base64_encode(json_encode(["jti" => $tokenId, "iat" => time(), "exp" => time() + 3600, "sub" => "test-user-123"])), "+/", "-_"), "=");
$jwt = "$header.$payload." . rtrim(strtr(base64_encode("sig"), "+/", "-_"), "=");

echo "\nGenerated JWT:\n$jwt\n";
echo "\nTest with:\n";
echo "curl -X POST \"https://localhost/simplesaml/module.php/oidc/introspect\" -H \"Content-Type: application/x-www-form-urlencoded\" -H \"Authorization: Bearer test\" -d \"token=$jwt\" -k\n";
EOF

php /tmp/test.php
```