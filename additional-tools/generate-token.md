```
cat > /tmp/test.php << 'EOF'
<?php
require_once '/var/simplesamlphp/vendor/autoload.php';

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;

// Database setup
$db = new PDO("sqlite:/var/simplesamlphp/data/mydb.sq3");

// Insert user with prepared statement
$stmt = $db->prepare("INSERT OR IGNORE INTO oidc_user (id, claims) VALUES (?, ?)");
$stmt->execute(["test-user-123", '{"sub":"test-user-123","name":"Test User"}']);

// Get first client
$client = $db->query("SELECT id FROM oidc_client LIMIT 1")->fetch(PDO::FETCH_ASSOC);
if (!$client) {
    die("Error: No client found in database. Please create a client first.\n");
}
echo "Using client: " . $client["id"] . "\n";

// Generate token ID
$tokenId = "test-token-" . bin2hex(random_bytes(16));
echo "Token ID: " . $tokenId . "\n";

// Calculate expiration time
$now = new DateTimeImmutable();
$expiresAt = $now->modify('+1 hour');

// Insert access token into database
$stmt = $db->prepare("INSERT INTO oidc_access_token (id, scopes, expires_at, user_id, client_id, is_revoked) VALUES (?, ?, ?, ?, ?, 0)");
$stmt->execute([
    $tokenId, 
    '["openid","profile","email"]', 
    $expiresAt->format('Y-m-d H:i:s'),
    "test-user-123", 
    $client["id"]
]);

echo "✓ Token stored in database\n";

// Read the actual key contents
$privateKeyContents = file_get_contents('/var/simplesamlphp/cert/oidc_module.key');
$publicKeyContents = file_get_contents('/var/simplesamlphp/cert/oidc_module.crt');

// Configure JWT
$config = Configuration::forAsymmetricSigner(
    new Sha256(),
    InMemory::plainText($privateKeyContents),
    InMemory::plainText($publicKeyContents)
);

// Build properly signed JWT with nbf claim
$token = $config->builder()
    ->issuedBy('https://localhost')
    ->permittedFor('resource-server')
    ->identifiedBy($tokenId)
    ->issuedAt($now)
    ->canOnlyBeUsedAfter($now)  // ← ADD THIS: Sets the nbf (Not Before) claim
    ->expiresAt($expiresAt)
    ->relatedTo('test-user-123')
    ->withClaim('scopes', ['openid', 'profile', 'email'])
    ->withClaim('client_id', $client["id"])
    ->getToken($config->signer(), $config->signingKey());

$jwt = $token->toString();

// Verify the token can be parsed and validated
try {
    $parsedToken = $config->parser()->parse($jwt);
    $config->validator()->assert($parsedToken, ...$config->validationConstraints());
    echo "✓ Token signature validated successfully!\n";
} catch (\Exception $e) {
    echo "✗ Validation failed: " . $e->getMessage() . "\n";
}

// Output the JWT
echo "\n" . str_repeat("=", 80) . "\n";
echo "Generated JWT:\n";
echo str_repeat("=", 80) . "\n";
echo $jwt . "\n";
echo str_repeat("=", 80) . "\n";

// Provide test command
echo "\nTest with curl:\n";
echo "curl -X POST \"https://localhost/simplesaml/module.php/oidc/introspect\" \\\n";
echo "  -H \"Content-Type: application/x-www-form-urlencoded\" \\\n";
echo "  -H \"Authorization: Bearer test\" \\\n";
echo "  -d \"token=$jwt\" \\\n";
echo "  -k\n";

// Also show decoded token for debugging
echo "\n" . str_repeat("=", 80) . "\n";
echo "Decoded Token Payload:\n";
echo str_repeat("=", 80) . "\n";
$parts = explode('.', $jwt);
$payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
echo json_encode($payload, JSON_PRETTY_PRINT) . "\n";
EOF


php /tmp/test.php
```