<?php

declare(strict_types=1);

/**
 * The upstream authorization servers of the proxied introspection harness which misbehave, one per path, and a
 * recording one which answers every token inactive and keeps count of what reached it. Served over the harness TLS
 * by the image's Apache, at https://upstream-mock.oidc.test/upstream-mock.php/<case>.
 *
 * GET /upstream-mock.php/recorder/state tells a test how many questions the recorder was asked, and what the last
 * one was.
 */

$case = trim((string)($_SERVER['PATH_INFO'] ?? ''), '/');
$issuer = 'https://upstream-mock.oidc.test/' . $case;
$stateFile = sys_get_temp_dir() . '/upstream-mock-recorder.json';

$json = static function (int $status, array $body, array $headers = []): never {
    http_response_code($status);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    foreach ($headers as $name => $value) {
        header($name . ': ' . $value);
    }
    echo json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    exit;
};

$activeAnswer = static fn(array $members = []): array => $members + [
    'active' => true,
    'iss' => $issuer,
    'sub' => 'someone-at-the-mock',
    'client_id' => 'a-client-at-the-mock',
    'scope' => 'openid',
    'token_type' => 'Bearer',
    'exp' => time() + 600,
    'iat' => time(),
];

if ($case === 'recorder/state') {
    $state = is_file($stateFile) ? json_decode((string)file_get_contents($stateFile), true) : null;
    $json(200, is_array($state) ? $state : ['count' => 0, 'last' => null]);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $json(405, ['error' => 'invalid_request'], ['Allow' => 'POST']);
}

match ($case) {
    'active' => $json(200, $activeAnswer()),
    // What an inactive answer carries besides 'active' must not travel on (AARC-G052 section 3).
    'inactive' => $json(200, [
        'active' => false,
        'iss' => $issuer,
        'sub' => 'subject-the-caller-must-not-see',
        'exp' => time() + 600,
        'scope' => 'openid',
    ]),
    'not-bearer' => $json(200, $activeAnswer(['token_type' => 'DPoP'])),
    'server-error' => $json(500, ['error' => 'server_error']),
    'too-many-requests' => $json(429, ['error' => 'temporarily_unavailable'], ['Retry-After' => '30']),
    // This OP's own credentials refused.
    'unauthorized' => $json(401, ['error' => 'invalid_client'], ['WWW-Authenticate' => 'Basic realm="mock"']),
    'not-json' => (static function (): never {
        header('Content-Type: text/html');
        echo '<html><body>Maintenance</body></html>';
        exit;
    })(),
    // Longer than the timeout the node gives this upstream.
    'slow' => (static function () use ($json, $activeAnswer): never {
        sleep(3);
        $json(200, $activeAnswer());
    })(),
    'recorder' => (static function () use ($json, $stateFile): never {
        $handle = fopen($stateFile, 'c+');
        flock($handle, LOCK_EX);
        $state = json_decode((string)stream_get_contents($handle), true);
        $state = [
            'count' => (is_array($state) ? (int)$state['count'] : 0) + 1,
            'last' => [
                'token' => $_POST['token'] ?? null,
                'token_type_hint' => $_POST['token_type_hint'] ?? null,
                'basic_client_id' => $_SERVER['PHP_AUTH_USER'] ?? null,
                'post_client_id' => $_POST['client_id'] ?? null,
            ],
        ];
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($state, JSON_THROW_ON_ERROR));
        flock($handle, LOCK_UN);
        fclose($handle);

        $json(200, ['active' => false]);
    })(),
    default => $json(404, ['error' => 'invalid_request', 'error_description' => 'No such mock: ' . $case]),
};
