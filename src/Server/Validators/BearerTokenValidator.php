<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Validators;

use DateInterval;
use DateTimeZone;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator as OAuth2BearerTokenValidator;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface as OAuth2AccessTokenRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;

use function count;
use function date_default_timezone_get;
use function is_array;
use function preg_replace;
use function trim;

class BearerTokenValidator extends OAuth2BearerTokenValidator
{
    /** @var \Lcobucci\JWT\Configuration */
    protected Configuration $jwtConfiguration;

    /** @var \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface */
    protected OAuth2AccessTokenRepositoryInterface $accessTokenRepository;

    /** @var \League\OAuth2\Server\CryptKey */
    protected $publicKey;

    /**
     * @throws \Exception
     */
    public function __construct(
        AccessTokenRepositoryInterface $accessTokenRepository,
        CryptKey $publicKey,
        ?DateInterval $jwtValidAtDateLeeway = null,
        protected LoggerService $loggerService = new LoggerService(),
    ) {
        parent::__construct($accessTokenRepository, $jwtValidAtDateLeeway);
        $this->accessTokenRepository = $accessTokenRepository;
        $this->setPublicKey($publicKey);
    }

    /**
     * Set the public key
     *
     * @param \League\OAuth2\Server\CryptKey $key
     * @throws \Exception
     */
    public function setPublicKey(CryptKey $key): void
    {
        $this->publicKey = $key;

        $this->initJwtConfiguration();
    }

    /**
     * Initialise the JWT configuration.
     * @throws \Exception
     */
    protected function initJwtConfiguration(): void
    {
        $this->jwtConfiguration = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText('empty', 'empty'),
        );

        /** @psalm-suppress DeprecatedMethod, ArgumentTypeCoercion */
        $this->jwtConfiguration->setValidationConstraints(
            new StrictValidAt(new SystemClock(new DateTimeZone(date_default_timezone_get()))),
            new SignedWith(
                new Sha256(),
                InMemory::plainText($this->publicKey->getKeyContents(), $this->publicKey->getPassPhrase() ?? ''),
            ),
        );
    }

    /**
     * {@inheritdoc}
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function validateAuthorization(ServerRequestInterface $request): ServerRequestInterface
    {
        $jwt = null;

        if (
            $request->hasHeader('authorization') &&
            ($header = $request->getHeader('authorization')) &&
            ($accessToken = $this->getTokenFromAuthorizationBearer($header[0]))
        ) {
            $jwt = $accessToken;
        } elseif (
            strcasecmp($request->getMethod(), 'POST') === 0 &&
            is_array($parsedBody = $request->getParsedBody()) &&
            isset($parsedBody['access_token']) &&
            is_string($parsedBody['access_token'])
        ) {
            $jwt = $parsedBody['access_token'];
        } elseif (
            // Handle case when Apache strips of Authorization header with Bearer scheme.
            // https://github.com/symfony/symfony/issues/19693
            // Although we actually handle it here, it has performance implications, so give warning about it.
            is_callable('apache_request_headers') &&
            ($headers = array_change_key_case(apache_request_headers())) &&
            (array_key_exists('authorization', $headers)) &&
            ($header = (string)$headers['authorization']) &&
            ($accessToken = $this->getTokenFromAuthorizationBearer($header))
        ) {
            $this->loggerService->warning(
                'Apache stripping of Authorization Bearer request header encountered. You should modify your' .
                ' Apache configuration to preserve to Authorization Bearer token in requests to avoid performance ' .
                'implications. Check the OIDC module README file on how to do that.',
            );
            $jwt = $accessToken;
        }

        if (!is_string($jwt) || empty($jwt)) {
            throw OidcServerException::accessDenied('Missing Authorization header or access_token request body param.');
        }

        try {
            // Attempt to parse the JWT
            /** @var \Lcobucci\JWT\Token\Plain $token */
            $token = $this->jwtConfiguration->parser()->parse($jwt);
        } catch (\Lcobucci\JWT\Exception $exception) {
            throw OidcServerException::accessDenied($exception->getMessage(), null, $exception);
        }

        try {
            // Attempt to validate the JWT
            $constraints = $this->jwtConfiguration->validationConstraints();
            $this->jwtConfiguration->validator()->assert($token, ...$constraints);
        } catch (RequiredConstraintsViolated) {
            throw OidcServerException::accessDenied('Access token could not be verified');
        }

        $claims = $token->claims();

        if (is_null($jti = $claims->get('jti')) || empty($jti) || !is_string($jti)) {
            throw OidcServerException::accessDenied('Access token malformed (jti missing or unexpected type)');
        }

        // Check if token has been revoked
        if ($this->accessTokenRepository->isAccessTokenRevoked($jti)) {
            throw OidcServerException::accessDenied('Access token has been revoked');
        }

        // Return the request with additional attributes
        return $request
            ->withAttribute('oauth_access_token_id', $jti)
            ->withAttribute('oauth_client_id', $this->convertSingleRecordAudToString($claims->get('aud')))
            ->withAttribute('oauth_user_id', $claims->get('sub'))
            ->withAttribute('oauth_scopes', $claims->get('scopes'));
    }

    protected function getTokenFromAuthorizationBearer(string $authorizationHeader): string
    {
        return trim((string) preg_replace('/^\s*Bearer\s/', '', $authorizationHeader));
    }

    /**
     * Convert single record arrays into strings to ensure backwards compatibility between v4 and v3.x of lcobucci/jwt
     *
     * @param mixed $aud
     *
     * @return array|string
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function convertSingleRecordAudToString(mixed $aud): array|string
    {
        if (is_string($aud)) {
            return $aud;
        }

        if (is_array($aud) && !empty($aud)) {
            if (count($aud) === 1) {
                return (string)$aud[0];
            } else {
                return $aud;
            }
        }

        throw OidcServerException::accessDenied('Unexpected sub claim value.');
    }
}
