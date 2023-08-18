<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Validators;

use DateInterval;
use DateTimeZone;
use Exception;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator as OAuth2BearerTokenValidator;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface as OAuth2AccessTokenRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

use function count;
use function date_default_timezone_get;
use function is_array;
use function preg_replace;
use function trim;

class BearerTokenValidator extends OAuth2BearerTokenValidator
{
    /**
     * @var Configuration
     */
    protected Configuration $jwtConfiguration;

    /**
     * @var OAuth2AccessTokenRepositoryInterface
     */
    protected OAuth2AccessTokenRepositoryInterface $accessTokenRepository;

    /**
     * @var CryptKey
     */
    protected $publicKey;

    /**
     * @param AccessTokenRepositoryInterface $accessTokenRepository
     * @param CryptKey $publicKey
     * @param DateInterval|null $jwtValidAtDateLeeway
     * @throws Exception
     */
    public function __construct(
        AccessTokenRepositoryInterface $accessTokenRepository,
        CryptKey $publicKey,
        DateInterval $jwtValidAtDateLeeway = null
    ) {
        parent::__construct($accessTokenRepository, $jwtValidAtDateLeeway);
        $this->accessTokenRepository = $accessTokenRepository;
        $this->setPublicKey($publicKey);
    }

    /**
     * Set the public key
     *
     * @param CryptKey $key
     * @throws Exception
     */
    public function setPublicKey(CryptKey $key): void
    {
        $this->publicKey = $key;

        $this->initJwtConfiguration();
    }

    /**
     * Initialise the JWT configuration.
     * @throws Exception
     */
    protected function initJwtConfiguration(): void
    {
        $this->jwtConfiguration = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText('empty', 'empty')
        );

        /** @psalm-suppress ArgumentTypeCoercion */
        $this->jwtConfiguration->setValidationConstraints(
            new StrictValidAt(new SystemClock(new DateTimeZone(date_default_timezone_get()))),
            new SignedWith(
                new Sha256(),
                InMemory::plainText($this->publicKey->getKeyContents(), $this->publicKey->getPassPhrase() ?? '')
            )
        );
    }

    /**
     * {@inheritdoc}
     * @throws OidcServerException
     */
    public function validateAuthorization(ServerRequestInterface $request): ServerRequestInterface
    {
        $jwt = null;

        if ($request->hasHeader('authorization')) {
            $header = $request->getHeader('authorization');
            $jwt = trim((string) preg_replace('/^\s*Bearer\s/', '', $header[0]));
        } elseif (
            strcasecmp($request->getMethod(), 'POST') === 0 &&
            is_array($parsedBody = $request->getParsedBody()) &&
            isset($parsedBody['access_token'])
        ) {
            $jwt = $parsedBody['access_token'];
        }

        if ($jwt === null) {
            throw OidcServerException::accessDenied('Missing Authorization header or access_token request body param.');
        }

        try {
            // Attempt to parse the JWT
            /** @var Plain $token */
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

        if (is_null($jti = $claims->get('jti')) || empty($jti)) {
            throw OidcServerException::accessDenied('Access token malformed (jti missing)');
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

    /**
     * Convert single record arrays into strings to ensure backwards compatibility between v4 and v3.x of lcobucci/jwt
     *
     * @param mixed $aud
     *
     * @return array|string
     */
    protected function convertSingleRecordAudToString(mixed $aud): array|string
    {
        return is_array($aud) && count($aud) === 1 ? $aud[0] : $aud;
    }
}
