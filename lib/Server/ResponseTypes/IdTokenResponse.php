<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Server\ResponseTypes;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\RegisteredClaims;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\Entities\ClaimSetInterface;
use OpenIDConnectServer\Repositories\IdentityProviderInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\ResponseTypes\Interfaces\NonceResponseTypeInterface;
use SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService;
use SimpleSAML\Modules\OpenIDConnect\Utils\FingerprintGenerator;
use SimpleSAML\Utils\Config;

/**
 * Class IdTokenResponse.
 *
 * @author Steve Rhoades <sedonami@gmail.com>
 * @license http://opensource.org/licenses/MIT MIT
 *
 * @see https://github.com/steverhoades/oauth2-openid-connect-server/blob/master/src/IdTokenResponse.php
 */
class IdTokenResponse extends BearerTokenResponse implements NonceResponseTypeInterface
{
    /**
     * @var IdentityProviderInterface
     */
    protected $identityProvider;

    /**
     * @var ClaimExtractor
     */
    protected $claimExtractor;

    /**
     * @var ConfigurationService
     */
    private $configurationService;

    /**
     * @var string|null
     */
    protected $nonce;

    public function __construct(
        IdentityProviderInterface $identityProvider,
        ClaimExtractor $claimExtractor,
        ConfigurationService $configurationService
    ) {
        $this->identityProvider = $identityProvider;
        $this->claimExtractor = $claimExtractor;
        $this->configurationService = $configurationService;
    }

    /**
     * @return array
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken)
    {
        if (false === $this->isOpenIDRequest($accessToken->getScopes())) {
            return [];
        }

        /** @var UserEntityInterface $userEntity */
        $userEntity = $this->identityProvider->getUserEntityByIdentifier($accessToken->getUserIdentifier());

        if (false === is_a($userEntity, UserEntityInterface::class)) {
            throw new \RuntimeException('UserEntity must implement UserEntityInterface');
        } elseif (false === is_a($userEntity, ClaimSetInterface::class)) {
            throw new \RuntimeException('UserEntity must implement ClaimSetInterface');
        }
        $jwtConfig = Configuration::forAsymmetricSigner(
            $this->configurationService->getSigner(),
            InMemory::plainText($this->privateKey->getKeyPath(), $this->privateKey->getPassPhrase() ?? ''),
            // The public key is not needed for signing
            InMemory::empty()
        );
        // Add required id_token claims
        $builder = $this->getBuilder($jwtConfig, $accessToken, $userEntity);

        if (null !== $this->getNonce()) {
            $builder->withClaim('nonce', $this->getNonce());
        }

        // Need a claim factory here to reduce the number of claims by provided scope.
        $claims = $this->claimExtractor->extract($accessToken->getScopes(), $userEntity->getClaims());

        foreach ($claims as $claimName => $claimValue) {
            switch ($claimName) {
                case RegisteredClaims::AUDIENCE:
                    $builder->permittedFor($claimValue);
                    break;
                case RegisteredClaims::EXPIRATION_TIME:
                    $builder->expiresAt(new \DateTimeImmutable('@' . $claimValue));
                    break;
                case RegisteredClaims::ID:
                    $builder->identifiedBy($claimValue);
                    break;
                case RegisteredClaims::ISSUED_AT:
                    $builder->issuedAt(new \DateTimeImmutable('@' . $claimValue));
                    break;
                case RegisteredClaims::ISSUER:
                    $builder->issuedBy($claimValue);
                    break;
                case RegisteredClaims::NOT_BEFORE:
                    $builder->canOnlyBeUsedAfter(new \DateTimeImmutable('@' . $claimValue));
                    break;
                case RegisteredClaims::SUBJECT:
                    $builder->relatedTo($claimValue);
                    break;
                default:
                    $builder->withClaim($claimName, $claimValue);
           }
        }

        $token = $builder->getToken(
            $jwtConfig->signer(),
            $jwtConfig->signingKey()
        );

        return [
            'id_token' =>  $token->toString(),
        ];
    }

    protected function getBuilder(Configuration $jwtConfig, AccessTokenEntityInterface $accessToken, UserEntityInterface $userEntity)
    {

        return $jwtConfig->builder()
            ->issuedBy($this->configurationService->getSimpleSAMLSelfURLHost())
            ->permittedFor($accessToken->getClient()->getIdentifier())
            ->identifiedBy($accessToken->getIdentifier())
            ->canOnlyBeUsedAfter(new \DateTimeImmutable('now'))
            ->expiresAt($accessToken->getExpiryDateTime())
            ->relatedTo($userEntity->getIdentifier())
            ->issuedAt(new \DateTimeImmutable('now'))
            ->withHeader('kid', FingerprintGenerator::forFile(Config::getCertPath('oidc_module.crt')));
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     *
     * @return bool
     */
    private function isOpenIDRequest($scopes)
    {
        // Verify scope and make sure openid exists.
        $valid = false;

        foreach ($scopes as $scope) {
            if ('openid' === $scope->getIdentifier()) {
                $valid = true;
                break;
            }
        }

        return $valid;
    }

    /**
     * @param string $nonce
     */
    public function setNonce(string $nonce): void
    {
        $this->nonce = $nonce;
    }

    /**
     * @return string|null
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }
}
