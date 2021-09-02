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

namespace SimpleSAML\Module\oidc\Services;

use DateInterval;
use League\OAuth2\Server\ResourceServer;
use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Error\Exception;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module\oidc\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Factories\AuthorizationServerFactory;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Factories\ClaimTranslatorExtractorFactory;
use SimpleSAML\Module\oidc\Factories\CryptKeyFactory;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\Grant\AuthCodeGrantFactory;
use SimpleSAML\Module\oidc\Factories\Grant\ImplicitGrantFactory;
use SimpleSAML\Module\oidc\Factories\Grant\OAuth2ImplicitGrantFactory;
use SimpleSAML\Module\oidc\Factories\Grant\RefreshTokenGrantFactory;
use SimpleSAML\Module\oidc\Factories\IdTokenBuilderFactory;
use SimpleSAML\Module\oidc\Factories\IdTokenResponseFactory;
use SimpleSAML\Module\oidc\Factories\ResourceServerFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\CodeChallengeVerifiersRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Repositories\ScopeRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\Grants\AuthCodeGrant;
use SimpleSAML\Module\oidc\Server\Grants\ImplicitGrant;
use SimpleSAML\Module\oidc\Server\Grants\OAuth2ImplicitGrant;
use SimpleSAML\Module\oidc\Server\Grants\RefreshTokenGrant;
use SimpleSAML\Module\oidc\Server\ResponseTypes\IdTokenResponse;
use SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\AddClaimsToIdTokenRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\CodeChallengeMethodRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\CodeChallengeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\MaxAgeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\PromptRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequestedClaimsRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequestParameterRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequiredNonceRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequiredOpenIdScopeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ResponseTypeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\StateRule;
use SimpleSAML\Session;
use SimpleSAML\Utils\Config;

class Container implements ContainerInterface
{
    /** @var array */
    private $services = [];

    /**
     * @throws \Exception
     */
    public function __construct()
    {
        $simpleSAMLConfiguration = Configuration::getInstance();
        $oidcModuleConfiguration = Configuration::getConfig('module_oidc.php');

        $configurationService = new ConfigurationService();
        $this->services[ConfigurationService::class] = $configurationService;

        $clientRepository = new ClientRepository($configurationService);
        $this->services[ClientRepository::class] = $clientRepository;

        $userRepository = new UserRepository($configurationService);
        $this->services[UserRepository::class] = $userRepository;

        $authCodeRepository = new AuthCodeRepository($configurationService);
        $this->services[AuthCodeRepository::class] = $authCodeRepository;

        $refreshTokenRepository = new RefreshTokenRepository($configurationService);
        $this->services[RefreshTokenRepository::class] = $refreshTokenRepository;

        $accessTokenRepository = new AccessTokenRepository($configurationService);
        $this->services[AccessTokenRepository::class] = $accessTokenRepository;

        $scopeRepository = new ScopeRepository($configurationService);
        $this->services[ScopeRepository::class] = $scopeRepository;

        $allowedOriginRepository = new AllowedOriginRepository($configurationService);
        $this->services[AllowedOriginRepository::class] = $allowedOriginRepository;

        $database = Database::getInstance();
        $this->services[Database::class] = $database;

        $databaseMigration = new DatabaseMigration($database);
        $this->services[DatabaseMigration::class] = $databaseMigration;

        $databaseLegacyOAuth2Import = new DatabaseLegacyOAuth2Import($clientRepository);
        $this->services[DatabaseLegacyOAuth2Import::class] = $databaseLegacyOAuth2Import;

        $authSimpleFactory = new AuthSimpleFactory($clientRepository, $configurationService);
        $this->services[AuthSimpleFactory::class] = $authSimpleFactory;

        $authContextService = new AuthContextService($configurationService, $authSimpleFactory);
        $this->services[AuthContextService::class] = $authContextService;

        $formFactory = new FormFactory($configurationService);
        $this->services[FormFactory::class] = $formFactory;

        $jsonWebKeySetService = new JsonWebKeySetService();
        $this->services[JsonWebKeySetService::class] = $jsonWebKeySetService;

        $session = Session::getSessionFromRequest();
        $this->services[Session::class] = $session;

        $sessionMessagesService = new SessionMessagesService($session);
        $this->services[SessionMessagesService::class] = $sessionMessagesService;

        $templateFactory = new TemplateFactory($simpleSAMLConfiguration);
        $this->services[TemplateFactory::class] = $templateFactory;

        $authProcService = new AuthProcService($configurationService);
        $this->services[AuthProcService::class] = $authProcService;

        $oidcOpenIdProviderMetadataService = new OidcOpenIdProviderMetadataService($configurationService);
        $this->services[OidcOpenIdProviderMetadataService::class] = $oidcOpenIdProviderMetadataService;

        $metadataStorageHandler = MetaDataStorageHandler::getMetadataHandler();
        $this->services[MetaDataStorageHandler::class] = $metadataStorageHandler;

        $authenticationService = new AuthenticationService(
            $userRepository,
            $authSimpleFactory,
            $authProcService,
            $clientRepository,
            $oidcOpenIdProviderMetadataService,
            $oidcModuleConfiguration->getString('useridattr', 'uid')
        );
        $this->services[AuthenticationService::class] = $authenticationService;

        $codeChallengeVerifiersRepository = new CodeChallengeVerifiersRepository();
        $this->services[CodeChallengeVerifiersRepository::class] = $codeChallengeVerifiersRepository;

        $claimTranslatorExtractor = (new ClaimTranslatorExtractorFactory(
            $configurationService
        ))->build();
        $this->services[ClaimTranslatorExtractor::class] = $claimTranslatorExtractor;

        $requestRules = [
            new StateRule(),
            new ClientIdRule($clientRepository),
            new RedirectUriRule(),
            new RequestParameterRule(),
            new PromptRule($authSimpleFactory, $session),
            new MaxAgeRule($authSimpleFactory, $session),
            new ScopeRule($scopeRepository),
            new RequiredOpenIdScopeRule(),
            new CodeChallengeRule(),
            new CodeChallengeMethodRule($codeChallengeVerifiersRepository),
            new RequestedClaimsRule($claimTranslatorExtractor),
            new AddClaimsToIdTokenRule(),
            new RequiredNonceRule(),
            new ResponseTypeRule(),
        ];
        $requestRuleManager = new RequestRulesManager($requestRules);
        $this->services[RequestRulesManager::class] = $requestRuleManager;

        $accessTokenDuration = new DateInterval(
            $configurationService->getOpenIDConnectConfiguration()->getString('accessTokenDuration')
        );
        $authCodeDuration = new DateInterval(
            $configurationService->getOpenIDConnectConfiguration()->getString('authCodeDuration')
        );
        $refreshTokenDuration = new DateInterval(
            $configurationService->getOpenIDConnectConfiguration()->getString('refreshTokenDuration')
        );

        $publicKeyPath = Config::getCertPath('oidc_module.crt');
        $privateKeyPath = Config::getCertPath('oidc_module.pem');
        $passPhrase = $configurationService->getOpenIDConnectConfiguration()->getString('pass_phrase', null);

        $cryptKeyFactory = new CryptKeyFactory(
            $publicKeyPath,
            $privateKeyPath,
            $passPhrase
        );
        $publicKey = $cryptKeyFactory->buildPublicKey();
        $privateKey = $cryptKeyFactory->buildPrivateKey();
        $encryptionKey = Config::getSecretSalt();

        $idTokenBuilderFactory = new IdTokenBuilderFactory(
            $configurationService,
            $claimTranslatorExtractor,
            $privateKey
        );
        $this->services[IdTokenBuilder::class] = $idTokenBuilderFactory->build();

        $idTokenResponseFactory = new IdTokenResponseFactory(
            $userRepository,
            $this->services[ConfigurationService::class],
            $this->services[IdTokenBuilder::class],
            $privateKey,
            $encryptionKey
        );
        $this->services[IdTokenResponse::class] = $idTokenResponseFactory->build();

        $authCodeGrantFactory = new AuthCodeGrantFactory(
            $authCodeRepository,
            $accessTokenRepository,
            $refreshTokenRepository,
            $refreshTokenDuration,
            $authCodeDuration,
            $requestRuleManager
        );
        $this->services[AuthCodeGrant::class] = $authCodeGrantFactory->build();

        $oAuth2ImplicitGrantFactory = new OAuth2ImplicitGrantFactory($accessTokenDuration, $requestRuleManager);
        $this->services[OAuth2ImplicitGrant::class] = $oAuth2ImplicitGrantFactory->build();

        $implicitGrantFactory = new ImplicitGrantFactory(
            $this->services[IdTokenBuilder::class],
            $accessTokenDuration,
            $requestRuleManager,
            $accessTokenRepository
        );
        $this->services[ImplicitGrant::class] = $implicitGrantFactory->build();

        $refreshTokenGrantFactory = new RefreshTokenGrantFactory(
            $refreshTokenRepository,
            $refreshTokenDuration
        );
        $this->services[RefreshTokenGrant::class] = $refreshTokenGrantFactory->build();

        $authorizationServerFactory = new AuthorizationServerFactory(
            $clientRepository,
            $accessTokenRepository,
            $scopeRepository,
            $this->services[AuthCodeGrant::class],
            $this->services[OAuth2ImplicitGrant::class],
            $this->services[ImplicitGrant::class],
            $this->services[RefreshTokenGrant::class],
            $accessTokenDuration,
            $this->services[IdTokenResponse::class],
            $requestRuleManager,
            $privateKey,
            $encryptionKey
        );
        $this->services[AuthorizationServer::class] = $authorizationServerFactory->build();

        $bearerTokenValidator = new BearerTokenValidator($accessTokenRepository);
        $this->services[BearerTokenValidator::class] = $bearerTokenValidator;

        $resourceServerFactory = new ResourceServerFactory(
            $accessTokenRepository,
            $publicKey,
            $bearerTokenValidator
        );
        $this->services[ResourceServer::class] = $resourceServerFactory->build();
    }

    /**
     * @inheritdoc
     */
    public function get($id)
    {
        if (false === $this->has($id)) {
            throw new class ($id) extends Exception implements NotFoundExceptionInterface {
                public function __construct(string $id)
                {
                    parent::__construct("Service not found: $id.");
                }
            };
        }

        return $this->services[$id];
    }

    /**
     * @inheritdoc
     */
    public function has($id)
    {
        return array_key_exists($id, $this->services);
    }
}
