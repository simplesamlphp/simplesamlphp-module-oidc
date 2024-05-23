<?php

declare(strict_types=1);

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
use SimpleSAML\Module\oidc\Factories\AuthorizationServerFactory;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Factories\ClaimTranslatorExtractorFactory;
use SimpleSAML\Module\oidc\Factories\CryptKeyFactory;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\Grant\AuthCodeGrantFactory;
use SimpleSAML\Module\oidc\Factories\Grant\ImplicitGrantFactory;
use SimpleSAML\Module\oidc\Factories\Grant\OAuth2ImplicitGrantFactory;
use SimpleSAML\Module\oidc\Factories\Grant\RefreshTokenGrantFactory;
use SimpleSAML\Module\oidc\Factories\IdTokenResponseFactory;
use SimpleSAML\Module\oidc\Factories\ResourceServerFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
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
use SimpleSAML\Module\oidc\Stores\Session\LogoutTicketStoreBuilder;
use SimpleSAML\Module\oidc\Stores\Session\LogoutTicketStoreDb;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\AcrValuesRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\AddClaimsToIdTokenRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\CodeChallengeMethodRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\CodeChallengeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\MaxAgeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\PostLogoutRedirectUriRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\PromptRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequestedClaimsRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequestParameterRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequiredNonceRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequiredOpenIdScopeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ResponseTypeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ScopeOfflineAccessRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\StateRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\UiLocalesRule;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Session;
use SimpleSAML\Utils\Config;

class Container implements ContainerInterface
{
    private array $services = [];

    /**
     * @throws \Exception
     */
    public function __construct()
    {
        $simpleSAMLConfiguration = Configuration::getInstance();

        $moduleConfig = new ModuleConfig();
        $this->services[ModuleConfig::class] = $moduleConfig;

        $loggerService = new LoggerService();
        $this->services[LoggerService::class] = $loggerService;

        $clientRepository = new ClientRepository($moduleConfig);
        $this->services[ClientRepository::class] = $clientRepository;

        $userRepository = new UserRepository($moduleConfig);
        $this->services[UserRepository::class] = $userRepository;

        $authCodeRepository = new AuthCodeRepository($moduleConfig);
        $this->services[AuthCodeRepository::class] = $authCodeRepository;

        $refreshTokenRepository = new RefreshTokenRepository($moduleConfig);
        $this->services[RefreshTokenRepository::class] = $refreshTokenRepository;

        $accessTokenRepository = new AccessTokenRepository($moduleConfig);
        $this->services[AccessTokenRepository::class] = $accessTokenRepository;

        $scopeRepository = new ScopeRepository($moduleConfig);
        $this->services[ScopeRepository::class] = $scopeRepository;

        $allowedOriginRepository = new AllowedOriginRepository($moduleConfig);
        $this->services[AllowedOriginRepository::class] = $allowedOriginRepository;

        $database = Database::getInstance();
        $this->services[Database::class] = $database;

        $databaseMigration = new DatabaseMigration($database);
        $this->services[DatabaseMigration::class] = $databaseMigration;

        $databaseLegacyOAuth2Import = new DatabaseLegacyOAuth2Import($clientRepository);
        $this->services[DatabaseLegacyOAuth2Import::class] = $databaseLegacyOAuth2Import;

        $authSimpleFactory = new AuthSimpleFactory($clientRepository, $moduleConfig);
        $this->services[AuthSimpleFactory::class] = $authSimpleFactory;

        $authContextService = new AuthContextService($moduleConfig, $authSimpleFactory);
        $this->services[AuthContextService::class] = $authContextService;

        $formFactory = new FormFactory($moduleConfig);
        $this->services[FormFactory::class] = $formFactory;

        $jsonWebKeySetService = new JsonWebKeySetService($moduleConfig);
        $this->services[JsonWebKeySetService::class] = $jsonWebKeySetService;

        $session = Session::getSessionFromRequest();
        $this->services[Session::class] = $session;

        $sessionService = new SessionService($session);
        $this->services[SessionService::class] = $sessionService;

        $sessionMessagesService = new SessionMessagesService($session);
        $this->services[SessionMessagesService::class] = $sessionMessagesService;

        $templateFactory = new TemplateFactory($simpleSAMLConfiguration);
        $this->services[TemplateFactory::class] = $templateFactory;

        $authProcService = new AuthProcService($moduleConfig);
        $this->services[AuthProcService::class] = $authProcService;

        $opMetadataService = new OpMetadataService($moduleConfig);
        $this->services[OpMetadataService::class] = $opMetadataService;

        $metadataStorageHandler = MetaDataStorageHandler::getMetadataHandler();
        $this->services[MetaDataStorageHandler::class] = $metadataStorageHandler;

        $claimTranslatorExtractor = (new ClaimTranslatorExtractorFactory(
            $moduleConfig,
        ))->build();
        $this->services[ClaimTranslatorExtractor::class] = $claimTranslatorExtractor;

        $authenticationService = new AuthenticationService(
            $userRepository,
            $authSimpleFactory,
            $authProcService,
            $clientRepository,
            $opMetadataService,
            $sessionService,
            $claimTranslatorExtractor,
            $moduleConfig,
        );
        $this->services[AuthenticationService::class] = $authenticationService;

        $codeChallengeVerifiersRepository = new CodeChallengeVerifiersRepository();
        $this->services[CodeChallengeVerifiersRepository::class] = $codeChallengeVerifiersRepository;

        $cryptKeyFactory = new CryptKeyFactory($moduleConfig);

        $requestRules = [
            new StateRule(),
            new ClientIdRule($clientRepository),
            new RedirectUriRule(),
            new RequestParameterRule(),
            new PromptRule($authSimpleFactory, $authenticationService),
            new MaxAgeRule($authSimpleFactory, $authenticationService),
            new ScopeRule($scopeRepository),
            new RequiredOpenIdScopeRule(),
            new CodeChallengeRule(),
            new CodeChallengeMethodRule($codeChallengeVerifiersRepository),
            new RequestedClaimsRule($claimTranslatorExtractor),
            new AddClaimsToIdTokenRule(),
            new RequiredNonceRule(),
            new ResponseTypeRule(),
            new IdTokenHintRule($moduleConfig, $cryptKeyFactory),
            new PostLogoutRedirectUriRule($clientRepository),
            new UiLocalesRule(),
            new AcrValuesRule(),
            new ScopeOfflineAccessRule(),
        ];
        $requestRuleManager = new RequestRulesManager($requestRules, $loggerService);
        $this->services[RequestRulesManager::class] = $requestRuleManager;

        $accessTokenDuration = new DateInterval(
            $moduleConfig->config()->getString(ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_TTL),
        );
        $authCodeDuration = new DateInterval(
            $moduleConfig->config()->getString(ModuleConfig::OPTION_TOKEN_AUTHORIZATION_CODE_TTL),
        );
        $refreshTokenDuration = new DateInterval(
            $moduleConfig->config()->getString(ModuleConfig::OPTION_TOKEN_REFRESH_TOKEN_TTL),
        );
        $publicKey = $cryptKeyFactory->buildPublicKey();
        $privateKey = $cryptKeyFactory->buildPrivateKey();
        $encryptionKey = (new Config())->getSecretSalt();

        $jsonWebTokenBuilderService = new JsonWebTokenBuilderService($moduleConfig);
        $this->services[JsonWebTokenBuilderService::class] = $jsonWebTokenBuilderService;

        $idTokenBuilder = new IdTokenBuilder($jsonWebTokenBuilderService, $claimTranslatorExtractor);
        $this->services[IdTokenBuilder::class] = $idTokenBuilder;

        $logoutTokenBuilder = new LogoutTokenBuilder($jsonWebTokenBuilderService);
        $this->services[LogoutTokenBuilder::class] = $logoutTokenBuilder;

        $sessionLogoutTicketStoreDb = new LogoutTicketStoreDb($database);
        $this->services[LogoutTicketStoreDb::class] = $sessionLogoutTicketStoreDb;

        $sessionLogoutTicketStoreBuilder = new LogoutTicketStoreBuilder($sessionLogoutTicketStoreDb);
        $this->services[LogoutTicketStoreBuilder::class] = $sessionLogoutTicketStoreBuilder;

        $idTokenResponseFactory = new IdTokenResponseFactory(
            $userRepository,
            $this->services[IdTokenBuilder::class],
            $privateKey,
            $encryptionKey,
        );
        $this->services[IdTokenResponse::class] = $idTokenResponseFactory->build();

        $authCodeGrantFactory = new AuthCodeGrantFactory(
            $authCodeRepository,
            $accessTokenRepository,
            $refreshTokenRepository,
            $refreshTokenDuration,
            $authCodeDuration,
            $requestRuleManager,
        );
        $this->services[AuthCodeGrant::class] = $authCodeGrantFactory->build();

        $oAuth2ImplicitGrantFactory = new OAuth2ImplicitGrantFactory($accessTokenDuration, $requestRuleManager);
        $this->services[OAuth2ImplicitGrant::class] = $oAuth2ImplicitGrantFactory->build();

        $implicitGrantFactory = new ImplicitGrantFactory(
            $this->services[IdTokenBuilder::class],
            $accessTokenDuration,
            $requestRuleManager,
            $accessTokenRepository,
        );
        $this->services[ImplicitGrant::class] = $implicitGrantFactory->build();

        $refreshTokenGrantFactory = new RefreshTokenGrantFactory(
            $refreshTokenRepository,
            $refreshTokenDuration,
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
            $encryptionKey,
        );
        $this->services[AuthorizationServer::class] = $authorizationServerFactory->build();

        $bearerTokenValidator = new BearerTokenValidator($accessTokenRepository, $publicKey);
        $this->services[BearerTokenValidator::class] = $bearerTokenValidator;

        $resourceServerFactory = new ResourceServerFactory(
            $accessTokenRepository,
            $publicKey,
            $bearerTokenValidator,
        );
        $this->services[ResourceServer::class] = $resourceServerFactory->build();
    }

    /**
     * @inheritdoc
     */
    public function get(string $id): mixed
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
    public function has(string $id): bool
    {
        return array_key_exists($id, $this->services);
    }
}
