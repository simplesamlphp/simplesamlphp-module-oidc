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

use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\StreamFactory;
use Laminas\Diactoros\UploadedFileFactory;
use League\OAuth2\Server\ResourceServer;
use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\UploadedFileFactoryInterface;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Error\Exception;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Factories\AuthorizationServerFactory;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Factories\CacheFactory;
use SimpleSAML\Module\oidc\Factories\ClaimTranslatorExtractorFactory;
use SimpleSAML\Module\oidc\Factories\CryptKeyFactory;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Factories\FederationFactory;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\Grant\AuthCodeGrantFactory;
use SimpleSAML\Module\oidc\Factories\Grant\ImplicitGrantFactory;
use SimpleSAML\Module\oidc\Factories\Grant\OAuth2ImplicitGrantFactory;
use SimpleSAML\Module\oidc\Factories\Grant\RefreshTokenGrantFactory;
use SimpleSAML\Module\oidc\Factories\IdTokenResponseFactory;
use SimpleSAML\Module\oidc\Factories\JwksFactory;
use SimpleSAML\Module\oidc\Factories\ProcessingChainFactory;
use SimpleSAML\Module\oidc\Factories\ResourceServerFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Forms\Controls\CsrfProtection;
use SimpleSAML\Module\oidc\Helpers;
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
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AcrValuesRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AddClaimsToIdTokenRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientAuthenticationRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeMethodRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeVerifierRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\MaxAgeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\PostLogoutRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\PromptRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestedClaimsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestObjectRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredNonceRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredOpenIdScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseTypeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeOfflineAccessRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\UiLocalesRule;
use SimpleSAML\Module\oidc\Server\ResponseTypes\IdTokenResponse;
use SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator;
use SimpleSAML\Module\oidc\Stores\Session\LogoutTicketStoreBuilder;
use SimpleSAML\Module\oidc\Stores\Session\LogoutTicketStoreDb;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\ClassInstanceBuilder;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\Session;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;

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
        $authSimpleFactory = new AuthSimpleFactory($moduleConfig);
        $this->services[AuthSimpleFactory::class] = $authSimpleFactory;

        $authContextService = new AuthContextService($moduleConfig, $authSimpleFactory);
        $this->services[AuthContextService::class] = $authContextService;

        $session = Session::getSessionFromRequest();
        $this->services[Session::class] = $session;

        $csrfProtection = new CsrfProtection('{oidc:client:csrf_error}', $session);
        $formFactory = new FormFactory($moduleConfig, $csrfProtection);
        $this->services[FormFactory::class] = $formFactory;

        $jsonWebKeySetService = new JsonWebKeySetService($moduleConfig);
        $this->services[JsonWebKeySetService::class] = $jsonWebKeySetService;

        $sessionService = new SessionService($session);
        $this->services[SessionService::class] = $sessionService;

        $sessionMessagesService = new SessionMessagesService($session);
        $this->services[SessionMessagesService::class] = $sessionMessagesService;

        $templateFactory = new TemplateFactory($simpleSAMLConfiguration);
        $this->services[TemplateFactory::class] = $templateFactory;

        $opMetadataService = new OpMetadataService($moduleConfig);
        $this->services[OpMetadataService::class] = $opMetadataService;

        $metadataStorageHandler = MetaDataStorageHandler::getMetadataHandler();
        $this->services[MetaDataStorageHandler::class] = $metadataStorageHandler;

        $claimSetEntityFactory = new ClaimSetEntityFactory();
        $this->services[ClaimSetEntityFactory::class] = $claimSetEntityFactory;

        $claimTranslatorExtractor = (new ClaimTranslatorExtractorFactory(
            $moduleConfig,
            $claimSetEntityFactory,
        ))->build();
        $this->services[ClaimTranslatorExtractor::class] = $claimTranslatorExtractor;

        $processingChainFactory = new ProcessingChainFactory($moduleConfig);
        $this->services[ProcessingChainFactory::class] = $processingChainFactory;

        $stateService = new StateService();
        $this->services[StateService::class] = $stateService;

        $helpers = new Helpers();

        $core = new Core();
        $this->services[Core::class] = $core;
        $classInstanceBuilder = new ClassInstanceBuilder();
        $this->services[ClassInstanceBuilder::class] = $classInstanceBuilder;
        $cacheFactory = new CacheFactory($moduleConfig, $loggerService, $classInstanceBuilder);
        $this->services[CacheFactory::class] = $cacheFactory;
        $federationCache = $cacheFactory->forFederation();
        $this->services[FederationCache::class] = $federationCache;
        $protocolCache = $cacheFactory->forProtocol();
        $this->services[ProtocolCache::class] = $protocolCache;
        $federationFactory = new FederationFactory($moduleConfig, $loggerService, $federationCache);
        $this->services[FederationFactory::class] = $federationFactory;
        $federation = $federationFactory->build();
        $this->services[Federation::class] = $federation;

        $requestParamsResolver = new RequestParamsResolver($helpers, $core, $federation);
        $this->services[RequestParamsResolver::class] = $requestParamsResolver;

        $sspBridge = new SspBridge();
        $this->services[SspBridge::class] = $sspBridge;

        $clientEntityFactory = new ClientEntityFactory(
            $sspBridge,
            $helpers,
            $claimTranslatorExtractor,
            $requestParamsResolver,
        );
        $this->services[ClientEntityFactory::class] = $clientEntityFactory;

        $clientRepository = new ClientRepository($moduleConfig, $clientEntityFactory);
        $this->services[ClientRepository::class] = $clientRepository;

        $userRepository = new UserRepository($moduleConfig);
        $this->services[UserRepository::class] = $userRepository;

        $authCodeEntityFactory = new AuthCodeEntityFactory($helpers);
        $this->services[AuthCodeEntityFactory::class] = $authCodeEntityFactory;

        $authCodeRepository = new AuthCodeRepository(
            $moduleConfig,
            $clientRepository,
            $authCodeEntityFactory,
        );
        $this->services[AuthCodeRepository::class] = $authCodeRepository;

        $cryptKeyFactory = new CryptKeyFactory($moduleConfig);

        $publicKey = $cryptKeyFactory->buildPublicKey();
        $privateKey = $cryptKeyFactory->buildPrivateKey();

        $jsonWebTokenBuilderService = new JsonWebTokenBuilderService($moduleConfig);
        $this->services[JsonWebTokenBuilderService::class] = $jsonWebTokenBuilderService;

        $accessTokenEntityFactory = new AccessTokenEntityFactory(
            $helpers,
            $privateKey,
            $jsonWebTokenBuilderService,
        );
        $this->services[AccessTokenEntityFactory::class] = $accessTokenEntityFactory;

        $accessTokenRepository = new AccessTokenRepository(
            $moduleConfig,
            $clientRepository,
            $accessTokenEntityFactory,
        );
        $this->services[AccessTokenRepository::class] = $accessTokenRepository;

        $refreshTokenRepository = new RefreshTokenRepository($moduleConfig, $accessTokenRepository);
        $this->services[RefreshTokenRepository::class] = $refreshTokenRepository;

        $scopeRepository = new ScopeRepository($moduleConfig);
        $this->services[ScopeRepository::class] = $scopeRepository;

        $allowedOriginRepository = new AllowedOriginRepository($moduleConfig);
        $this->services[AllowedOriginRepository::class] = $allowedOriginRepository;

        $database = Database::getInstance();
        $this->services[Database::class] = $database;

        $databaseMigration = new DatabaseMigration($database);
        $this->services[DatabaseMigration::class] = $databaseMigration;

        $databaseLegacyOAuth2Import = new DatabaseLegacyOAuth2Import($clientRepository, $clientEntityFactory);
        $this->services[DatabaseLegacyOAuth2Import::class] = $databaseLegacyOAuth2Import;

        $authenticationService = new AuthenticationService(
            $userRepository,
            $authSimpleFactory,
            $clientRepository,
            $opMetadataService,
            $sessionService,
            $claimTranslatorExtractor,
            $moduleConfig,
            $processingChainFactory,
            $stateService,
            $helpers,
            $requestParamsResolver,
        );
        $this->services[AuthenticationService::class] = $authenticationService;

        $codeChallengeVerifiersRepository = new CodeChallengeVerifiersRepository();
        $this->services[CodeChallengeVerifiersRepository::class] = $codeChallengeVerifiersRepository;

        $jwksFactory = new JwksFactory($moduleConfig, $loggerService, $federationCache);
        $this->services[JwksFactory::class] = $jwksFactory;

        $jwks = $jwksFactory->build();
        $this->services[Jwks::class] = $jwks;

        $jwksResolver = new JwksResolver($jwks);
        $this->services[JwksResolver::class] = $jwksResolver;

        $requestRules = [
            new StateRule($requestParamsResolver),
            new ClientIdRule(
                $requestParamsResolver,
                $clientRepository,
                $moduleConfig,
                $clientEntityFactory,
                $federation,
                $helpers,
                $jwksResolver,
                $federationCache,
            ),
            new RedirectUriRule($requestParamsResolver),
            new RequestObjectRule($requestParamsResolver, $jwksResolver),
            new PromptRule($requestParamsResolver, $authSimpleFactory, $authenticationService),
            new MaxAgeRule($requestParamsResolver, $authSimpleFactory, $authenticationService),
            new ScopeRule($requestParamsResolver, $scopeRepository, $helpers),
            new RequiredOpenIdScopeRule($requestParamsResolver),
            new CodeChallengeRule($requestParamsResolver),
            new CodeChallengeMethodRule($requestParamsResolver, $codeChallengeVerifiersRepository),
            new RequestedClaimsRule($requestParamsResolver, $claimTranslatorExtractor),
            new AddClaimsToIdTokenRule($requestParamsResolver),
            new RequiredNonceRule($requestParamsResolver),
            new ResponseTypeRule($requestParamsResolver),
            new IdTokenHintRule($requestParamsResolver, $moduleConfig, $cryptKeyFactory),
            new PostLogoutRedirectUriRule($requestParamsResolver, $clientRepository),
            new UiLocalesRule($requestParamsResolver),
            new AcrValuesRule($requestParamsResolver),
            new ScopeOfflineAccessRule($requestParamsResolver),
            new ClientAuthenticationRule(
                $requestParamsResolver,
                $moduleConfig,
                $jwksResolver,
                $helpers,
                $protocolCache,
            ),
            new CodeVerifierRule($requestParamsResolver),
        ];
        $requestRuleManager = new RequestRulesManager($requestRules, $loggerService);
        $this->services[RequestRulesManager::class] = $requestRuleManager;

        $idTokenBuilder = new IdTokenBuilder($jsonWebTokenBuilderService, $claimTranslatorExtractor);
        $this->services[IdTokenBuilder::class] = $idTokenBuilder;

        $logoutTokenBuilder = new LogoutTokenBuilder($jsonWebTokenBuilderService);
        $this->services[LogoutTokenBuilder::class] = $logoutTokenBuilder;

        $sessionLogoutTicketStoreDb = new LogoutTicketStoreDb($database);
        $this->services[LogoutTicketStoreDb::class] = $sessionLogoutTicketStoreDb;

        $sessionLogoutTicketStoreBuilder = new LogoutTicketStoreBuilder($sessionLogoutTicketStoreDb);
        $this->services[LogoutTicketStoreBuilder::class] = $sessionLogoutTicketStoreBuilder;

        $idTokenResponseFactory = new IdTokenResponseFactory(
            $moduleConfig,
            $userRepository,
            $this->services[IdTokenBuilder::class],
            $privateKey,
        );
        $this->services[IdTokenResponse::class] = $idTokenResponseFactory->build();

        $this->services[Helpers::class] = $helpers;

        $authCodeGrantFactory = new AuthCodeGrantFactory(
            $moduleConfig,
            $authCodeRepository,
            $accessTokenRepository,
            $refreshTokenRepository,
            $requestRuleManager,
            $requestParamsResolver,
            $accessTokenEntityFactory,
            $authCodeEntityFactory,
        );
        $this->services[AuthCodeGrant::class] = $authCodeGrantFactory->build();

        $oAuth2ImplicitGrantFactory = new OAuth2ImplicitGrantFactory($moduleConfig, $requestRuleManager);
        $this->services[OAuth2ImplicitGrant::class] = $oAuth2ImplicitGrantFactory->build();

        $implicitGrantFactory = new ImplicitGrantFactory(
            $moduleConfig,
            $this->services[IdTokenBuilder::class],
            $requestRuleManager,
            $accessTokenRepository,
            $requestParamsResolver,
            $accessTokenEntityFactory,
        );
        $this->services[ImplicitGrant::class] = $implicitGrantFactory->build();

        $refreshTokenGrantFactory = new RefreshTokenGrantFactory(
            $moduleConfig,
            $refreshTokenRepository,
            $accessTokenEntityFactory,
        );
        $this->services[RefreshTokenGrant::class] = $refreshTokenGrantFactory->build();

        $authorizationServerFactory = new AuthorizationServerFactory(
            $moduleConfig,
            $clientRepository,
            $accessTokenRepository,
            $scopeRepository,
            $this->services[AuthCodeGrant::class],
            $this->services[OAuth2ImplicitGrant::class],
            $this->services[ImplicitGrant::class],
            $this->services[RefreshTokenGrant::class],
            $this->services[IdTokenResponse::class],
            $requestRuleManager,
            $privateKey,
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

        $httpFoundationFactory = new HttpFoundationFactory();
        $this->services[HttpFoundationFactory::class] = $httpFoundationFactory;

        $serverRequestFactory = new ServerRequestFactory();
        $this->services[ServerRequestFactoryInterface::class] = $serverRequestFactory;

        $responseFactory = new ResponseFactory();
        $this->services[ResponseFactoryInterface::class] = $responseFactory;

        $streamFactory = new StreamFactory();
        $this->services[StreamFactoryInterface::class] = $streamFactory;

        $uploadedFileFactory = new UploadedFileFactory();
        $this->services[UploadedFileFactoryInterface::class] = $uploadedFileFactory;

        $psrHttpBridge = new PsrHttpBridge(
            $httpFoundationFactory,
            $serverRequestFactory,
            $responseFactory,
            $streamFactory,
            $uploadedFileFactory,
        );
        $this->services[PsrHttpBridge::class] = $psrHttpBridge;

        $errorResponder = new ErrorResponder($psrHttpBridge);
        $this->services[ErrorResponder::class] = $errorResponder;
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
