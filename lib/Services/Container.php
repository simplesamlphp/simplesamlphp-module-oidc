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

namespace SimpleSAML\Modules\OpenIDConnect\Services;

use SimpleSAML\Modules\OpenIDConnect\Server\AuthorizationServer;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\AuthCodeGrant;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\OAuth2ImplicitGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\ResourceServer;
use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Error\Exception;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Modules\OpenIDConnect\ClaimTranslatorExtractor;
use SimpleSAML\Modules\OpenIDConnect\Factories\AuthorizationServerFactory;
use SimpleSAML\Modules\OpenIDConnect\Factories\AuthSimpleFactory;
use SimpleSAML\Modules\OpenIDConnect\Factories\ClaimTranslatorExtractorFactory;
use SimpleSAML\Modules\OpenIDConnect\Factories\FormFactory;
use SimpleSAML\Modules\OpenIDConnect\Factories\Grant\AuthCodeGrantFactory;
use SimpleSAML\Modules\OpenIDConnect\Factories\Grant\OAuth2ImplicitGrantFactory;
use SimpleSAML\Modules\OpenIDConnect\Factories\Grant\RefreshTokenGrantFactory;
use SimpleSAML\Modules\OpenIDConnect\Factories\IdTokenResponseFactory;
use SimpleSAML\Modules\OpenIDConnect\Factories\ResourceServerFactory;
use SimpleSAML\Modules\OpenIDConnect\Factories\TemplateFactory;
use SimpleSAML\Modules\OpenIDConnect\Repositories\AccessTokenRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\AuthCodeRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\RefreshTokenRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ScopeRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\UserRepository;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\CodeChallengeRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\PromptRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\RequestRulesManager;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\ScopeRule;
use SimpleSAML\Session;

class Container implements ContainerInterface
{
    /** @var array */
    private $services = [];

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

        $database = Database::getInstance();
        $this->services[Database::class] = $database;

        $databaseMigration = new DatabaseMigration($database);
        $this->services[DatabaseMigration::class] = $databaseMigration;

        $databaseLegacyOAuth2Import = new DatabaseLegacyOAuth2Import($clientRepository);
        $this->services[DatabaseLegacyOAuth2Import::class] = $databaseLegacyOAuth2Import;

        $authSimpleFactory = new AuthSimpleFactory($clientRepository, $configurationService);
        $this->services[AuthSimpleFactory::class] = $authSimpleFactory;

        $formFactory = new FormFactory($configurationService);
        $this->services[FormFactory::class] = $formFactory;

        $jsonWebKeySetService = new JsonWebKeySetService();
        $this->services[JsonWebKeySetService::class] = $jsonWebKeySetService;

        $sessionMessagesService = new SessionMessagesService(Session::getSessionFromRequest());
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

        // Request rules, order is important
        $promptRule = new PromptRule($authSimpleFactory);
        $scopesRule = new ScopeRule($scopeRepository);
        $codeChallengeRule = new CodeChallengeRule();
        $requestRuleManager = new RequestRulesManager();
        $requestRuleManager->add($promptRule);
        $requestRuleManager->add($scopesRule);
        $requestRuleManager->add($codeChallengeRule);
        // TODO separate rules for each grant and for each request (authorization and token)...
        $this->services[RequestRulesManager::class] = $requestRuleManager;

        $accessTokenDuration = new \DateInterval(
            $configurationService->getOpenIDConnectConfiguration()->getString('accessTokenDuration')
        );
        $authCodeDuration = new \DateInterval(
            $configurationService->getOpenIDConnectConfiguration()->getString('authCodeDuration')
        );
        $refreshTokenDuration = new \DateInterval(
            $configurationService->getOpenIDConnectConfiguration()->getString('refreshTokenDuration')
        );
        $passPhrase = $configurationService->getOpenIDConnectConfiguration()->getString('pass_phrase', null);

        $claimTranslatorExtractor = (new ClaimTranslatorExtractorFactory(
            $configurationService
        ))->build();
        $this->services[ClaimTranslatorExtractor::class] = $claimTranslatorExtractor;

        $idTokenResponseFactory = new IdTokenResponseFactory(
            $userRepository,
            $configurationService,
            $claimTranslatorExtractor
        );
        $this->services[IdTokenResponseFactory::class] = $idTokenResponseFactory;

        $authCodeGrantFactory = new AuthCodeGrantFactory(
            $authCodeRepository,
            $refreshTokenRepository,
            $refreshTokenDuration,
            $authCodeDuration,
            $requestRuleManager
        );
        $this->services[AuthCodeGrant::class] = $authCodeGrantFactory->build();

        $oAuth2ImplicitGrantFactory = new OAuth2ImplicitGrantFactory($accessTokenDuration);
        $this->services[OAuth2ImplicitGrant::class] = $oAuth2ImplicitGrantFactory->build();

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
            $this->services[RefreshTokenGrant::class],
            $accessTokenDuration,
            $idTokenResponseFactory,
            $passPhrase
        );
        $this->services[AuthorizationServer::class] = $authorizationServerFactory->build();

        $resourceServerFactory = new ResourceServerFactory(
            $accessTokenRepository
        );
        $this->services[ResourceServer::class] = $resourceServerFactory->build();
    }

    /**
     * @param string $id
     *
     * @throws \SimpleSAML\Error\Exception
     *
     * @return object
     */
    public function get($id)
    {
        if (false === $this->has($id)) {
            throw new class ($id) extends Exception implements NotFoundExceptionInterface {
                public function __construct(string $id)
                {
                    parent::__construct("Service not found: {$id}.");
                }
            };
        }

        return $this->services[$id];
    }

    /**
     * @param string $id
     *
     * @return bool
     */
    public function has($id)
    {
        return \array_key_exists($id, $this->services);
    }
}
