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

use SimpleSAML\Modules\OpenIDConnect\Factories\CryptKeyFactory;
use SimpleSAML\Modules\OpenIDConnect\Factories\IdTokenBuilderFactory;
use SimpleSAML\Modules\OpenIDConnect\Repositories\CodeChallengeVerifiersRepository;
use SimpleSAML\Modules\OpenIDConnect\Server\AuthorizationServer;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\AuthCodeGrant;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\OAuth2ImplicitGrant;
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
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\RefreshTokenGrant;
use SimpleSAML\Modules\OpenIDConnect\Server\ResponseTypes\IdTokenResponse;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\ClientIdRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\CodeChallengeMethodRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\CodeChallengeRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\MaxAgeRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\PromptRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\RequestRulesManager;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\RedirectUriRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\RequestParameterRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\ScopeRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\StateRule;
use SimpleSAML\Session;
use SimpleSAML\Utils\Config;

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

        $requestRules = [
            new StateRule(),
            new ClientIdRule($clientRepository),
            new RedirectUriRule(),
            new RequestParameterRule(),
            new PromptRule($authSimpleFactory, $session),
            new MaxAgeRule($authSimpleFactory, $session),
            new ScopeRule($scopeRepository),
            new CodeChallengeRule(),
            new CodeChallengeMethodRule($codeChallengeVerifiersRepository),
        ];
        $requestRuleManager = new RequestRulesManager($requestRules);
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

        $claimTranslatorExtractor = (new ClaimTranslatorExtractorFactory(
            $configurationService
        ))->build();
        $this->services[ClaimTranslatorExtractor::class] = $claimTranslatorExtractor;

        $idTokenBuilderFactory = new IdTokenBuilderFactory(
            $userRepository,
            $configurationService,
            $claimTranslatorExtractor,
            $privateKey
        );
        $this->services[IdTokenBuilder::class] = $idTokenBuilderFactory->build();

        $idTokenResponseFactory = new IdTokenResponseFactory(
            $this->services[IdTokenBuilder::class],
            $privateKey,
            $encryptionKey
        );
        $this->services[IdTokenResponse::class] = $idTokenResponseFactory->build();

        $authCodeGrantFactory = new AuthCodeGrantFactory(
            $authCodeRepository,
            $refreshTokenRepository,
            $refreshTokenDuration,
            $authCodeDuration,
            $requestRuleManager
        );
        $this->services[AuthCodeGrant::class] = $authCodeGrantFactory->build();

        $oAuth2ImplicitGrantFactory = new OAuth2ImplicitGrantFactory($accessTokenDuration, $requestRuleManager);
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
            $this->services[IdTokenResponse::class],
            $requestRuleManager,
            $privateKey,
            $encryptionKey
        );
        $this->services[AuthorizationServer::class] = $authorizationServerFactory->build();

        $resourceServerFactory = new ResourceServerFactory(
            $accessTokenRepository,
            $publicKey
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
