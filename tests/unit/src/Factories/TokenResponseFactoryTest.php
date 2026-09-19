<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use League\OAuth2\Server\CryptKey;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use SimpleSAML\Module\oidc\Factories\TokenResponseFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\ResponseTypes\TokenResponse;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Services\LoggerService;

/**
 * The factory behind the token response.
 *
 * `routing/services/services.yml` names `build` as the factory of the TokenResponse service, which the
 * AuthorizationServerFactory takes in its constructor; nothing else calls it. The factory's whole job is to
 * hand the response its four collaborators, the user repository standing in as the identity provider, and
 * then the configured encryption key, which League's response type takes through a setter and encrypts the
 * refresh token payload with. The private key goes in through the constructor and is stored, and the
 * module's response never reads it: its tokens are signed with the configured key pair bag instead. The
 * response keeps all of it to itself, so the tests read it back by reflection.
 */
#[CoversClass(TokenResponseFactory::class)]
#[UsesClass(TokenResponse::class)]
#[AllowMockObjectsWithoutExpectations]
class TokenResponseFactoryTest extends TestCase
{
    protected const string ENCRYPTION_KEY = 'encryption-key';


    protected MockObject $moduleConfigMock;

    protected MockObject $userRepositoryMock;

    protected MockObject $idTokenBuilderMock;

    protected MockObject $privateKeyMock;

    protected MockObject $loggerServiceMock;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getEncryptionKey')->willReturn(self::ENCRYPTION_KEY);

        $this->userRepositoryMock = $this->createMock(UserRepository::class);
        $this->idTokenBuilderMock = $this->createMock(IdTokenBuilder::class);
        $this->privateKeyMock = $this->createMock(CryptKey::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
    }


    protected function sut(): TokenResponseFactory
    {
        return new TokenResponseFactory(
            $this->moduleConfigMock,
            $this->userRepositoryMock,
            $this->idTokenBuilderMock,
            $this->privateKeyMock,
            $this->loggerServiceMock,
        );
    }


    protected function propertyOf(TokenResponse $tokenResponse, string $property): mixed
    {
        return (new ReflectionProperty($tokenResponse, $property))->getValue($tokenResponse);
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(TokenResponseFactory::class, $this->sut());
    }


    /**
     * Every collaborator the factory was given is in its place on the response, and the encryption key is the
     * configured one.
     */
    public function testBuildsTheTokenResponseAroundTheFactorysCollaboratorsAndTheEncryptionKey(): void
    {
        $tokenResponse = $this->sut()->build();

        $this->assertSame($this->userRepositoryMock, $this->propertyOf($tokenResponse, 'identityProvider'));
        $this->assertSame($this->idTokenBuilderMock, $this->propertyOf($tokenResponse, 'idTokenBuilder'));
        $this->assertSame($this->privateKeyMock, $this->propertyOf($tokenResponse, 'privateKey'));
        $this->assertSame($this->loggerServiceMock, $this->propertyOf($tokenResponse, 'loggerService'));
        $this->assertSame(self::ENCRYPTION_KEY, $this->propertyOf($tokenResponse, 'encryptionKey'));
    }
}
