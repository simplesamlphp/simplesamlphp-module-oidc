<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\VciContextResolver;
use SimpleSAML\OpenID\Codebooks\AtContextsEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;

/**
 * The `@context` of a `vc+sd-jwt` credential, as the credential and the issuer metadata both carry it.
 *
 * The W3C credentials v2 context comes first, always. The module's own context document for the
 * credential configuration comes second, by its URL, when one is configured. Whatever the credential
 * configuration declares under `credential_definition.@context` -- or under a top level `@context`, when
 * the definition has none -- follows, each string once, the W3C context and anything already listed
 * skipped, and anything which is not a string ignored.
 */
#[CoversClass(VciContextResolver::class)]
#[AllowMockObjectsWithoutExpectations]
class VciContextResolverTest extends TestCase
{
    protected const string CREDENTIAL_CONFIGURATION_ID = 'EmployeeBadge';

    protected const string MODULE_CONTEXT_URL = 'https://op.example.org/vci/context/EmployeeBadge';

    protected const string CONTEXT_A = 'https://example.org/contexts/badge-a';

    protected const string CONTEXT_B = 'https://example.org/contexts/badge-b';


    protected MockObject $moduleConfigMock;

    protected MockObject $routesMock;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->routesMock = $this->createMock(Routes::class);
        $this->routesMock->method('urlCredentialJsonLdContext')
            ->with(self::CREDENTIAL_CONFIGURATION_ID)
            ->willReturn(self::MODULE_CONTEXT_URL);
    }


    protected function sut(): VciContextResolver
    {
        return new VciContextResolver($this->moduleConfigMock, $this->routesMock);
    }


    protected function withAContextDocumentConfigured(bool $configured = true): void
    {
        $this->moduleConfigMock->method('getVciCredentialJsonLdContextFor')
            ->with(self::CREDENTIAL_CONFIGURATION_ID)
            ->willReturn($configured ? ['@context' => ['@version' => 1.1]] : null);
    }


    /**
     * @param string[] $contexts
     * @return array<string,mixed>
     */
    protected static function configurationDefining(array $contexts): array
    {
        return [
            ClaimsEnum::CredentialDefinition->value => [
                ClaimsEnum::AtContext->value => $contexts,
            ],
        ];
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(VciContextResolver::class, $this->sut());
    }


    public function testTheW3cContextIsAllThereIsForAConfigurationDeclaringNoneWithNoContextDocument(): void
    {
        $this->withAContextDocumentConfigured(false);
        $this->routesMock->expects($this->never())->method('urlCredentialJsonLdContext');

        $this->assertSame(
            [AtContextsEnum::W3OrgNsCredentialsV2->value],
            $this->sut()->resolve(self::CREDENTIAL_CONFIGURATION_ID, []),
        );
    }


    public function testTheModulesContextDocumentUrlFollowsTheW3cContextWhenOneIsConfigured(): void
    {
        $this->withAContextDocumentConfigured();

        $this->assertSame(
            [AtContextsEnum::W3OrgNsCredentialsV2->value, self::MODULE_CONTEXT_URL],
            $this->sut()->resolve(self::CREDENTIAL_CONFIGURATION_ID, []),
        );
    }


    public function testTheDeclaredContextsFollowInTheirOrderWithTheW3cContextNotRepeated(): void
    {
        $this->withAContextDocumentConfigured();

        $atContext = $this->sut()->resolve(
            self::CREDENTIAL_CONFIGURATION_ID,
            self::configurationDefining([
                self::CONTEXT_B,
                AtContextsEnum::W3OrgNsCredentialsV2->value,
                self::CONTEXT_A,
            ]),
        );

        $this->assertSame(
            [AtContextsEnum::W3OrgNsCredentialsV2->value, self::MODULE_CONTEXT_URL, self::CONTEXT_B, self::CONTEXT_A],
            $atContext,
        );
    }


    public function testATopLevelContextDeclarationCountsWhenTheDefinitionHasNone(): void
    {
        $this->withAContextDocumentConfigured(false);

        $atContext = $this->sut()->resolve(
            self::CREDENTIAL_CONFIGURATION_ID,
            [ClaimsEnum::AtContext->value => [self::CONTEXT_A]],
        );

        $this->assertSame([AtContextsEnum::W3OrgNsCredentialsV2->value, self::CONTEXT_A], $atContext);
    }


    public function testTheDefinitionsContextDeclarationOutranksATopLevelOne(): void
    {
        $this->withAContextDocumentConfigured(false);

        $atContext = $this->sut()->resolve(
            self::CREDENTIAL_CONFIGURATION_ID,
            self::configurationDefining([self::CONTEXT_A]) + [ClaimsEnum::AtContext->value => [self::CONTEXT_B]],
        );

        $this->assertSame([AtContextsEnum::W3OrgNsCredentialsV2->value, self::CONTEXT_A], $atContext);
    }


    /**
     * A context listed twice, or one which is the module's own document URL, goes in once; a member which
     * is not a string goes in not at all.
     */
    public function testListsEachContextOnceAndOnlyStrings(): void
    {
        $this->withAContextDocumentConfigured();

        $atContext = $this->sut()->resolve(
            self::CREDENTIAL_CONFIGURATION_ID,
            self::configurationDefining([
                self::CONTEXT_A,
                self::MODULE_CONTEXT_URL,
                42,
                null,
                ['nested' => self::CONTEXT_B],
                self::CONTEXT_A,
            ]),
        );

        $this->assertSame(
            [AtContextsEnum::W3OrgNsCredentialsV2->value, self::MODULE_CONTEXT_URL, self::CONTEXT_A],
            $atContext,
        );
    }


    /**
     * @param mixed $declared
     */
    #[DataProvider('notAListProvider')]
    public function testAContextDeclarationWhichIsNotAListIsIgnored(mixed $declared): void
    {
        $this->withAContextDocumentConfigured(false);

        $atContext = $this->sut()->resolve(
            self::CREDENTIAL_CONFIGURATION_ID,
            [ClaimsEnum::CredentialDefinition->value => [ClaimsEnum::AtContext->value => $declared]],
        );

        $this->assertSame([AtContextsEnum::W3OrgNsCredentialsV2->value], $atContext);
    }


    /**
     * @return array<string,array{mixed}>
     */
    public static function notAListProvider(): array
    {
        return [
            'a single string' => [self::CONTEXT_A],
            'a number' => [42],
        ];
    }
}
