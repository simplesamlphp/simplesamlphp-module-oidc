<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use ArgumentCountError;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Factories\IntrospectionReleasePolicyFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\Introspection\IntrospectionReleasePolicyInterface;
use SimpleSAML\Module\oidc\Services\Introspection\PassthroughIntrospectionReleasePolicy;
use SimpleSAML\Module\oidc\Utils\ClassInstanceBuilder;
use stdClass;

#[CoversClass(IntrospectionReleasePolicyFactory::class)]
#[AllowMockObjectsWithoutExpectations]
class IntrospectionReleasePolicyFactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $classInstanceBuilderMock;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->classInstanceBuilderMock = $this->createMock(ClassInstanceBuilder::class);
    }


    protected function sut(): IntrospectionReleasePolicyFactory
    {
        return new IntrospectionReleasePolicyFactory($this->moduleConfigMock, $this->classInstanceBuilderMock);
    }


    public function testBuildsThePassthroughPolicyWhenNoneIsConfigured(): void
    {
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionReleasePolicyClass')->willReturn(null);
        $this->classInstanceBuilderMock->expects($this->never())->method('build');

        $this->assertInstanceOf(PassthroughIntrospectionReleasePolicy::class, $this->sut()->build());
    }


    public function testBuildsTheConfiguredPolicyWithTheConfiguredArguments(): void
    {
        $arguments = ['positional', 'named' => 'value'];
        $policy = $this->createStub(IntrospectionReleasePolicyInterface::class);

        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionReleasePolicyClass')
            ->willReturn(PassthroughIntrospectionReleasePolicy::class);
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionReleasePolicyArguments')
            ->willReturn($arguments);
        $this->classInstanceBuilderMock->expects($this->once())
            ->method('build')
            ->with(PassthroughIntrospectionReleasePolicy::class, $arguments)
            ->willReturn($policy);

        $this->assertSame($policy, $this->sut()->build());
    }


    /**
     * Refused before anything is constructed: a class which is not a policy never has its constructor run.
     */
    #[DataProvider('notAPolicyProvider')]
    public function testRefusesAClassWhichIsNotAReleasePolicy(string $class): void
    {
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionReleasePolicyClass')->willReturn($class);
        $this->classInstanceBuilderMock->expects($this->never())->method('build');

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_RELEASE_POLICY);

        $this->sut()->build();
    }


    public static function notAPolicyProvider(): array
    {
        return [
            'a class which is not a policy' => [stdClass::class],
            'a class which does not exist' => ['No\\Such\\ReleasePolicy'],
            'an empty name' => [''],
            'the interface itself' => [IntrospectionReleasePolicyInterface::class],
        ];
    }


    public function testRefusesAPolicyWhichCanNotBeConstructedWithTheConfiguredArguments(): void
    {
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionReleasePolicyClass')
            ->willReturn(PassthroughIntrospectionReleasePolicy::class);
        $this->classInstanceBuilderMock->method('build')
            ->willThrowException(new ArgumentCountError('Too few arguments'));

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessageMatches(
            '/' . ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_RELEASE_POLICY_ARGUMENTS . ': Too few arguments/',
        );

        $this->sut()->build();
    }


    public function testRefusesWhatIsNotAPolicyOnceConstructed(): void
    {
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionReleasePolicyClass')
            ->willReturn(PassthroughIntrospectionReleasePolicy::class);
        $this->classInstanceBuilderMock->method('build')->willReturn(new stdClass());

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('did not construct a release policy');

        $this->sut()->build();
    }
}
