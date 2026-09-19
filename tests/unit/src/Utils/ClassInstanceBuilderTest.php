<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use DateInterval;
use DateMalformedIntervalStringException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListAllocationTarget;
use SimpleSAML\Module\oidc\Utils\ClassInstanceBuilder;
use stdClass;

/**
 * Builds an instance of a class named at runtime, which is how `CacheFactory` builds the configured cache
 * adapter from its class name and constructor arguments.
 *
 * The one thing of its own it does is refuse a name which is not a class, with the module's exception;
 * what the constructor it then calls does with the arguments is that constructor's business, and its
 * failures come out as they are.
 */
#[CoversClass(ClassInstanceBuilder::class)]
class ClassInstanceBuilderTest extends TestCase
{
    protected function sut(): ClassInstanceBuilder
    {
        return new ClassInstanceBuilder();
    }


    /**
     * A class whose first two constructor arguments are both strings, so an order the builder did not
     * keep would show in the getters rather than in a type error.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \ReflectionException
     */
    public function testBuildsTheNamedClassWithTheArgumentsInOrder(): void
    {
        $instance = $this->sut()->build(
            StatusListAllocationTarget::class,
            ['employee-badges', 'a1b2c3d4e5f6', StatusListExpiryLaneEnum::NonExpiring],
        );

        $this->assertInstanceOf(StatusListAllocationTarget::class, $instance);
        $this->assertSame('employee-badges', $instance->getPoolId());
        $this->assertSame('a1b2c3d4e5f6', $instance->getPolicyFingerprint());
        $this->assertSame(StatusListExpiryLaneEnum::NonExpiring, $instance->getExpiryLane());
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \ReflectionException
     */
    public function testBuildsAClassWithoutAConstructorFromNoArguments(): void
    {
        $this->assertInstanceOf(stdClass::class, $this->sut()->build(stdClass::class, []));
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \ReflectionException
     */
    public function testRefusesANameWhichIsNotAClass(): void
    {
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('Error building instance: class Nope\Such\Adapter does not exist');

        $this->sut()->build('Nope\Such\Adapter', []);
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \ReflectionException
     */
    public function testLetsTheConstructorsOwnRefusalThrough(): void
    {
        $this->expectException(DateMalformedIntervalStringException::class);

        $this->sut()->build(DateInterval::class, ['seven minutes']);
    }
}
