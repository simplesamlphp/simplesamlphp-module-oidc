<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionProperty;
use SimpleSAML\Auth\State;
use SimpleSAML\Error\UserAborted;
use SimpleSAML\Module\oidc\Services\StateService;

/**
 * @covers \SimpleSAML\Module\oidc\Services\StateService
 */
#[AllowMockObjectsWithoutExpectations]
class StateServiceTest extends TestCase
{
    /**
     * @return \SimpleSAML\Module\oidc\Services\StateService
     */
    protected function mock(): StateService
    {
        return new StateService();
    }


    /**
     * @return void
     */
    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            StateService::class,
            $this->mock(),
        );
    }


    /**
     * The exception state is loaded through SimpleSAMLphp's State, at its exception stage.
     */
    public function testItLoadsTheExceptionStateThroughTheAuthState(): void
    {
        $exceptionState = [State::EXCEPTION_DATA => new UserAborted()];
        $authState = new class extends State {
            public static array $loaded = [];

            public static ?array $state = null;


            public static function loadExceptionState(?string $id = null): ?array
            {
                self::$loaded[] = $id;

                return self::$state;
            }
        };
        $authState::$state = $exceptionState;
        // The State is the service's own, so it is put in before anything else initializes the readonly property.
        $stateService = (new ReflectionClass(StateService::class))->newInstanceWithoutConstructor();
        (new ReflectionProperty(StateService::class, 'authState'))->setValue($stateService, $authState);

        $this->assertSame($exceptionState, $stateService->loadExceptionState('exception-state-id'));
        $this->assertSame(['exception-state-id'], $authState::$loaded);
    }
}
