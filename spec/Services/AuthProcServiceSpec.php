<?php

namespace spec\SimpleSAML\Module\oidc\Services;

use PhpSpec\ObjectBehavior;
use SimpleSAML\Module\oidc\Services\AuthProcService;
use SimpleSAML\Module\oidc\Services\ConfigurationService;

class AuthProcServiceSpec extends ObjectBehavior
{
    public function let(
        ConfigurationService $configurationService
    ): void {
        $configurationService->getAuthProcFilters()->willReturn([]);
        $this->beConstructedWith($configurationService);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(AuthProcService::class);
    }

    public function it_loads_configured_filters(
        ConfigurationService $configurationService
    ): void {
        $configurationService->getAuthProcFilters()->willReturn(['\SimpleSAML\Module\core\Auth\Process\AttributeAdd',]);
        $this->getLoadedFilters()->shouldBeArray();
        $this->getLoadedFilters()->shouldHaveCount(1);
    }

    public function it_executes_configured_filters(
        ConfigurationService $configurationService
    ): void {
        $sampleFilters = [
            50 => [
                'class' => '\SimpleSAML\Module\core\Auth\Process\AttributeAdd',
                'newKey' => ['newValue']
            ],
        ];

        $configurationService->getAuthProcFilters()->willReturn($sampleFilters);

        $state = ['Attributes' => ['existingKey' => ['existingValue']]];

        $this->processState($state)->shouldHaveKeyWithValueCustom('newKey', 'newValue');
        $this->processState($state)->shouldHaveKeyWithValueCustom('existingKey', 'existingValue');
    }

    public function getMatchers(): array
    {
        return [
            'haveKeyWithValueCustom' => function ($subject, $key, $value) {
                $attributes = $subject['Attributes'];
                return array_key_exists($key, $attributes) &&
                    ($value === $attributes[$key][0]);
            },
        ];
    }
}
