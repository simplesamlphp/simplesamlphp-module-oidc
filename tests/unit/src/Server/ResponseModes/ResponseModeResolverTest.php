<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\ResponseModes;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Server\ResponseModes\FormPostResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\FragmentResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeResolver;
use SimpleSAML\OpenID\Codebooks\ResponseModesEnum;

/**
 * A response mode kept by its value is found again as the response mode service of that value, and every
 * response mode's value finds that response mode.
 */
#[CoversClass(ResponseModeResolver::class)]
class ResponseModeResolverTest extends TestCase
{
    public function testEveryValueFindsTheResponseModeOfThatValue(): void
    {
        $queryResponseMode = new QueryResponseMode();
        $fragmentResponseMode = new FragmentResponseMode();
        $formPostResponseMode = $this->createStub(FormPostResponseMode::class);
        $formPostResponseMode->method('getMode')->willReturn(ResponseModesEnum::FormPost);
        $sut = new ResponseModeResolver($queryResponseMode, $fragmentResponseMode, $formPostResponseMode);

        $this->assertSame($queryResponseMode, $sut->forMode(ResponseModesEnum::Query));
        $this->assertSame($fragmentResponseMode, $sut->forMode(ResponseModesEnum::Fragment));
        $this->assertSame($formPostResponseMode, $sut->forMode(ResponseModesEnum::FormPost));

        foreach (ResponseModesEnum::cases() as $mode) {
            $this->assertSame($mode, $sut->forMode($mode)->getMode());
        }
    }
}
