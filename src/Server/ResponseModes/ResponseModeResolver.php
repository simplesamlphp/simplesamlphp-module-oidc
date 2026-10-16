<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\ResponseModes;

use SimpleSAML\OpenID\Codebooks\ResponseModesEnum;

/**
 * The response mode of a `response_mode` value, for a response mode which was kept by its value
 * (ResponseModeInterface::getMode()): in a state SimpleSAMLphp keeps in the session, for one, where a response mode
 * must not go, since the `form_post` one holds the services which render its page.
 */
class ResponseModeResolver
{
    public function __construct(
        private readonly QueryResponseMode $queryResponseMode,
        private readonly FragmentResponseMode $fragmentResponseMode,
        private readonly FormPostResponseMode $formPostResponseMode,
    ) {
    }


    public function forMode(ResponseModesEnum $mode): ResponseModeInterface
    {
        return match ($mode) {
            ResponseModesEnum::Query => $this->queryResponseMode,
            ResponseModesEnum::Fragment => $this->fragmentResponseMode,
            ResponseModesEnum::FormPost => $this->formPostResponseMode,
        };
    }
}
