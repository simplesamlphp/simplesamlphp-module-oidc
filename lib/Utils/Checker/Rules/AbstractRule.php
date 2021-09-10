<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\RequestRuleInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;

abstract class AbstractRule implements RequestRuleInterface
{
    /**
     * @inheritDoc
     */
    public function getKey(): string
    {
        return static::class;
    }

    protected function getParamFromRequestBasedOnAllowedMethods(
        string $paramKey,
        ServerRequestInterface $request,
        array $allowedServerRequestMethods = ['GET']
    ): ?string {
        // Make sure the case is compatible...
        $allowedServerRequestMethods = array_map('strtoupper', $allowedServerRequestMethods);
        $requestMethod = strtoupper($request->getMethod());

        if (! in_array($requestMethod, $allowedServerRequestMethods)) {
            // TODO Log method not allowed
            return null;
        }

        switch ($requestMethod) {
            case 'GET':
                return $request->getQueryParams()[$paramKey] ?? null;
            case 'POST':
                if (is_array($parsedBody = $request->getParsedBody())) {
                    return $parsedBody[$paramKey] ?? null;
                }
                break;
            default:
                // TODO Log method not supported
        }

        return null;
    }
}
