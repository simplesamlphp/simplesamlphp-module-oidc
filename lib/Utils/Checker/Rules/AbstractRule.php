<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
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
        LoggerService $loggerService,
        array $allowedServerRequestMethods = ['GET']
    ): ?string {
        // Make sure the case is compatible...
        $allowedServerRequestMethods = array_map('strtoupper', $allowedServerRequestMethods);
        $requestMethod = strtoupper($request->getMethod());

        if (! in_array($requestMethod, $allowedServerRequestMethods)) {
            $loggerService->warning(
                sprintf(
                    'Method %s not allowed for intended request. Allowed methods were %s.',
                    $requestMethod,
                    implode(', ', $allowedServerRequestMethods)
                )
            );
            return null;
        }

        switch ($requestMethod) {
            case 'GET':
                return $request->getQueryParams()[$paramKey] ?? null;
            case 'POST':
                if (is_array($parsedBody = $request->getParsedBody())) {
                    return $parsedBody[$paramKey] ?? null;
                }
                // break; // ... falls through to default
            default:
                $loggerService->warning(
                    sprintf(
                        'Request method %s is not supported.',
                        $requestMethod
                    )
                );
        }

        return null;
    }
}
