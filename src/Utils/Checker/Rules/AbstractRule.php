<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\RequestRuleInterface;

abstract class AbstractRule implements RequestRuleInterface
{
    /**
     * @inheritDoc
     */
    public function getKey(): string
    {
        return static::class;
    }

    /**
     * @param string $paramKey
     * @param ServerRequestInterface $request
     * @param LoggerService $loggerService
     * @param string[] $allowedServerRequestMethods
     * @return string|null
     */
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

        /** @var ?string $param */
        $param = null;
        switch ($requestMethod) {
            case 'GET':
                $param = isset($request->getQueryParams()[$paramKey]) ?
                    (string)$request->getQueryParams()[$paramKey] : null;
                break;
            case 'POST':
                if (is_array($parsedBody = $request->getParsedBody())) {
                    $param = isset($parsedBody[$paramKey]) ? (string)$parsedBody[$paramKey] : null;
                }
                break;
            default:
                $loggerService->warning(
                    sprintf(
                        'Request method %s is not supported.',
                        $requestMethod
                    )
                );
        }

        return $param;
    }
}
