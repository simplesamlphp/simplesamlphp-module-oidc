<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\RequestRuleInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

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
     * @param string[] $allowedServerRequestMethods
     */
    protected function getAllRequestParamsBasedOnAllowedMethods(
        ServerRequestInterface $request,
        LoggerService $loggerService,
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET->value],
    ): ?array {
        // Make sure the case is compatible...
        $allowedServerRequestMethods = array_map('strtoupper', $allowedServerRequestMethods);
        $requestMethod = strtoupper($request->getMethod());

        if (! in_array($requestMethod, $allowedServerRequestMethods)) {
            $loggerService->warning(
                sprintf(
                    'Method %s not allowed for intended request. Allowed methods were %s.',
                    $requestMethod,
                    implode(', ', $allowedServerRequestMethods),
                ),
            );
            return null;
        }

        switch ($requestMethod) {
            case 'GET':
                return $request->getQueryParams();
            case 'POST':
                if (is_array($parsedBody = $request->getParsedBody())) {
                    return $parsedBody;
                }
                $loggerService->warning(
                    sprintf(
                        'Unexpected HTTP body content for method %s. Got: %s',
                        $requestMethod,
                        var_export($parsedBody, true),
                    ),
                );
                return null;
            default:
                $loggerService->warning(sprintf('Request method %s is not supported.', $requestMethod));
                return null;
        }
    }

    /**
     * @param string[] $allowedServerRequestMethods
     */
    protected function getRequestParamBasedOnAllowedMethods(
        string $paramKey,
        ServerRequestInterface $request,
        LoggerService $loggerService,
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET->value],
    ): ?string {
        $requestParams = $this->getAllRequestParamsBasedOnAllowedMethods(
            $request,
            $loggerService,
            $allowedServerRequestMethods,
        );

        if (is_null($requestParams)) {
            return null;
        }

        return isset($requestParams[$paramKey]) ? (string)$requestParams[$paramKey] : null;
    }
}
