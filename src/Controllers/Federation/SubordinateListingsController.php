<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Federation;

use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\ErrorsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class SubordinateListingsController
{
    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly ClientRepository $clientRepository,
        private readonly Helpers $helpers,
        private readonly Routes $routes,
        private readonly LoggerService $loggerService,
    ) {
        if (!$this->moduleConfig->getFederationEnabled()) {
            throw OidcServerException::forbidden('federation capabilities not enabled');
        }
    }

    public function list(Request $request): Response
    {
        // If unsupported query parameter is provided, we have to respond with an error: "If the responder does not
        // support this feature, it MUST use the HTTP status code 400 and the content type application/json, with
        // the error code unsupported_parameter."

        // Currently, we don't support any of the mentioned params in the spec, so let's return error for any of them.
        $unsupportedParams = [
            ParamsEnum::EntityType->value,
            ParamsEnum::TrustMarked->value,
            ParamsEnum::TrustMarkId->value,
            ParamsEnum::Intermediate->value,
        ];

        $requestedParams = array_keys($request->query->all());

        if (!empty($intersectedParams = array_intersect($unsupportedParams, $requestedParams))) {
            return $this->routes->newJsonErrorResponse(
                ErrorsEnum::UnsupportedParameter->value,
                'Unsupported parameter: ' . implode(', ', $intersectedParams),
            );
        }

        dd($request->query->all());


        if ($entityTypes = $request->query->all(ParamsEnum::EntityType->value)) {
        }

        return new Response();
    }
}
