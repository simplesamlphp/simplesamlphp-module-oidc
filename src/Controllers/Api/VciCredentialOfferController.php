<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Api;

use SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\Api\Authorization;
use SimpleSAML\OpenID\VerifiableCredentials;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class VciCredentialOfferController
{
    /**
     * @throws OidcServerException
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Authorization $authorization,
        protected readonly VerifiableCredentials $verifiableCredentials,
        protected readonly ClientEntityFactory $clientEntityFactory,
    ) {
        if (!$this->moduleConfig->getApiEnabled()) {
            throw OidcServerException::forbidden('API capabilities not enabled.');
        }
    }

    /**
     * @throws AuthorizationException
     */
    public function credentialOffer(Request $request): Response
    {
        $this->authorization->requireTokenForAnyOfScope(
            $request,
            [ApiScopesEnum::VciCredentialOffer, ApiScopesEnum::VciAll, ApiScopesEnum::All],
        );

        $input = $request->getPayload()->all();

        // Currently, we need a dedicated client for which the PreAuthZed code will be bound to.
        // TODO mivanci: Remove requirement for dedicated client for authorization codes.
        $client = $this->clientEntityFactory->getGenericForVciPreAuthZFlow();

        dd($this->verifiableCredentials->helpers()->arr()->hybridSort($input['user_attributes']));

        return new JsonResponse(['ok']);
    }
}
