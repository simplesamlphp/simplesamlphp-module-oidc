<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

class AuthorizationDetailsRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected readonly ModuleConfig $moduleConfig,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }

    /**
     * @inheritDoc
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?ResultInterface {
        $loggerService->debug('AuthorizationDetailsRule: Running.');

        $authorizationDetailsParam = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::AuthorizationDetails->value,
            $request,
            $allowedServerRequestMethods,
        );

        if ($authorizationDetailsParam === null) {
            $loggerService->debug('AuthorizationDetailsRule: No authorization_details parameter.');
            return null;
        }

        $loggerService->debug(
            'AuthorizationDetailsRule: authorization_details parameter value: ' . $authorizationDetailsParam,
        );

        try {
            $authorizationDetails = json_decode($authorizationDetailsParam, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            $loggerService->error(
                'AuthorizationDetailsRule: Could not JSON decode authorization_details parameter value.',
            );
            return null;
        }

        if (!is_array($authorizationDetails)) {
            $loggerService->error('AuthorizationDetailsRule: authorization_details parameter value is not an array.');
            return null;
        }

        if (empty($authorizationDetails)) {
            $loggerService->error('AuthorizationDetailsRule: authorization_details parameter value is empty.');
            return null;
        }

        // Since we only use AuthorizationDetailsRule for VCI, we will throw as per RAR spec.
        // https://www.rfc-editor.org/rfc/rfc9396.html#name-authorization-error-respons
        if (! $this->moduleConfig->getVerifiableCredentialEnabled()) {
            $loggerService->error('AuthorizationDetailsRule: Rich Authorization Requests are not used by this server.');
            throw OidcServerException::invalidRequest(
                'authorization_details',
                'Rich Authorization Requests are not used by this server.',
            );
        }

        // Check for known authorization_details and their types.
        // Currently, only 'vci' is supported, which defines type as per:
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-using-authorization-details
        foreach ($authorizationDetails as $authorizationDetail) {
            if (!is_array($authorizationDetail)) {
                $loggerService->error(
                    'AuthorizationDetailsRule: authorization_details parameter value is not an array.',
                );
                throw OidcServerException::invalidRequest(
                    'authorization_details',
                    'Malformed authorization_details parameter value.',
                );
            }

            if (!isset($authorizationDetail['type'])) {
                $loggerService->error(
                    'AuthorizationDetailsRule: authorization_details parameter value has no type.',
                );
                throw OidcServerException::invalidRequest(
                    'authorization_details',
                    'Authorization details parameter value has no type.',
                );
            }

            if ($authorizationDetail['type'] !== 'openid_credential') {
                $loggerService->error(
                    'AuthorizationDetailsRule: authorization_details parameter value has unknown type.',
                );
                throw OidcServerException::invalidRequest(
                    'authorization_details',
                    'Authorization details parameter value has unknown type.',
                );
            }

            if (!isset($authorizationDetail['credential_configuration_id'])) {
                $loggerService->error(
                    'AuthorizationDetailsRule: authorization_details parameter value has no' .
                    ' credential_configuration_id.',
                );
                throw OidcServerException::invalidRequest(
                    'authorization_details',
                    'Authorization details parameter value has no credential_configuration_id.',
                );
            }
        }

        $loggerService->debug(
            'AuthorizationDetailsRule: authorization_details decoded.',
            ['authorization_details' => $authorizationDetails,],
        );

        return new Result($this->getKey(), $authorizationDetails);
    }
}
