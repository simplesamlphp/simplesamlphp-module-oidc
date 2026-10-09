<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use JsonException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

/**
 * The authorization_details parameter of RFC 9396, which OpenID4VCI 1.0 section 5.1.1 uses to ask for credentials:
 * details of type openid_credential, each naming a credential configuration of this issuer, and optionally
 * describing the claims wanted in it (Appendix B.1).
 *
 * It runs at the authorization and pushed authorization request endpoints, and at the token endpoint for the
 * pre-authorized code grant. A value it can not accept refuses the request with invalid_authorization_details (RFC
 * 9396 section 5). At the authorization endpoint that refusal goes to the redirect URI, with the state, as
 * ScopeRule's does: the client and its redirect URI are established by then, and so is an offer's issuer_state,
 * IssuerStateRule running first. The pushed authorization request endpoint answers it directly, and the token
 * endpoint has no redirect URI to send it to.
 *
 * A server which does not issue credentials knows no type of authorization details, so it refuses a well-formed
 * value; one which is not a non-empty array of details it ignores, as it would any other parameter it does not use
 * (RFC 6749 section 3.1). A server which issues credentials refuses it.
 *
 * The claims descriptions of a detail are checked (Appendix B.1, B.3 and C) but not honoured: the credential holds
 * the claims of its configuration whatever was asked, and the token response leaves claims out of the details it
 * returns (TokenResponse), so they are not taken for a selection granted.
 *
 * @extends \SimpleSAML\Module\oidc\Server\RequestRules\Rules\AbstractRule<array>
 */
class AuthorizationDetailsRule extends AbstractRule
{
    /**
     * The one authorization details type this server knows (OpenID4VCI 1.0 section 5.1.1).
     */
    final public const string TYPE_OPENID_CREDENTIAL = 'openid_credential';


    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected readonly ModuleConfig $moduleConfig,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }


    /**
     * @inheritDoc
     *
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface $responseMode
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedServerRequestMethods
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode = new QueryResponseMode(),
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?Result {
        $loggerService->debug('AuthorizationDetailsRule::checkRule.');

        $parameters = $this->requestParamsResolver->getAllBasedOnAllowedMethods(
            $request,
            $allowedServerRequestMethods,
        );

        // Read by key: a Request Object claim written as null is a value which is not an array of details, not an
        // absent parameter.
        if (! array_key_exists(ParamsEnum::AuthorizationDetails->value, $parameters)) {
            $loggerService->debug('AuthorizationDetailsRule: No authorization_details parameter.');
            return null;
        }

        /** @psalm-suppress MixedAssignment */
        $authorizationDetailsParam = $parameters[ParamsEnum::AuthorizationDetails->value];

        // The encoding depends on where the parameter travels (RFC 9396 section 3). As a query or form
        // parameter it is the serialized JSON. In a Request Object, and so in a pushed request which used one,
        // it is a claim holding the decoded JSON array itself. Once the parameters are merged, where a value came
        // from is not known, so either form is taken from either place. A JSON object whose members are named 0,
        // 1, ... decodes to the same array as a JSON array does, and is read as one.
        /** @psalm-suppress MixedAssignment */
        $authorizationDetails = $authorizationDetailsParam;
        if (is_string($authorizationDetailsParam)) {
            try {
                /** @psalm-suppress MixedAssignment */
                $authorizationDetails = json_decode($authorizationDetailsParam, true, 512, JSON_THROW_ON_ERROR);
            } catch (JsonException) {
                $authorizationDetails = null;
            }
        }

        if (! $this->moduleConfig->getVciEnabled()) {
            if (! $this->isNonEmptyJsonArray($authorizationDetails)) {
                $loggerService->debug(
                    'AuthorizationDetailsRule: authorization_details ignored: it is not an array of details, and ' .
                    'Rich Authorization Requests are not used by this server.',
                );
                return null;
            }

            throw $this->refusal(
                'Rich Authorization Requests are not used by this server.',
                $currentResultBag,
                $responseMode,
                $loggerService,
            );
        }

        if (! $this->isNonEmptyJsonArray($authorizationDetails)) {
            throw $this->refusal(
                'The authorization_details parameter is not a non-empty JSON array of authorization details.',
                $currentResultBag,
                $responseMode,
                $loggerService,
            );
        }

        $credentialConfigurationIds = $this->moduleConfig->getVciCredentialConfigurationIdsSupported();

        /** @psalm-suppress MixedAssignment */
        foreach ($authorizationDetails as $authorizationDetail) {
            $reason = $this->findFaultInAuthorizationDetail($authorizationDetail, $credentialConfigurationIds);

            if ($reason !== null) {
                throw $this->refusal($reason, $currentResultBag, $responseMode, $loggerService);
            }
        }

        $loggerService->debug(
            'AuthorizationDetailsRule: authorization_details decoded.',
            ['authorization_details' => $authorizationDetails,],
        );

        return new Result($this->getKey(), $authorizationDetails);
    }


    /**
     * Why an authorization detail can not be accepted, or null when it can. Members this server does not use are
     * allowed (OpenID4VCI 1.0 section 5.1.1: an openid_credential detail is never invalid for an unknown member).
     *
     * @param string[] $credentialConfigurationIds
     */
    protected function findFaultInAuthorizationDetail(
        mixed $authorizationDetail,
        array $credentialConfigurationIds,
    ): ?string {
        if (! $this->isJsonObject($authorizationDetail)) {
            return 'An authorization detail is not a JSON object.';
        }

        if (! isset($authorizationDetail[ClaimsEnum::Type->value])) {
            return 'An authorization detail has no type.';
        }

        if ($authorizationDetail[ClaimsEnum::Type->value] !== self::TYPE_OPENID_CREDENTIAL) {
            return 'An authorization detail is of a type this server does not support; the one it supports is ' .
            self::TYPE_OPENID_CREDENTIAL . '.';
        }

        if (! isset($authorizationDetail[ClaimsEnum::CredentialConfigurationId->value])) {
            return 'An authorization detail has no credential_configuration_id.';
        }

        /** @psalm-suppress MixedAssignment */
        $credentialConfigurationId = $authorizationDetail[ClaimsEnum::CredentialConfigurationId->value];

        if (! is_string($credentialConfigurationId) || $credentialConfigurationId === '') {
            return 'The credential_configuration_id of an authorization detail is not a non-empty string.';
        }

        // Not named back: the value is the client's, and only an identifier this issuer publishes is safe to echo.
        if (! in_array($credentialConfigurationId, $credentialConfigurationIds, true)) {
            return 'An authorization detail names a credential configuration this issuer does not support.';
        }

        if (array_key_exists(ClaimsEnum::Claims->value, $authorizationDetail)) {
            return $this->findFaultInClaimsDescriptions($authorizationDetail[ClaimsEnum::Claims->value]);
        }

        return null;
    }


    /**
     * Why the claims of an authorization detail can not be accepted, or null when they can: a non-empty array of
     * claims description objects (OpenID4VCI 1.0 Appendix B.1), each with a path which is a claims path pointer
     * (Appendix C) and, if it has one, a boolean mandatory; none repeating or contradicting another (Appendix
     * B.3).
     *
     * The pointers are laid out in a tree, one node per path prefix, which tells a repeated or contradictory
     * description in one pass over the paths, however many there are. A node addressed by two pointers is a claim
     * described twice. A node continued by two kinds of component is read two ways: by null (every element of an
     * array) and by an index (one element), or by a member name (an object) and by null or an index (an array).
     */
    protected function findFaultInClaimsDescriptions(mixed $claimsDescriptions): ?string
    {
        if (! $this->isNonEmptyJsonArray($claimsDescriptions)) {
            return 'The claims of an authorization detail are not a non-empty array of claims descriptions.';
        }

        // Edges keyed by parent node, kind and value; the root is node 0. A node is continued by one kind of
        // component, or the descriptions contradict each other.
        $childNodes = [];
        $continuationKindOf = [];
        $addressedNodes = [];
        $nextNode = 1;

        /** @psalm-suppress MixedAssignment */
        foreach ($claimsDescriptions as $claimsDescription) {
            if (! $this->isJsonObject($claimsDescription)) {
                return 'A claims description of an authorization detail is not a JSON object.';
            }

            /** @psalm-suppress MixedAssignment */
            $path = $claimsDescription[ClaimsEnum::Path->value] ?? null;

            if (! $this->isClaimsPathPointer($path)) {
                return 'A claims description of an authorization detail has no path which is a claims path ' .
                'pointer: a non-empty array of strings, nulls and non-negative integers.';
            }

            if (
                array_key_exists(ClaimsEnum::Mandatory->value, $claimsDescription) &&
                ! is_bool($claimsDescription[ClaimsEnum::Mandatory->value])
            ) {
                return 'The mandatory member of a claims description of an authorization detail is not a boolean.';
            }

            $node = 0;
            foreach ($path as $component) {
                $kind = match (true) {
                    is_string($component) => 'member',
                    $component === null => 'all',
                    default => 'index',
                };

                $continuationKindOf[$node] ??= $kind;
                if ($continuationKindOf[$node] !== $kind) {
                    return 'Two claims descriptions of an authorization detail contradict each other: one ' .
                    'addresses an object member where another addresses an array, or all elements of an ' .
                    'array where another addresses one of them.';
                }

                $edge = $node . "\x00" . $kind . "\x00" . (string)$component;
                $node = $childNodes[$edge] ??= $nextNode++;
            }

            if (isset($addressedNodes[$node])) {
                return 'Two claims descriptions of an authorization detail address the same claim.';
            }
            $addressedNodes[$node] = true;
        }

        return null;
    }


    /**
     * A claims path pointer into a JSON-based credential, the only kind this issuer issues (OpenID4VCI 1.0
     * Appendix C.1): a non-empty array of strings (a member), nulls (every element of an array) and non-negative
     * integers (one element).
     *
     * @psalm-assert-if-true non-empty-list<string|int|null> $path
     */
    protected function isClaimsPathPointer(mixed $path): bool
    {
        if (! $this->isNonEmptyJsonArray($path)) {
            return false;
        }

        /** @psalm-suppress MixedAssignment */
        foreach ($path as $component) {
            if (! (is_string($component) || $component === null || (is_int($component) && $component >= 0))) {
                return false;
            }
        }

        return true;
    }


    /**
     * A JSON object as it decodes to a PHP array: one with named members. An empty object decodes to an empty array,
     * and is taken as one too; it has none of the members a detail or a claims description requires.
     *
     * @psalm-assert-if-true mixed[] $value
     */
    protected function isJsonObject(mixed $value): bool
    {
        return is_array($value) && ($value === [] || ! array_is_list($value));
    }


    /**
     * A JSON array with at least one element, as it decodes to a PHP array.
     *
     * @psalm-assert-if-true non-empty-list<mixed> $value
     */
    protected function isNonEmptyJsonArray(mixed $value): bool
    {
        return is_array($value) && $value !== [] && array_is_list($value);
    }


    /**
     * The refusal of the request, sent to the redirect URI when one is established (the authorization endpoint),
     * and answered directly otherwise.
     */
    protected function refusal(
        string $reason,
        ResultBagInterface $currentResultBag,
        ResponseModeInterface $responseMode,
        LoggerService $loggerService,
    ): OidcServerException {
        $loggerService->notice(
            'Request rejected: its authorization_details can not be accepted.',
            ['reason' => $reason],
        );

        /** @psalm-suppress MixedAssignment */
        $redirectUri = $currentResultBag->get(ClientRedirectUriRule::class)?->getValue();
        /** @psalm-suppress MixedAssignment */
        $state = $currentResultBag->get(StateRule::class)?->getValue();

        return OidcServerException::invalidAuthorizationDetails(
            $reason,
            is_string($redirectUri) ? $redirectUri : null,
            is_string($state) ? $state : null,
            $responseMode,
        );
    }
}
