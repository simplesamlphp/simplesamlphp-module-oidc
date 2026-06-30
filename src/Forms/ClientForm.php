<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Forms;

use Nette\Forms\Form;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Forms\Controls\CsrfProtection;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ResponseTypeGrantTypeCorrespondence;
use SimpleSAML\OpenID\Codebooks\ApplicationTypesEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\ClientRegistrationTypesEnum;
use SimpleSAML\OpenID\Codebooks\TokenEndpointAuthMethodsEnum;
use Traversable;

/**
 * @psalm-suppress PropertyNotSetInConstructor Raised for $httpRequest which is marked as internal, so won't handle.
 */
class ClientForm extends Form
{
    protected const string TYPE_ARRAY = 'array';

    /**
     * RFC3986. AppendixB. Parsing a URI Reference with a Regular Expression.
     * From v6.*, the regex was modified to allow URI without host, to support adding entries like
     * `openid-credential-offer://`
     */
    final public const string REGEX_URI = '/^[^:]+:\/\/?([^\s\/$.?#].[^\s]*)?$/';

    /**
     * Must have http:// or https:// scheme, and at least one 'domain.top-level-domain' pair, or more subdomains.
     * Top-level-domain may end with '.'.
     * No reserved chars allowed, meaning no userinfo, path, query or fragment components. May end with port number.
     */
    final public const string REGEX_ALLOWED_ORIGIN_URL =
    "/^http(s?):\/\/([^\s\/!$&'()+,;=.?#@*:]+\.)"
    . "?[^\s\/!$&'()+,;=.?#@*:]+(\.[^\s\/!$&'()+,;=.?#@*:]+)*\.?(:\d{1,5})?$/i";

    /**
     * URI which must contain https or http scheme, can contain path and query, and can't contain fragment.
     */
    final public const string REGEX_HTTP_URI = '/^http(s?):\/\/[^\s\/$.?#][^\s#]*$/i';

    /**
     * URI with https or http scheme and host / domain. It can contain path, but no query, or fragment component.
     */
    final public const string REGEX_HTTP_URI_PATH = '/^http(s?):\/\/[^\s\/$.?#][^\s?#]*$/i';


    /**
     * @throws \Exception
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected CsrfProtection $csrfProtection,
        protected SspBridge $sspBridge,
        protected Helpers $helpers,
    ) {
        parent::__construct();

        $this->buildForm();
    }

    public function validateRedirectUri(Form $form): void
    {
        $values = $form->getValues(self::TYPE_ARRAY);
        /** @var string[] $redirectUris */
        $redirectUris = $values['redirect_uri'] ?? [];
        $this->validateByMatchingRegex(
            $redirectUris,
            self::REGEX_URI,
            'Invalid URI: ',
        );
    }

    public function validateAllowedOrigin(Form $form): void
    {
        $values = $form->getValues(self::TYPE_ARRAY);
        /** @var string[] $allowedOrigins */
        $allowedOrigins = $values['allowed_origin'] ?? [];
        $this->validateByMatchingRegex(
            $allowedOrigins,
            self::REGEX_ALLOWED_ORIGIN_URL,
            'Invalid allowed origin: ',
        );
    }

    public function validatePostLogoutRedirectUri(Form $form): void
    {
        $values = $form->getValues(self::TYPE_ARRAY);
        /** @var string[] $postLogoutRedirectUris */
        $postLogoutRedirectUris = $values['post_logout_redirect_uri'] ?? [];
        $this->validateByMatchingRegex(
            $postLogoutRedirectUris,
            self::REGEX_URI,
            'Invalid post-logout redirect URI: ',
        );
    }

    public function validateBackChannelLogoutUri(Form $form): void
    {
        /** @var ?string $bclUri */
        $bclUri = $form->getValues()['backchannel_logout_uri'] ?? null;
        if ($bclUri !== null) {
            $this->validateByMatchingRegex(
                [$bclUri],
                self::REGEX_HTTP_URI,
                'Invalid back-channel logout URI: ',
            );
        }
    }

    public function validateEntityIdentifier(Form $form): void
    {
        /** @var ?string $entityIdentifier */
        $entityIdentifier = $form->getValues()['entity_identifier'] ?? null;
        if ($entityIdentifier !== null) {
            $this->validateByMatchingRegex(
                [$entityIdentifier],
                self::REGEX_HTTP_URI_PATH,
                'Invalid Entity Identifier URI: ',
            );
        }
    }

    public function validateClientRegistrationTypes(Form $form): void
    {
        /** @var ?string[] $clientRegistrationTypes */
        $clientRegistrationTypes = $form->getValues()['client_registration_types'] ?? null;
        if ($clientRegistrationTypes !== null) {
            foreach ($clientRegistrationTypes as $clientRegistrationType) {
                if (is_null(ClientRegistrationTypesEnum::tryFrom($clientRegistrationType))) {
                    $this->addError("Invalid value: $clientRegistrationType");
                }
            }
        }
    }

    public function validateFederationJwks(Form $form): void
    {
        $this->validateJwks($form->getValues()['federation_jwks'] ?? null);
    }

    public function validateProtocolJwks(Form $form): void
    {
        $this->validateJwks($form->getValues()['jwks'] ?? null);
    }

    public function validateJwksUri(Form $form): void
    {
        /** @var string[] $uris */
        $uris = array_filter(
            [
                $form->getValues()['jwks_uri'] ?? null,
                $form->getValues()['signed_jwks_uri'] ?? null,
            ],
        );
        if (!empty($uris)) {
            $this->validateByMatchingRegex(
                $uris,
                self::REGEX_HTTP_URI,
                'Invalid JWKS URI: ',
            );
        }
    }


    public function validateRequestUris(Form $form): void
    {
        $values = $form->getValues(self::TYPE_ARRAY);

        $requestUris = $values[ClaimsEnum::RequestUris->value] ?? null;

        if (!is_array($requestUris)) {
            $this->addError(
                'Unexpected Request URIs format (expected array): ' . var_export($requestUris, true),
            );
            return;
        }

        /** @psalm-suppress MixedAssignment */
        foreach ($requestUris as $uri) {
            if (!is_string($uri)) {
                $this->addError('Request URI must be a string: ' . var_export($uri, true));
            } elseif (!str_starts_with(strtolower($uri), 'https://')) {
                $this->addError('Request URI must be an HTTPS URL: ' . $uri);
            }
        }
    }

    /**
     * Validate the per-client Authentication Processing Filters. The value is
     * expected to be a JSON object/array in the same shape as the global
     * ModuleConfig::OPTION_AUTH_PROCESSING_FILTERS option, i.e. a list keyed by
     * priority where each filter is either a class string or an array with a
     * 'class' key. JSON syntax itself is validated in getValues().
     *
     * @throws \Exception
     */
    public function validateAuthProcFilters(Form $form): void
    {
        $values = $form->getValues(self::TYPE_ARRAY);

        $authProcFilters = $values[ClientEntity::KEY_AUTH_PROC_FILTERS] ?? [];

        if (!is_array($authProcFilters)) {
            $this->addError('Authentication Processing Filters must be a JSON object.');
            return;
        }

        /**
         * @var mixed $filter
         */
        foreach ($authProcFilters as $filter) {
            if (is_string($filter)) {
                continue;
            }

            if (!is_array($filter)) {
                $this->addError(
                    'Each Authentication Processing Filter must be a class string or an object: ' .
                    var_export($filter, true),
                );
                continue;
            }

            if (!isset($filter['class']) || !is_string($filter['class'])) {
                $this->addError(
                    "Each Authentication Processing Filter object must have a string 'class' property: " .
                    var_export($filter, true),
                );
            }
        }
    }

    /**
     * Cast integer-like string array keys to int, leaving all other keys (and
     * the values) untouched. Only the top level is processed, which is where
     * authproc filter priority keys live. Used to normalize priorities coming
     * from the JSON-encoded authproc filters field.
     */
    protected function castNumericKeysToInt(array $array): array
    {
        $result = [];
        /** @var mixed $value */
        foreach ($array as $key => $value) {
            if (is_string($key) && preg_match('/^-?\d+$/', $key) === 1) {
                $key = (int) $key;
            }
            /** @psalm-suppress MixedAssignment */
            $result[$key] = $value;
        }

        return $result;
    }

    public function validateJwks(mixed $jwks): void
    {
        if (is_null($jwks)) {
            return;
        }

        if (!is_array($jwks)) {
            $this->addError(sprintf("Invalid JWKS format: %s", var_export($jwks, true)));
            return;
        }

        if (!array_key_exists('keys', $jwks)) {
            $this->addError(sprintf("No keys property in JWKS: %s", var_export($jwks, true)));
            return;
        }

        if (empty($jwks['keys'])) {
            $this->addError(sprintf("Empty keys in JWKS: %s", var_export($jwks, true)));
        }
    }

    /**
     * @param string[] $values
     * @param non-empty-string $regex
     */
    protected function validateByMatchingRegex(
        array $values,
        string $regex,
        string $messagePrefix = 'Invalid value: ',
    ): void {
        foreach ($values as $value) {
            if (!preg_match($regex, $value)) {
                $this->addError($messagePrefix . $value);
            }
        }
    }

    public function getValues(string|object|bool|null $returnType = null, ?array $controls = null): array
    {
        /** @psalm-suppress RedundantCast */
        $values = (array)parent::getValues(self::TYPE_ARRAY);

        // Derive the client type (confidential/public) using the same precedence as DCR registration
        // (see ClientEntityFactory::determineIsConfidential() + the token_endpoint_auth_method lockstep):
        //   1. token_endpoint_auth_method, if selected: `none` => public, any real method => confidential;
        //   2. else application_type `native` => public (a native app is a strong public-client indication);
        //   3. else the explicit confidential/public choice stands.
        // The server is the authority here; client-form.js mirrors this live in the UI.
        /** @var mixed $selectedAuthMethod */
        $selectedAuthMethod = $values[ClaimsEnum::TokenEndpointAuthMethod->value] ?? null;
        /** @var mixed $selectedApplicationType */
        $selectedApplicationType = $values[ClaimsEnum::ApplicationType->value] ?? null;
        if (is_string($selectedAuthMethod) && trim($selectedAuthMethod) !== '') {
            $values['is_confidential'] = trim($selectedAuthMethod) !== TokenEndpointAuthMethodsEnum::None->value;
        } elseif ($selectedApplicationType === ApplicationTypesEnum::Native->value) {
            $values['is_confidential'] = false;
        }

        // Sanitize redirect_uri and allowed_origin
        $values['redirect_uri'] = $this->helpers->str()->convertTextToArray((string)$values['redirect_uri']);
        if (! $values['is_confidential'] && isset($values['allowed_origin'])) {
            $values['allowed_origin'] = $this->helpers->str()->convertTextToArray((string)$values['allowed_origin']);
        } else {
            $values['allowed_origin'] = [];
        }
        $values['post_logout_redirect_uri'] =
        $this->helpers->str()->convertTextToArray((string)$values['post_logout_redirect_uri']);

        $bclUri = trim((string)$values['backchannel_logout_uri']);
        $values['backchannel_logout_uri'] = empty($bclUri) ? null : $bclUri;

        $scopes = is_array($values['scopes']) ? $values['scopes'] : [];

        // openid scope is mandatory
        $values['scopes'] = array_unique(
            array_merge(
                $scopes,
                ['openid'],
            ),
        );

        $entityIdentifier = trim((string)$values['entity_identifier']);
        $values['entity_identifier'] = empty($entityIdentifier) ? null : $entityIdentifier;

        $values['client_registration_types'] = is_array($values['client_registration_types']) ?
        array_intersect($values['client_registration_types'], $this->getClientRegistrationTypes()) :
        [ClientRegistrationTypesEnum::Automatic->value];

        $federationJwks = trim((string)$values['federation_jwks']);
        try {
            /** @psalm-suppress MixedAssignment */
            $values['federation_jwks'] = empty($federationJwks) ?
            null :
            json_decode($federationJwks, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            $this->addError('Federation JSON error: ' . $e->getMessage());
            $values['federation_jwks'] = null;
        }

        $jwks = trim((string)$values['jwks']);
        try {
            /** @psalm-suppress MixedAssignment */
            $values['jwks'] = empty($jwks) ?
            null :
            json_decode($jwks, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            $this->addError('JWKS JSON error: ' . $e->getMessage());
            $values['jwks'] = null;
        }

        $jwksUri = trim((string)$values['jwks_uri']);
        $values['jwks_uri'] = empty($jwksUri) ? null : $jwksUri;

        $signedJwksUri = trim((string)$values['signed_jwks_uri']);
        $values['signed_jwks_uri'] = empty($signedJwksUri) ? null : $signedJwksUri;

        /** @var mixed $requestUrisValue */
        $requestUrisValue = $values[ClaimsEnum::RequestUris->value] ?? '';
        $values[ClaimsEnum::RequestUris->value] = $this->helpers->str()->convertTextToArray(
            is_string($requestUrisValue) ? $requestUrisValue : '',
        );

        $idTokenSignedResponseAlg = trim((string)$values[ClaimsEnum::IdTokenSignedResponseAlg->value]);
        $values[ClaimsEnum::IdTokenSignedResponseAlg->value] = empty($idTokenSignedResponseAlg) ?
        null : $idTokenSignedResponseAlg;

        $responseModesAllowed = is_array($values[ClientEntity::KEY_ALLOWED_RESPONSE_MODES]) ?
        $values[ClientEntity::KEY_ALLOWED_RESPONSE_MODES] : [];
        $values[ClientEntity::KEY_ALLOWED_RESPONSE_MODES] = array_intersect(
            $responseModesAllowed,
            array_keys($this->getAllowedResponseModesValues()),
        );

        /** @var mixed $grantTypes */
        $grantTypes = $values[ClaimsEnum::GrantTypes->value] ?? null;
        $grantTypes = is_array($grantTypes) ? $grantTypes : [];
        $values[ClaimsEnum::GrantTypes->value] = array_values(
            array_intersect($grantTypes, array_keys($this->getSupportedGrantTypes())),
        );

        /** @var mixed $responseTypes */
        $responseTypes = $values[ClaimsEnum::ResponseTypes->value] ?? null;
        $responseTypes = is_array($responseTypes) ? $responseTypes : [];
        $values[ClaimsEnum::ResponseTypes->value] = array_values(
            array_intersect($responseTypes, array_keys($this->getSupportedResponseTypes())),
        );

        // Enforce the OIDC DCR response_type <-> grant_type correspondence server-side (the JS does the same live):
        // every grant type required by a selected response_type must be present in grant_types. We keep only
        // supported grant types so the multi-select can render the result.
        /** @var string[] $selectedGrantTypes */
        $selectedGrantTypes = $values[ClaimsEnum::GrantTypes->value];
        /** @var string[] $selectedResponseTypes */
        $selectedResponseTypes = $values[ClaimsEnum::ResponseTypes->value];

        $normalizedGrantTypes = ResponseTypeGrantTypeCorrespondence::mergeRequiredGrantTypes(
            $selectedGrantTypes,
            $selectedResponseTypes,
        );
        $values[ClaimsEnum::GrantTypes->value] = array_values(
            array_intersect($normalizedGrantTypes, array_keys($this->getSupportedGrantTypes())),
        );

        /** @var mixed $tokenEndpointAuthMethod */
        $tokenEndpointAuthMethod = $values[ClaimsEnum::TokenEndpointAuthMethod->value] ?? '';
        $tokenEndpointAuthMethod = is_string($tokenEndpointAuthMethod) ? trim($tokenEndpointAuthMethod) : '';
        $values[ClaimsEnum::TokenEndpointAuthMethod->value] = $tokenEndpointAuthMethod === '' ?
        null : $tokenEndpointAuthMethod;

        /** @var mixed $defaultMaxAgeRaw */
        $defaultMaxAgeRaw = $values[ClaimsEnum::DefaultMaxAge->value] ?? '';
        $defaultMaxAge = (is_string($defaultMaxAgeRaw) || is_int($defaultMaxAgeRaw)) ?
        trim((string)$defaultMaxAgeRaw) : '';
        $values[ClaimsEnum::DefaultMaxAge->value] = ctype_digit($defaultMaxAge) ? (int)$defaultMaxAge : null;

        $values[ClaimsEnum::RequireAuthTime->value] = (bool)($values[ClaimsEnum::RequireAuthTime->value] ?? false);

        $values[ClientEntity::KEY_ADD_CLAIMS_TO_ID_TOKEN] =
        (bool)($values[ClientEntity::KEY_ADD_CLAIMS_TO_ID_TOKEN] ?? false);

        /** @var mixed $defaultAcrValues */
        $defaultAcrValues = $values[ClaimsEnum::DefaultAcrValues->value] ?? null;
        $defaultAcrValues = is_array($defaultAcrValues) ? $defaultAcrValues : [];
        $values[ClaimsEnum::DefaultAcrValues->value] = array_values(
            array_intersect($defaultAcrValues, array_keys($this->getSupportedAcrValues())),
        );

        foreach (
            [
                ClaimsEnum::InitiateLoginUri->value,
                ClaimsEnum::SoftwareId->value,
                ClaimsEnum::SoftwareVersion->value,
                ClaimsEnum::LogoUri->value,
                ClaimsEnum::ClientUri->value,
                ClaimsEnum::PolicyUri->value,
                ClaimsEnum::TosUri->value,
                ClaimsEnum::ApplicationType->value,
            ] as $stringClaim
        ) {
            /** @var mixed $claimValue */
            $claimValue = $values[$stringClaim] ?? '';
            $stringValue = is_string($claimValue) ? trim($claimValue) : '';
            $values[$stringClaim] = $stringValue === '' ? null : $stringValue;
        }

        /** @var mixed $contacts */
        $contacts = $values[ClaimsEnum::Contacts->value] ?? '';
        $values[ClaimsEnum::Contacts->value] = $this->helpers->str()->convertTextToArray(
            is_string($contacts) ? $contacts : '',
        );

        $authProcFilters = trim((string)($values[ClientEntity::KEY_AUTH_PROC_FILTERS] ?? ''));
        try {
            /** @psalm-suppress MixedAssignment */
            $decodedAuthProcFilters = $authProcFilters === '' ?
            [] :
            json_decode($authProcFilters, true, 512, JSON_THROW_ON_ERROR);
            // Normalize numeric priority keys to integers. PHP already casts
            // canonical integer string keys (e.g. "60") to int, but not forms
            // like "08", so we make the priority type predictable for the
            // SimpleSAMLphp ProcessingChain.
            /** @psalm-suppress MixedAssignment */
            $values[ClientEntity::KEY_AUTH_PROC_FILTERS] = is_array($decodedAuthProcFilters) ?
            $this->castNumericKeysToInt($decodedAuthProcFilters) :
            $decodedAuthProcFilters;
        } catch (\JsonException $e) {
            $this->addError('Authentication Processing Filters JSON error: ' . $e->getMessage());
            $values[ClientEntity::KEY_AUTH_PROC_FILTERS] = [];
        }

        return $values;
    }

    /**
     * @throws \Exception
     */
    public function setDefaults(object|array $values, bool $erase = false): static
    {
        if (!is_array($values)) {
            if ($values instanceof Traversable) {
                $values = iterator_to_array($values);
            } else {
                $values = (array) $values;
            }
        }

        /** @var string[] $redirectUris */
        $redirectUris = is_array($values['redirect_uri']) ? $values['redirect_uri'] : [];
        $values['redirect_uri'] = implode("\n", $redirectUris);

        // Allowed origins are only available for public clients (not for confidential clients).
        if (!$values['is_confidential'] && isset($values['allowed_origin'])) {
            /** @var string[] $allowedOrigins */
            $allowedOrigins = is_array($values['allowed_origin']) ? $values['allowed_origin'] : [];
            $values['allowed_origin'] = implode("\n", $allowedOrigins);
        } else {
            $values['allowed_origin'] = '';
        }

        /** @var string[] $postLogoutRedirectUris */
        $postLogoutRedirectUris = is_array($values['post_logout_redirect_uri']) ?
        $values['post_logout_redirect_uri'] : [];
        $values['post_logout_redirect_uri'] = implode("\n", $postLogoutRedirectUris);

        $scopes = is_array($values['scopes']) ? $values['scopes'] : [];
        $values['scopes'] = array_intersect($scopes, array_keys($this->getScopes()));

        $values['client_registration_types'] = is_array($values['client_registration_types']) ?
        array_intersect($values['client_registration_types'], $this->getClientRegistrationTypes()) :
        [ClientRegistrationTypesEnum::Automatic->value];

        $values['federation_jwks'] = is_array($values['federation_jwks']) ?
        json_encode($values['federation_jwks'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) : null;

        $values['jwks'] = is_array($values['jwks']) ?
        json_encode($values['jwks'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) : null;

        if (
            $values['auth_source'] !== null &&
            (!in_array($values['auth_source'], $this->sspBridge->auth()->source()->getSources()))
        ) {
            // Possible auth source name change without prior update in clients, resetting.
            $values['auth_source'] = null;
        }

        $requestUris = isset($values[ClaimsEnum::RequestUris->value]) &&
        is_array($values[ClaimsEnum::RequestUris->value]) ?
        $values[ClaimsEnum::RequestUris->value] :
        [];
        $stringUris = [];
        /** @var mixed $uri */
        foreach ($requestUris as $uri) {
            if (is_string($uri)) {
                $stringUris[] = $uri;
            }
        }
        $values[ClaimsEnum::RequestUris->value] = implode("\n", $stringUris);

        $values[ClientEntity::KEY_ALLOWED_RESPONSE_MODES] = is_array(
            $values[ClientEntity::KEY_ALLOWED_RESPONSE_MODES],
        ) ? $values[ClientEntity::KEY_ALLOWED_RESPONSE_MODES] : [];

        /** @var mixed $grantTypes */
        $grantTypes = $values[ClaimsEnum::GrantTypes->value] ?? null;
        $grantTypes = is_array($grantTypes) ? $grantTypes : [];
        $values[ClaimsEnum::GrantTypes->value] = array_values(
            array_intersect($grantTypes, array_keys($this->getSupportedGrantTypes())),
        );

        /** @var mixed $responseTypes */
        $responseTypes = $values[ClaimsEnum::ResponseTypes->value] ?? null;
        $responseTypes = is_array($responseTypes) ? $responseTypes : [];
        $values[ClaimsEnum::ResponseTypes->value] = array_values(
            array_intersect($responseTypes, array_keys($this->getSupportedResponseTypes())),
        );

        /** @var mixed $tokenEndpointAuthMethod */
        $tokenEndpointAuthMethod = $values[ClaimsEnum::TokenEndpointAuthMethod->value] ?? null;
        $values[ClaimsEnum::TokenEndpointAuthMethod->value] = (is_string($tokenEndpointAuthMethod) &&
            array_key_exists(
                $tokenEndpointAuthMethod,
                $this->getSupportedTokenEndpointAuthMethods(),
            )) ? $tokenEndpointAuthMethod : null;

        /** @var mixed $defaultMaxAge */
        $defaultMaxAge = $values[ClaimsEnum::DefaultMaxAge->value] ?? null;
        $values[ClaimsEnum::DefaultMaxAge->value] = is_int($defaultMaxAge) ? (string)$defaultMaxAge : '';

        $values[ClaimsEnum::RequireAuthTime->value] = (bool)($values[ClaimsEnum::RequireAuthTime->value] ?? false);

        $values[ClientEntity::KEY_ADD_CLAIMS_TO_ID_TOKEN] =
        (bool)($values[ClientEntity::KEY_ADD_CLAIMS_TO_ID_TOKEN] ?? false);

        /** @var mixed $defaultAcrValues */
        $defaultAcrValues = $values[ClaimsEnum::DefaultAcrValues->value] ?? null;
        $defaultAcrValues = is_array($defaultAcrValues) ? $defaultAcrValues : [];
        // The field is a multi-select bound to the OP's supported ACRs; keep only currently-supported values so the
        // control can render them (values no longer supported are dropped rather than shown as invalid options).
        $values[ClaimsEnum::DefaultAcrValues->value] = array_values(
            array_intersect($defaultAcrValues, array_keys($this->getSupportedAcrValues())),
        );

        /** @var mixed $contacts */
        $contacts = $values[ClaimsEnum::Contacts->value] ?? null;
        $contacts = is_array($contacts) ? $contacts : [];
        $contactStrings = [];
        /** @var mixed $contact */
        foreach ($contacts as $contact) {
            if (is_string($contact)) {
                $contactStrings[] = $contact;
            }
        }
        $values[ClaimsEnum::Contacts->value] = implode("\n", $contactStrings);

        /** @var mixed $authProcFilters */
        $authProcFilters = $values[ClientEntity::KEY_AUTH_PROC_FILTERS] ?? null;
        $values[ClientEntity::KEY_AUTH_PROC_FILTERS] = (is_array($authProcFilters) && $authProcFilters !== []) ?
        (string)json_encode($authProcFilters, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) :
        '';

        parent::setDefaults($values, $erase);

        return $this;
    }

    /**
     * @throws \Exception
     */
    protected function buildForm(): void
    {
        $this->getElementPrototype()->addAttributes(['class' => 'ui form']);

        $this->onValidate[] = $this->validateRedirectUri(...);
        $this->onValidate[] = $this->validateAllowedOrigin(...);
        $this->onValidate[] = $this->validatePostLogoutRedirectUri(...);
        $this->onValidate[] = $this->validateBackChannelLogoutUri(...);
        $this->onValidate[] = $this->validateEntityIdentifier(...);
        $this->onValidate[] = $this->validateClientRegistrationTypes(...);
        $this->onValidate[] = $this->validateResponseModes(...);
        $this->onValidate[] = $this->validateFederationJwks(...);
        $this->onValidate[] = $this->validateProtocolJwks(...);
        $this->onValidate[] = $this->validateJwksUri(...);
        $this->onValidate[] = $this->validateRequestUris(...);
        $this->onValidate[] = $this->validateAuthProcFilters(...);

        $this->setMethod('POST');
        $this->addComponent($this->csrfProtection, Form::ProtectorId);

        $this->addText('name', Translate::noop('Name'))
            ->setHtmlAttribute('class', 'full-width')
            ->setMaxLength(255)
            ->setRequired(Translate::noop('Name is required.'));

        $this->addTextArea('description', Translate::noop('Description'), null, 3)
            ->setHtmlAttribute('class', 'full-width');
        $this->addTextArea('redirect_uri', Translate::noop('Redirect URI'), null, 5)
            ->setHtmlAttribute('class', 'full-width')
            ->setRequired(Translate::noop('At least one redirect URI is required.'));

        $this->addCheckbox('is_enabled', Translate::noop('Activated'));

        $this->addCheckbox('is_confidential', '{oidc:client:is_confidential}');

        $this->addSelect('auth_source', Translate::noop('Authentication source'))
            ->setHtmlAttribute('class', 'full-width')
            ->setItems($this->sspBridge->auth()->source()->getSources(), false)
            ->setPrompt(Translate::noop('-'));

        $scopes = $this->getScopes();

        $this->addMultiSelect('scopes', Translate::noop('Scopes'), $scopes, 10)
            ->setHtmlAttribute('class', 'full-width')
            ->setRequired(Translate::noop('At least one scope is required.'));

        $this->addText('owner', Translate::noop('Owner'))
            ->setMaxLength(190);
        $this->addTextArea('post_logout_redirect_uri', Translate::noop('Post-logout Redirect URIs'), null, 5)
            ->setHtmlAttribute('class', 'full-width');
        $this->addTextArea('allowed_origin', Translate::noop('Allowed origins for public clients'), null, 5)
            ->setHtmlAttribute('class', 'full-width');

        $this->addText('backchannel_logout_uri', Translate::noop('Back-Channel Logout URI'))
            ->setHtmlAttribute('class', 'full-width');

        $this->addText('entity_identifier', 'Entity Identifier')
            ->setHtmlAttribute('class', 'full-width');

        $this->addMultiSelect(
            'client_registration_types',
            'Registration types',
            $this->getClientRegistrationTypes(),
            2,
        )->setHtmlAttribute('class', 'full-width');

        $this->addTextArea('federation_jwks', '{oidc:client:federation_jwks}', null, 5)
            ->setHtmlAttribute('class', 'full-width');

        $this->addTextArea('jwks', '{oidc:client:jwks}', null, 5)
            ->setHtmlAttribute('class', 'full-width');

        $this->addText('jwks_uri', 'JWKS URI')
            ->setHtmlAttribute('class', 'full-width');
        $this->addText('signed_jwks_uri', 'Signed JWKS URI')
            ->setHtmlAttribute('class', 'full-width');

        $this->addSelect('id_token_signed_response_alg', Translate::noop('ID Token Signing Algorithm'))
            ->setHtmlAttribute('class', 'full-width')
            ->setItems($this->getSupportedIdTokenSigningAlgs(), false)
            ->setPrompt(Translate::noop('-'));

        $this->addMultiSelect(
            ClientEntity::KEY_ALLOWED_RESPONSE_MODES,
            Translate::noop('Allowed Response Modes'),
            $this->getAllowedResponseModesValues(),
            3,
        )->setHtmlAttribute('class', 'full-width')
         ->setRequired(Translate::noop('At least one response mode is required.'));

        $this->addCheckbox(
            ClaimsEnum::RequirePushedAuthorizationRequests->value,
            'Require Pushed Authorization Requests (PAR)',
        );
        $this->addCheckbox(ClaimsEnum::RequireSignedRequestObject->value, 'Require Signed Request Object');
        $this->addTextArea(ClaimsEnum::RequestUris->value, 'Request URIs (OIDC Core / JAR, one per line)', null, 5)
            ->setHtmlAttribute('class', 'full-width');

        $this->addMultiSelect(
            ClaimsEnum::GrantTypes->value,
            Translate::noop('Grant Types'),
            $this->getSupportedGrantTypes(),
            3,
        )->setHtmlAttribute('class', 'full-width');

        $this->addMultiSelect(
            ClaimsEnum::ResponseTypes->value,
            Translate::noop('Response Types'),
            $this->getSupportedResponseTypes(),
            3,
        )->setHtmlAttribute('class', 'full-width');

        $this->addSelect(
            ClaimsEnum::TokenEndpointAuthMethod->value,
            Translate::noop('Token Endpoint Authentication Method'),
        )->setHtmlAttribute('class', 'full-width')
            ->setItems($this->getSupportedTokenEndpointAuthMethods(), false)
            ->setPrompt(Translate::noop('-'));

        $this->addText(ClaimsEnum::DefaultMaxAge->value, Translate::noop('Default Max Age (seconds)'))
            ->setHtmlAttribute('class', 'full-width')
            ->setHtmlType('number');

        $this->addCheckbox(ClaimsEnum::RequireAuthTime->value, Translate::noop('Require auth_time in ID Token'));

        $this->addCheckbox(
            ClientEntity::KEY_ADD_CLAIMS_TO_ID_TOKEN,
            Translate::noop('Release user claims in ID Token'),
        );

        // Bound to the OP's supported ACRs (acr_values_supported). When the OP advertises no ACRs, this has no
        // items and the field is hidden in the template (a per-client default ACR cannot do anything in that case).
        $this->addMultiSelect(
            ClaimsEnum::DefaultAcrValues->value,
            Translate::noop('Default ACR Values'),
            $this->getSupportedAcrValues(),
            3,
        )->setHtmlAttribute('class', 'full-width');

        $this->addText(ClaimsEnum::InitiateLoginUri->value, Translate::noop('Initiate Login URI'))
            ->setHtmlAttribute('class', 'full-width');

        $this->addText(ClaimsEnum::SoftwareId->value, Translate::noop('Software ID'))
            ->setHtmlAttribute('class', 'full-width');

        $this->addText(ClaimsEnum::SoftwareVersion->value, Translate::noop('Software Version'))
            ->setHtmlAttribute('class', 'full-width');

        $this->addText(ClaimsEnum::LogoUri->value, Translate::noop('Logo URI'))
            ->setHtmlAttribute('class', 'full-width');
        $this->addText(ClaimsEnum::ClientUri->value, Translate::noop('Client URI'))
            ->setHtmlAttribute('class', 'full-width');
        $this->addText(ClaimsEnum::PolicyUri->value, Translate::noop('Policy URI'))
            ->setHtmlAttribute('class', 'full-width');
        $this->addText(ClaimsEnum::TosUri->value, Translate::noop('Terms of Service URI'))
            ->setHtmlAttribute('class', 'full-width');

        $this->addSelect(ClaimsEnum::ApplicationType->value, Translate::noop('Application Type'))
            ->setHtmlAttribute('class', 'full-width')
            ->setItems($this->getSupportedApplicationTypes(), false)
            ->setPrompt(Translate::noop('-'));

        $this->addTextArea(ClaimsEnum::Contacts->value, Translate::noop('Contacts (one per line)'), null, 3)
            ->setHtmlAttribute('class', 'full-width');

        $this->addTextArea(
            ClientEntity::KEY_AUTH_PROC_FILTERS,
            Translate::noop('Authentication Processing Filters'),
            null,
            5,
        )->setHtmlAttribute('class', 'full-width');
    }

    /**
     * Validate provided response modes
     *
     * @throws \Exception
     */
    public function validateResponseModes(Form $form): void
    {
        $values = $form->getValues(self::TYPE_ARRAY);
        /** @var string[]|null $responseModes */
        $responseModes = $values[ClientEntity::KEY_ALLOWED_RESPONSE_MODES] ?? null;
        if (is_array($responseModes)) {
            $allowed = array_keys($this->getAllowedResponseModesValues());
            foreach ($responseModes as $mode) {
                if (!in_array($mode, $allowed, true)) {
                    $this->addError("Invalid value: $mode");
                }
            }
        }
    }

    /**
     * ID Token signing algorithms the OP can actually sign with, i.e., those
     * for which a protocol signing key pair is configured (the same set
     * advertised as id_token_signing_alg_values_supported in OP metadata).
     * Used to populate the id_token_signed_response_alg select, which
     * constrains the value to this set.
     *
     * @return string[]
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function getSupportedIdTokenSigningAlgs(): array
    {
        return $this->moduleConfig->getProtocolSignatureKeyPairBag()->getAllAlgorithmNamesUnique();
    }

    /**
     * @return string[] map of value => label
     */
    protected function getAllowedResponseModesValues(): array
    {
        $supported = $this->moduleConfig->getSupportedResponseModes();
        return array_combine($supported, $supported);
    }

    /**
     * Grant types the client may be registered to use (value => label), matching the OP's
     * grant_types_supported.
     *
     * @return array<string,string>
     */
    protected function getSupportedGrantTypes(): array
    {
        $supported = $this->moduleConfig->getSupportedGrantTypes();

        return array_combine($supported, $supported);
    }

    /**
     * Response types the client may be registered to use (value => label), matching the OP's
     * response_types_supported.
     *
     * @return array<string,string>
     */
    protected function getSupportedResponseTypes(): array
    {
        $supported = $this->moduleConfig->getSupportedResponseTypes();

        return array_combine($supported, $supported);
    }

    /**
     * Token endpoint authentication methods the client may be registered to use (value => label).
     *
     * @return array<string,string>
     */
    protected function getSupportedTokenEndpointAuthMethods(): array
    {
        $supported = $this->moduleConfig->getSupportedTokenEndpointAuthMethods();

        return array_combine($supported, $supported);
    }

    /**
     * The OP's supported ACR values (value => label), as configured via OPTION_AUTH_ACR_VALUES_SUPPORTED and
     * advertised in discovery as acr_values_supported. Empty when the OP advertises no ACRs.
     *
     * @return array<string,string>
     */
    protected function getSupportedAcrValues(): array
    {
        /** @var list<string> $supported */
        $supported = array_values(array_filter($this->moduleConfig->getAcrValuesSupported(), 'is_string'));

        return array_combine($supported, $supported);
    }

    /**
     * Whether the OP has any supported ACR values configured. Used by the template to hide the per-client
     * default_acr_values field when there is nothing to select.
     */
    public function hasConfiguredAcrValues(): bool
    {
        return $this->getSupportedAcrValues() !== [];
    }

    /**
     * JSON map of response_type => required grant_types, restricted to the response types this OP offers. Consumed
     * by the admin-form JavaScript to live-select the corresponding grant types, sharing the single source of truth
     * with the server-side normalization (ResponseTypeGrantTypeCorrespondence).
     */
    public function getResponseTypeGrantTypeMapJson(): string
    {
        $map = array_intersect_key(
            ResponseTypeGrantTypeCorrespondence::map(),
            $this->getSupportedResponseTypes(),
        );

        return (string)json_encode($map, JSON_UNESCAPED_SLASHES);
    }

    /**
     * Application types the client may register (value => label).
     *
     * @return array<string,string>
     */
    protected function getSupportedApplicationTypes(): array
    {
        $supported = [
            ApplicationTypesEnum::Web->value,
            ApplicationTypesEnum::Native->value,
        ];

        return array_combine($supported, $supported);
    }

    /**
     * @throws \Exception
     */
    protected function getScopes(): array
    {
        return array_map(
            fn(array $item): mixed => $item['description'],
            $this->moduleConfig->getScopes(),
        );
    }

    /**
     * @return string[]
     */
    public function getClientRegistrationTypes(): array
    {
        $types = [];

        foreach (ClientRegistrationTypesEnum::cases() as $case) {
            $types[$case->value] = $case->value;
        }

        return $types;
    }
}
