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
use SimpleSAML\Auth\Source;
use SimpleSAML\Module\oidc\Forms\Controls\CsrfProtection;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Codebooks\ClientRegistrationTypesEnum;
use Traversable;

/**
 * @psalm-suppress PropertyNotSetInConstructor Raised for $httpRequest which is marked as internal, so won't handle.
 */
class ClientForm extends Form
{
    protected const TYPE_ARRAY = 'array';

    /**
     * RFC3986. AppendixB. Parsing a URI Reference with a Regular Expression.
     */
    final public const REGEX_URI = '/^[^:]+:\/\/?[^\s\/$.?#].[^\s]*$/';

    /**
     * Must have http:// or https:// scheme, and at least one 'domain.top-level-domain' pair, or more subdomains.
     * Top-level-domain may end with '.'.
     * No reserved chars allowed, meaning no userinfo, path, query or fragment components. May end with port number.
     */
    final public const REGEX_ALLOWED_ORIGIN_URL =
    "/^http(s?):\/\/([^\s\/!$&'()+,;=.?#@*:]+\.)"
    . "?[^\s\/!$&'()+,;=.?#@*:]+(\.[^\s\/!$&'()+,;=.?#@*:]+)*\.?(:\d{1,5})?$/i";

    /**
     * URI which must contain https or http scheme, can contain path and query, and can't contain fragment.
     */
    final public const REGEX_HTTP_URI = '/^http(s?):\/\/[^\s\/$.?#][^\s#]*$/i';

    /**
     * URI with https or http scheme and host / domain. It can contain path, but no query, or fragment component.
     */
    final public const REGEX_HTTP_URI_PATH = '/^http(s?):\/\/[^\s\/$.?#][^\s?#]*$/i';

    /**
     * @throws \Exception
     */
    public function __construct(private readonly ModuleConfig $moduleConfig, protected CsrfProtection $csrfProtection)
    {
        parent::__construct();

        $this->buildForm();
    }

    public function validateRedirectUri(Form $form): void
    {
        /** @var array $values */
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
        /** @var array $values */
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
        /** @var array $values */
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
        $federationJwks = $form->getValues()['federation_jwks'] ?? null;
        if (is_null($federationJwks)) {
            return;
        }

        if (!is_array($federationJwks)) {
            $this->addError(sprintf("Invalid JWKS format: %s", var_export($federationJwks, true)));
            return;
        }

        if (!array_key_exists('keys', $federationJwks)) {
            $this->addError(sprintf("No keys property in JWKS: %s", var_export($federationJwks, true)));
            return;
        }

        if (empty($federationJwks['keys'])) {
            $this->addError(sprintf("Empty keys in JWKS: %s", var_export($federationJwks, true)));
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
        /** @var array $values */
        $values = parent::getValues(self::TYPE_ARRAY);

        // Sanitize redirect_uri and allowed_origin
        $values['redirect_uri'] = $this->convertTextToArrayWithLinesAsValues((string)$values['redirect_uri']);
        if (! $values['is_confidential'] && isset($values['allowed_origin'])) {
            $values['allowed_origin'] = $this->convertTextToArrayWithLinesAsValues((string)$values['allowed_origin']);
        } else {
            $values['allowed_origin'] = [];
        }
        $values['post_logout_redirect_uri'] =
        $this->convertTextToArrayWithLinesAsValues((string)$values['post_logout_redirect_uri']);

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
        /** @psalm-suppress MixedAssignment */
        $values['federation_jwks'] = empty($federationJwks) ?
        null :
        json_decode($federationJwks, true, 512, JSON_THROW_ON_ERROR);

        return $values;
    }

    /**
     * @throws \Exception
     */
    public function setDefaults(object|array $data, bool $erase = false): static
    {
        if (!is_array($data)) {
            if ($data instanceof Traversable) {
                $data = iterator_to_array($data);
            } else {
                $data = (array) $data;
            }
        }

        /** @var string[] $redirectUris */
        $redirectUris = is_array($data['redirect_uri']) ? $data['redirect_uri'] : [];
        $data['redirect_uri'] = implode("\n", $redirectUris);

        // Allowed origins are only available for public clients (not for confidential clients).
        if (!$data['is_confidential'] && isset($data['allowed_origin'])) {
            /** @var string[] $allowedOrigins */
            $allowedOrigins = is_array($data['allowed_origin']) ? $data['allowed_origin'] : [];
            $data['allowed_origin'] = implode("\n", $allowedOrigins);
        } else {
            $data['allowed_origin'] = '';
        }

        /** @var string[] $postLogoutRedirectUris */
        $postLogoutRedirectUris = is_array($data['post_logout_redirect_uri']) ? $data['post_logout_redirect_uri'] : [];
        $data['post_logout_redirect_uri'] = implode("\n", $postLogoutRedirectUris);

        $scopes = is_array($data['scopes']) ? $data['scopes'] : [];
        $data['scopes'] = array_intersect($scopes, array_keys($this->getScopes()));

        $data['client_registration_types'] = is_array($data['client_registration_types']) ?
        array_intersect($data['client_registration_types'], $this->getClientRegistrationTypes()) :
        [ClientRegistrationTypesEnum::Automatic->value];

        $data['federation_jwks'] = is_array($data['federation_jwks']) ? json_encode($data['federation_jwks']) : null;

        parent::setDefaults($data, $erase);

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
        $this->onValidate[] = $this->validateFederationJwks(...);

        $this->setMethod('POST');
        $this->addComponent($this->csrfProtection, Form::ProtectorId);

        $this->addText('name', '{oidc:client:name}')
            ->setMaxLength(255)
            ->setRequired('Set a name');

        $this->addTextArea('description', '{oidc:client:description}', null, 5);
        $this->addTextArea('redirect_uri', '{oidc:client:redirect_uri}', null, 5)
            ->setRequired('Write one redirect URI at least');

        $this->addCheckbox('is_enabled', '{oidc:client:is_enabled}');

        $this->addCheckbox('is_confidential', '{oidc:client:is_confidential}');

        $this->addSelect('auth_source', '{oidc:client:auth_source}:')
            ->setHtmlAttribute('class', 'ui fluid dropdown clearable')
            ->setItems(Source::getSources(), false)
            ->setPrompt('Pick an AuthSource');

        $scopes = $this->getScopes();

        $this->addMultiSelect('scopes', '{oidc:client:scopes}')
            ->setHtmlAttribute('class', 'ui fluid dropdown')
            ->setItems($scopes)
            ->setRequired('Select one scope at least');

        $this->addText('owner', '{oidc:client:owner}')
            ->setMaxLength(190);
        $this->addTextArea('post_logout_redirect_uri', '{oidc:client:post_logout_redirect_uri}', null, 5);
        $this->addTextArea('allowed_origin', '{oidc:client:allowed_origin}', null, 5);

        $this->addText('backchannel_logout_uri', '{oidc:client:backchannel_logout_uri}');

        $this->addText('entity_identifier', 'Entity Identifier');

        $this->addMultiSelect('client_registration_types', 'Registration types')
            ->setHtmlAttribute('class', 'ui fluid dropdown')
            ->setItems($this->getClientRegistrationTypes());

        $this->addTextArea('federation_jwks', '{oidc:client:federation_jwks}', null, 5);
    }

    /**
     * @throws \Exception
     */
    protected function getScopes(): array
    {
        return array_map(
            fn(array $item): mixed => $item['description'],
            $this->moduleConfig->getOpenIDScopes(),
        );
    }

    /**
     * @return string[]
     */
    protected function convertTextToArrayWithLinesAsValues(string $text): array
    {
        return array_filter(
            preg_split("/[\t\r\n]+/", $text),
            fn(string $line): bool => !empty(trim($line)),
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
