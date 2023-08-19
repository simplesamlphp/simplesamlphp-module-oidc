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

namespace SimpleSAML\Module\oidc\Form;

use Exception;
use Nette\Forms\Form;
use SimpleSAML\Auth\Source;
use SimpleSAML\Module\oidc\Form\Controls\CsrfProtection;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use Traversable;

class ClientForm extends Form
{
    protected const TYPE_ARRAY = 'array';

    /**
     * RFC3986. AppendixB. Parsing a URI Reference with a Regular Expression.
     */
    public const REGEX_URI = '/^[^:]+:\/\/?[^\s\/$.?#].[^\s]*$/';

    /**
     * Must have http:// or https:// scheme, and at least one 'domain.top-level-domain' pair, or more subdomains.
     * Top-level-domain may end with '.'.
     * No reserved chars allowed, meaning no userinfo, path, query or fragment components. May end with port number.
     */
    public const REGEX_ALLOWED_ORIGIN_URL =
        "/^http(s?):\/\/[^\s\/!$&'()+,;=.?#@*:]+\.[^\s\/!$&'()+,;=.?#@*]+\.?(\.[^\s\/!$&'()+,;=?#@*:]+)*(:\d{1,5})?$/i";

    /**
     * URI which must contain https or http scheme, can contain path and query, and can't contain fragment.
     */
    public const REGEX_HTTP_URI = '/^http(s?):\/\/[^\s\/$.?#][^\s#]*$/i';

    private ConfigurationService $configurationService;

    /**
     * @throws Exception
     */
    public function __construct(ConfigurationService $configurationService)
    {
        parent::__construct();

        $this->configurationService = $configurationService;

        $this->buildForm();
    }

    public function validateRedirectUri(Form $form): void
    {
        /** @var array $values */
        $values = $form->getValues(self::TYPE_ARRAY);

        $this->validateByMatchingRegex(
            $values['redirect_uri'] ?? [],
            self::REGEX_URI,
            'Invalid URI: '
        );
    }

    public function validateAllowedOrigin(Form $form): void
    {
        /** @var array $values */
        $values = $form->getValues(self::TYPE_ARRAY);

        $this->validateByMatchingRegex(
            $values['allowed_origin'] ?? [],
            self::REGEX_ALLOWED_ORIGIN_URL,
            'Invalid allowed origin: '
        );
    }

    public function validatePostLogoutRedirectUri(Form $form): void
    {
        /** @var array $values */
        $values = $form->getValues(self::TYPE_ARRAY);

        $this->validateByMatchingRegex(
            $values['post_logout_redirect_uri'] ?? [],
            self::REGEX_URI,
            'Invalid post-logout redirect URI: '
        );
    }

    public function validateBackChannelLogoutUri(Form $form): void
    {
        if (($bclUri = $form->getValues()['backchannel_logout_uri'] ?? null) !== null) {
            $this->validateByMatchingRegex(
                [$bclUri],
                self::REGEX_HTTP_URI,
                'Invalid back-channel logout URI: '
            );
        }
    }

    /**
     * @param array $values
     * @param non-empty-string $regex
     * @param string $messagePrefix
     * @return void
     */
    protected function validateByMatchingRegex(
        array $values,
        string $regex,
        string $messagePrefix = 'Invalid value: '
    ): void {
        foreach ($values as $value) {
            if (!preg_match($regex, $value)) {
                $this->addError($messagePrefix . $value);
            }
        }
    }

    public function getValues($returnType = null, ?array $controls = null): array
    {
        /** @var array $values */
        $values = parent::getValues(self::TYPE_ARRAY);

        // Sanitize redirect_uri and allowed_origin
        $values['redirect_uri'] = $this->convertTextToArrayWithLinesAsValues($values['redirect_uri']);
        if (! $values['is_confidential'] && isset($values['allowed_origin'])) {
            $values['allowed_origin'] = $this->convertTextToArrayWithLinesAsValues($values['allowed_origin']);
        } else {
            $values['allowed_origin'] = [];
        }
        $values['post_logout_redirect_uri'] =
            $this->convertTextToArrayWithLinesAsValues($values['post_logout_redirect_uri']);

        $bclUri = trim($values['backchannel_logout_uri']);
        $values['backchannel_logout_uri'] = empty($bclUri) ? null : $bclUri;

        // openid scope is mandatory
        $values['scopes'] = array_unique(
            array_merge(
                $values['scopes'],
                ['openid']
            )
        );

        return $values;
    }

    /**
     * @throws Exception
     */
    public function setDefaults($data, bool $erase = false): ClientForm
    {
        if (! is_array($data)) {
            if ($data instanceof Traversable) {
                $data = iterator_to_array($data);
            } else {
                $data = (array) $data;
            }
        }

        $data['redirect_uri'] = implode("\n", $data['redirect_uri']);

        // Allowed origins are only available for public clients (not for confidential clients).
        if (! $data['is_confidential'] && isset($data['allowed_origin'])) {
            $data['allowed_origin'] = implode("\n", $data['allowed_origin']);
        } else {
            $data['allowed_origin'] = '';
        }

        $data['post_logout_redirect_uri'] = implode("\n", $data['post_logout_redirect_uri']);

        $data['scopes'] = array_intersect($data['scopes'], array_keys($this->getScopes()));

        return parent::setDefaults($data, $erase);
    }

    /**
     * @throws Exception
     */
    protected function buildForm(): void
    {
        $this->getElementPrototype()->addAttributes(['class' => 'ui form']);

        /** @psalm-suppress InvalidPropertyAssignmentValue According to docs this is fine. */
        $this->onValidate[] = [$this, 'validateRedirectUri'];
        /** @psalm-suppress InvalidPropertyAssignmentValue According to docs this is fine. */
        $this->onValidate[] = [$this, 'validateAllowedOrigin'];
        /** @psalm-suppress InvalidPropertyAssignmentValue According to docs this is fine. */
        $this->onValidate[] = [$this, 'validatePostLogoutRedirectUri'];
        /** @psalm-suppress InvalidPropertyAssignmentValue According to docs this is fine. */
        $this->onValidate[] = [$this, 'validateBackChannelLogoutUri'];

        $this->setMethod('POST');
        $this->addComponent(new CsrfProtection('{oidc:client:csrf_error}'), Form::PROTECTOR_ID);

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
    }

    /**
     * @throws Exception
     */
    protected function getScopes(): array
    {
        return array_map(function ($item): mixed {
            return $item['description'];
        }, $this->configurationService->getOpenIDScopes());
    }

    /**
     * @param string $text
     * @return string[]
     */
    protected function convertTextToArrayWithLinesAsValues(string $text): array
    {
        return array_filter(
            preg_split("/[\t\r\n]+/", $text),
            /**
             * @param string $line
             *
             * @return bool
             */
            function (string $line) {
                return !empty(trim($line));
            }
        );
    }
}
