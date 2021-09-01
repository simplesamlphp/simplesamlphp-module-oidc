<?php

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

use Nette\Forms\Form;
use SimpleSAML\Auth\Source;
use SimpleSAML\Module\oidc\Form\Controls\CsrfProtection;
use SimpleSAML\Module\oidc\Services\ConfigurationService;

class ClientForm extends Form
{
    /**
     * RFC3986. AppendixB. Parsing a URI Reference with a Regular Expression.
     * Important if updating regex: also used in JavaScript validation in templates/clients/_form.twig
     */
    public const REGEX_URI = '/^[^:]+:\/\/?[^\s\/$.?#].[^\s]*$/';

    /**
     * Must have http:// or https:// scheme, and at least one 'domain.top-level-domain' pair, or more subdomains.
     * Top-level-domain may end with '.'.
     * No reserved chars allowed, meaning no userinfo, path, query or fragment components. May end with port number.
     * Important if updating regex: also used in JavaScript validation in templates/clients/_form.twig
     */
    public const REGEX_ALLOWED_ORIGIN_URL =
        "/^http(s?):\/\/[^\s\/!$&'()+,;=.?#@*:]+\.[^\s\/!$&'()+,;=.?#@*]+\.?(\.[^\s\/!$&'()+,;=?#@*:]+)*(:\d{1,5})?$/i";

    /**
     * @var \SimpleSAML\Module\oidc\Services\ConfigurationService
     */
    private $configurationService;

    /**
     * {@inheritdoc}
     */
    public function __construct(ConfigurationService $configurationService)
    {
        parent::__construct(null);

        $this->configurationService = $configurationService;

        $this->buildForm();
    }

    public function validateRedirectUri(Form $form): void
    {
        $this->validateByMatchingRegex(
            $form->getValues()['redirect_uri'],
            self::REGEX_URI,
            'Invalid URI: '
        );
    }

    public function validateAllowedOrigin(Form $form): void
    {
        $this->validateByMatchingRegex(
            $form->getValues()['allowed_origin'] ?? [],
            self::REGEX_ALLOWED_ORIGIN_URL,
            'Invalid allowed origin: '
        );
    }

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

    /**
     * @param bool $asArray
     *
     * @return array
     */
    public function getValues($asArray = false)
    {
        $values = parent::getValues(true);

        // Sanitize redirect_uri and allowed_origin
        $values['redirect_uri'] = $this->convertTextToArrayWithLinesAsValues($values['redirect_uri']);
        if (! $values['is_confidential'] && isset($values['allowed_origin'])) {
            $values['allowed_origin'] = $this->convertTextToArrayWithLinesAsValues($values['allowed_origin']);
        } else {
            $values['allowed_origin'] = [];
        }

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
     * @param array $values
     * @param bool  $erase
     *
     * @return Form
     */
    public function setDefaults($values, $erase = false)
    {
        $values['redirect_uri'] = implode("\n", $values['redirect_uri']);

        // Allowed origins are only available for public clients (not for confidential clients).
        if (! $values['is_confidential'] && isset($values['allowed_origin'])) {
            $values['allowed_origin'] = implode("\n", $values['allowed_origin']);
        } else {
            $values['allowed_origin'] = '';
        }

        $values['scopes'] = array_intersect($values['scopes'], array_keys($this->getScopes()));

        return parent::setDefaults($values, $erase);
    }

    protected function buildForm(): void
    {
        $this->getElementPrototype()->addAttributes(['class' => 'ui form']);

        $this->onValidate[] = [$this, 'validateRedirectUri'];
        $this->onValidate[] = [$this, 'validateAllowedOrigin'];

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
            ->setAttribute('class', 'ui fluid dropdown clearable')
            ->setItems(Source::getSources(), false)
            ->setPrompt('Pick an AuthSource');

        $scopes = $this->getScopes();

        $this->addMultiSelect('scopes', '{oidc:client:scopes}')
            ->setAttribute('class', 'ui fluid dropdown')
            ->setItems($scopes)
            ->setRequired('Select one scope at least');

        $this->addTextArea('allowed_origin', '{oidc:client:allowed_origin}', null, 5);
    }

    protected function getScopes(): array
    {
        $items = array_map(function ($item) {
            return $item['description'];
        }, $this->configurationService->getOpenIDScopes());

        return $items;
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
