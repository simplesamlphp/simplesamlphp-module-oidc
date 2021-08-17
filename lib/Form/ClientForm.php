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
     */
    public const REGEX_URI = '/^[^:]+:\/\/?[^\s\/$.?#].[^\s]*$/';

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
        $values = $form->getValues();
        $redirect_uris = $values['redirect_uri'];
        foreach ($redirect_uris as $redirect_uri) {
            if (!preg_match(self::REGEX_URI, $redirect_uri)) {
                $this->addError('Invalid URI: ' . $redirect_uri);
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

        // Sanitize Redirect URIs
        $redirect_uris = preg_split("/[\t\r\n]+/", $values['redirect_uri']);
        $redirect_uris = array_filter(
            $redirect_uris,
            /**
             * @param string $redirect_uri
             *
             * @return bool
             */
            function ($redirect_uri) {
                return !empty(trim($redirect_uri));
            }
        );
        $values['redirect_uri'] = $redirect_uris;
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
        $values['scopes'] = array_intersect($values['scopes'], array_keys($this->getScopes()));

        return parent::setDefaults($values, $erase);
    }

    protected function buildForm(): void
    {
        $this->getElementPrototype()->addAttributes(['class' => 'ui form']);

        $this->onValidate[] = [$this, 'validateRedirectUri'];

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
    }

    protected function getScopes(): array
    {
        $items = array_map(function ($item) {
            return $item['description'];
        }, $this->configurationService->getOpenIDScopes());

        return $items;
    }
}
