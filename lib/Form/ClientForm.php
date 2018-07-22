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

namespace SimpleSAML\Modules\OpenIDConnect\Form;

use Nette\Forms\Form;

class ClientForm extends Form
{
    /**
     * RFC3986. AppendixB. Parsing a URI Reference with a Regular Expression.
     */
    const REGEX_URI = '/^[^:]+:\/\/?[^\s\/$.?#].[^\s]*$/';

    /**
     * {@inheritdoc}
     */
    public function __construct($name = null)
    {
        parent::__construct($name);

        $this->getElementPrototype()->addAttributes(['class' => 'ui form']);

        $this->onValidate[] = [$this, 'validateRedirectUri'];

        $this->setMethod('POST');
        $this->addComponent(new Controls\CsrfProtection(null), Form::PROTECTOR_ID);

        $this->addText('name', '{oidc:client:name}')
            ->setMaxLength(255)
            ->setRequired('Set a name')
        ;

        $this->addTextArea('description', '{oidc:client:description}', null, 5);
        $this->addTextArea('redirect_uri', '{oidc:client:redirect_uri}', null, 5)
            ->setRequired('Write one redirect URI at least')
        ;

        $this->addCheckbox('is_enabled', '{oidc:client:is_enabled}');

        $this->addSelect('auth_source', '{oidc:client:auth_source}:')
            ->setAttribute('class', 'ui fluid dropdown')
            ->setItems(\SimpleSAML_Auth_Source::getSources(), false)
            ->setPrompt('Pick an AuthSource')
            ->setRequired('Select one Auth Source')
        ;

        $oidcConfig = \SimpleSAML_Configuration::getOptionalConfig('module_oidc.php');
        $items = array_map(function ($item) {
            return $item['description'];
        }, $oidcConfig->getArray('scopes', []));

        $this->addMultiSelect('scopes', '{oidc:client:scopes}')
            ->setAttribute('class', 'ui fluid dropdown')
            ->setItems($items)
            ->setRequired('Select one scope at least');
    }

    /**
     * @param Form $form
     */
    public function validateRedirectUri($form)
    {
        $values = $form->getValues();
        $redirect_uris = $values['redirect_uri'];
        foreach ($redirect_uris as $redirect_uri) {
            if (!preg_match(self::REGEX_URI, $redirect_uri)) {
                $this->addError('Invalid URI: '.$redirect_uri);
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getValues($asArray = false)
    {
        $values = parent::getValues(true);

        // Sanitize Redirect URIs
        $redirect_uris = preg_split("/[\t\r\n]+/", $values['redirect_uri']);
        $redirect_uris = array_filter($redirect_uris, function ($redirect_uri) {
            return !empty(trim($redirect_uri));
        });
        $values['redirect_uri'] = $redirect_uris;

        return $values;
    }

    /**
     * {@inheritdoc}
     */
    public function setDefaults($values, $erase = false)
    {
        $values['redirect_uri'] = implode("\n", $values['redirect_uri']);

        return parent::setDefaults($values, $erase);
    }
}
