<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Session;

class PromptRule extends AbstractRule
{
    private const PROMPT_REAUTHENTICATE = 'prompt_reauthenticate';

    /**
     * @var AuthSimpleFactory
     */
    private $authSimpleFactory;
    /**
     * @var Session
     */
    private $session;

    public function __construct(AuthSimpleFactory $authSimpleFactory, Session $session)
    {
        $this->authSimpleFactory = $authSimpleFactory;
        $this->session = $session;
    }

    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET']
    ): ?ResultInterface {
        /** @var ClientEntityInterface $client */
        $client = $currentResultBag->getOrFail(ClientIdRule::class)->getValue();

        $authSimple = $this->authSimpleFactory->build($client);

        $queryParams = $request->getQueryParams();
        if (!array_key_exists('prompt', $queryParams)) {
            $this->session->setData('oidc', self::PROMPT_REAUTHENTICATE, false);

            return null;
        }

        $prompt = explode(" ", $queryParams['prompt']);
        if (count($prompt) > 1 && in_array('none', $prompt, true)) {
            throw OAuthServerException::invalidRequest('prompt', 'Invalid prompt parameter');
        }
        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::class)->getValue();

        if (in_array('none', $prompt, true) && !$authSimple->isAuthenticated()) {
            throw OidcServerException::loginRequired(
                null,
                $redirectUri,
                null,
                $queryParams['state'] ?? null,
                $useFragmentInHttpErrorResponses
            );
        }

        if (in_array('login', $prompt, true) && $authSimple->isAuthenticated()) {
            if ($this->session->getData('oidc', self::PROMPT_REAUTHENTICATE) !== 'login') {
                $authId = $authSimple->getAuthSource()->getAuthId();
                $this->session->doLogout($authId);
            }

            $this->session->setData('oidc', self::PROMPT_REAUTHENTICATE, 'login');
        }

        return null;
    }
}
