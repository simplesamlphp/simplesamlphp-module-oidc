<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Factories\AuthSimpleFactory;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Session;

class PromptRule extends AbstractRule
{
    const PROMPT_REAUTHENTICATE = 'prompt_reauthenticate';

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
        array $data
    ): ?ResultInterface {
        $authSimple = $this->authSimpleFactory->build($request);

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
                $queryParams['state'] ?? null
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
