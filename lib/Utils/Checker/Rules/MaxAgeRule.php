<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Session;

class MaxAgeRule extends AbstractRule
{
    private const MAX_AGE_REAUTHENTICATE = 'max_age_reauthenticate';

    /**
     * @var AuthSimpleFactory
     */
    private $authSimpleFactory;
    /**
     * @var Session
     */
    private $session;

    public function __construct(
        AuthSimpleFactory $authSimpleFactory,
        Session $session
    ) {
        $this->authSimpleFactory = $authSimpleFactory;
        $this->session = $session;
    }

    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET']
    ): ?ResultInterface {
        $queryParams = $request->getQueryParams();

        /** @var ClientEntityInterface $client */
        $client = $currentResultBag->getOrFail(ClientIdRule::class)->getValue();

        $authSimple = $this->authSimpleFactory->build($client);

        if (!array_key_exists('max_age', $queryParams) || !$authSimple->isAuthenticated()) {
            $this->session->setData('oidc', self::MAX_AGE_REAUTHENTICATE, false);

            return null;
        }

        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::class)->getValue();

        if (false === filter_var($queryParams['max_age'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]])) {
            throw OidcServerException::invalidRequest(
                'max_age',
                'max_age must be a valid integer',
                null,
                $redirectUri,
                $queryParams['state'] ?? null,
                $useFragmentInHttpErrorResponses
            );
        }

        $maxAge = (int) $queryParams['max_age'];
        $lastAuth =  (int) $authSimple->getAuthData('AuthnInstant');
        $isExpired = $lastAuth + $maxAge < time();

        if ($isExpired && !$this->session->getData('oidc', self::MAX_AGE_REAUTHENTICATE)) {
            $authId = $authSimple->getAuthSource()->getAuthId();
            $this->session->doLogout($authId);

            $this->session->setData('oidc', self::MAX_AGE_REAUTHENTICATE, true);
        }

        return new Result($this->getKey(), $lastAuth);
    }
}
