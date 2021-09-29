<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Lcobucci\JWT\UnencryptedToken;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use Throwable;

class PostLogoutRedirectUriRule extends AbstractRule
{
    protected ClientRepository $clientRepository;

    public function __construct(ClientRepository $clientRepository)
    {
        $this->clientRepository = $clientRepository;
    }

    /**
     * @inheritDoc
     * @throws Throwable
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET']
    ): ?ResultInterface {
        /** @var string|null $state */
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();

        /** @var UnencryptedToken|null $idTokenHint */
        $idTokenHint = $currentResultBag->getOrFail(IdTokenHintRule::class)->getValue();

        $postLogoutRedirectUri = $this->getParamFromRequestBasedOnAllowedMethods(
            'post_logout_redirect_uri',
            $request,
            $loggerService,
            $allowedServerRequestMethods
        );

        $result = new Result($this->getKey(), $postLogoutRedirectUri);

        if ($postLogoutRedirectUri === null) {
            return $result;
        }

        if ($idTokenHint === null) {
            $hint = 'id_token_hint is mandatory when post_logout_redirect_uri is included';
            throw OidcServerException::invalidRequest('id_token_hint', $hint);
        }

        $claims = $idTokenHint->claims()->all();

        if (! isset($claims['aud']) || empty($claims['aud'])) {
            throw OidcServerException::invalidRequest('id_token_hint', 'aud claim not present', null, null, $state);
        }
        $auds = is_array($claims['aud']) ? $claims['aud'] : [$claims['aud']];

        $isPostLogoutRedirectUriRegistered = false;
        foreach ($auds as $aud) {
            $client = $this->clientRepository->findById($aud);
            if ($client === null) {
                throw OidcServerException::invalidRequest('id_token_hint', 'aud claim not valid', null, null, $state);
            }
            if (in_array($postLogoutRedirectUri, $client->getPostLogoutRedirectUri(), true)) {
                $isPostLogoutRedirectUriRegistered = true;
                break;
            }
        }

        if (! $isPostLogoutRedirectUriRegistered) {
            throw OidcServerException::invalidRequest(
                'id_token_hint',
                'post_logout_redirect_uri not registered',
                null,
                null,
                $state
            );
        }

        return $result;
    }
}
