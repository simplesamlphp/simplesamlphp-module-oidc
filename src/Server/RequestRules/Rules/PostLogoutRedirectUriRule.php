<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

/**
 * @extends AbstractRule<string|null>
 */
class PostLogoutRedirectUriRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected ClientRepository $clientRepository,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }

    /**
     * @inheritDoc
     *
     * @throws \Throwable
     *
     * @param ResponseModeInterface $responseMode
     * @param HttpMethodsEnum[] $allowedServerRequestMethods
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode = new QueryResponseMode(),
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?Result {
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();

        $idTokenHint = $currentResultBag->getOrFail(IdTokenHintRule::class)->getValue();

        $postLogoutRedirectUri = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::PostLogoutRedirectUri->value,
            $request,
            $allowedServerRequestMethods,
        );

        $result = new Result($this->getKey(), $postLogoutRedirectUri);

        if ($postLogoutRedirectUri === null) {
            return $result;
        }

        // Per RP-Initiated Logout (https://openid.net/specs/openid-connect-rpinitiated-1_0.html), id_token_hint is
        // RECOMMENDED, not required, when post_logout_redirect_uri is included. If it is not supplied, the OP MUST NOT
        // perform post-logout redirection unless it has other means of confirming the legitimacy of the redirection
        // target. We have no such means (the registration check below relies on the id_token_hint aud claim), so
        // instead of rejecting the request, we simply skip the redirection. The end user will still be logged out and
        // shown our own "you are logged out" page.
        if ($idTokenHint === null) {
            $loggerService->warning(
                'post_logout_redirect_uri was provided without id_token_hint; ' .
                'skipping post-logout redirection and showing logout page instead.',
            );
            return new Result($this->getKey(), null);
        }

        $auds = $idTokenHint->getAudience();

        $isPostLogoutRedirectUriRegistered = false;
        foreach ($auds as $aud) {
            $client = $this->clientRepository->findById($aud);
            if ($client === null) {
                $loggerService->notice(
                    'End session request rejected: `id_token_hint` aud claim does not match a known client.',
                    ['aud' => $aud],
                );
                throw OidcServerException::invalidRequest(
                    ParamsEnum::IdTokenHint->value,
                    'aud claim not valid',
                    null,
                    null,
                    $state,
                );
            }
            if (in_array($postLogoutRedirectUri, $client->getPostLogoutRedirectUri(), true)) {
                $isPostLogoutRedirectUriRegistered = true;
                break;
            }
        }

        if (! $isPostLogoutRedirectUriRegistered) {
            $loggerService->notice(
                'End session request rejected: `post_logout_redirect_uri` is not registered for any client in ' .
                'the id_token_hint aud claim.',
                ['post_logout_redirect_uri' => $postLogoutRedirectUri],
            );
            throw OidcServerException::invalidRequest(
                ParamsEnum::IdTokenHint->value,
                'post_logout_redirect_uri not registered',
                null,
                null,
                $state,
            );
        }

        return $result;
    }
}
