<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

class PostLogoutRedirectUriRule extends AbstractRule
{
    public function __construct(
        ParamsResolver $paramsResolver,
        protected ClientRepository $clientRepository,
    ) {
        parent::__construct($paramsResolver);
    }

    /**
     * @inheritDoc
     * @throws \Throwable
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?ResultInterface {
        /** @var string|null $state */
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();

        /** @var \Lcobucci\JWT\UnencryptedToken|null $idTokenHint */
        $idTokenHint = $currentResultBag->getOrFail(IdTokenHintRule::class)->getValue();

        $postLogoutRedirectUri = $this->paramsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::PostLogoutRedirectUri->value,
            $request,
            $allowedServerRequestMethods,
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

        if (empty($claims['aud'])) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::IdTokenHint->value,
                'aud claim not present',
                null,
                null,
                $state,
            );
        }
        /** @var string[] $auds */
        $auds = is_array($claims['aud']) ? $claims['aud'] : [$claims['aud']];

        $isPostLogoutRedirectUriRegistered = false;
        foreach ($auds as $aud) {
            $client = $this->clientRepository->findById($aud);
            if ($client === null) {
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
