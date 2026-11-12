<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\CredentialOfferRepository;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use Throwable;

/**
 * An issuer_state ties an OpenID4VCI authorization request to the Credential Offer it follows (OpenID4VCI 1.0
 * section 5.1.3), so in such a request it has to name an offer of this issuer which can still be redeemed: one
 * whose issuer state has neither expired nor been spent, and which the API caller that made it has not withdrawn.
 * A request naming any other is refused here, before the End-User is asked to log in, rather than only at the
 * token endpoint, where the offer is spent (AuthCodeGrant). With Verifiable Credential issuance switched on, a
 * code request carrying an issuer_state is an OpenID4VCI one (RequestParamsResolver::isVciAuthorizationCodeRequest()),
 * so it is checked. Otherwise -- issuance switched off, or a response type other than code -- the request follows
 * no offer, and the parameter means nothing to it: it is ignored, as any unknown parameter is (RFC 6749 section
 * 3.1).
 *
 * @extends \SimpleSAML\Module\oidc\Server\RequestRules\Rules\AbstractRule<string|null>
 */
class IssuerStateRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected readonly IssuerStateRepository $issuerStateRepository,
        protected readonly CredentialOfferRepository $credentialOfferRepository,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }


    /**
     * @inheritDoc
     *
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface $responseMode
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedServerRequestMethods
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode = new QueryResponseMode(),
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?Result {
        $issuerState = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::IssuerState->value,
            $request,
            $allowedServerRequestMethods,
        );

        if ($issuerState === null) {
            return new Result($this->getKey(), null);
        }

        if (!$this->requestParamsResolver->isVciAuthorizationCodeRequest($request, $allowedServerRequestMethods)) {
            $loggerService->debug('IssuerStateRule: issuer_state ignored, the request is not an OpenID4VCI one.');
            return new Result($this->getKey(), null);
        }

        $offeredState = $this->issuerStateRepository->findValid($issuerState);

        if ($offeredState !== null && !$this->isOfferWithdrawn($offeredState->getOfferId(), $loggerService)) {
            return new Result($this->getKey(), $issuerState);
        }

        $client = $currentResultBag->getOrFail(ClientRule::class)->getValue();
        $loggerService->notice(
            'Authorization request rejected: `issuer_state` names no Credential Offer which can still be redeemed.',
            ['client_id' => $client instanceof ClientEntityInterface ? $client->getIdentifier() : null],
        );

        // The generic client stands in for a wallet which is not registered, and both it and the redirect URI
        // were accepted only because the request carries an issuer_state. With that refuted, the client is in
        // effect an unknown one, and the error is shown here rather than sent to the redirect URI (RFC 6749
        // section 4.1.2.1).
        if (!$client instanceof ClientEntityInterface || $client->isGeneric()) {
            throw OidcServerException::invalidRequest(ParamsEnum::IssuerState->value, 'Issuer state is not valid.');
        }

        throw OidcServerException::invalidRequest(
            ParamsEnum::IssuerState->value,
            'Issuer state is not valid.',
            null,
            $currentResultBag->getOrFail(ClientRedirectUriRule::class)->getValue(),
            $currentResultBag->getOrFail(StateRule::class)->getValue(),
            $responseMode,
        );
    }


    /**
     * Whether the offer the issuer state redeems has been withdrawn. Read from the primary, as every read of an
     * offer is. A state which names no offer, and an offer which is not recorded, are left to the token endpoint,
     * which refuses both as this server's fault (AuthCodeGrant).
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException When the offer can not be read.
     */
    protected function isOfferWithdrawn(?string $offerId, LoggerService $loggerService): bool
    {
        if ($offerId === null) {
            return false;
        }

        try {
            $offer = $this->credentialOfferRepository->find($offerId);
        } catch (Throwable $exception) {
            $loggerService->error(
                'IssuerStateRule: the Credential Offer the issuer state redeems could not be read.',
                ['offerId' => $offerId, 'error' => $exception->getMessage()],
            );
            throw OidcServerException::serverError('The Credential Offer could not be read.');
        }

        if ($offer?->getWithdrawnAt() === null) {
            return false;
        }

        $loggerService->info(
            'IssuerStateRule: the Credential Offer the issuer state redeems has been withdrawn.',
            ['offerId' => $offerId],
        );

        return true;
    }
}
