<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Factories\CryptKeyFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use Throwable;

class IdTokenHintRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        protected ModuleConfig $moduleConfig,
        protected CryptKeyFactory $cryptKeyFactory,
    ) {
        parent::__construct($requestParamsResolver);
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

        $idTokenHintParam = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::IdTokenHint->value,
            $request,
            $allowedServerRequestMethods,
        );

        if ($idTokenHintParam === null) {
            return new Result($this->getKey(), $idTokenHintParam);
        }

        // TODO mivanci Fix: unmockable services... inject instead.
        $privateKey = $this->cryptKeyFactory->buildPrivateKey();
        $publicKey = $this->cryptKeyFactory->buildPublicKey();
        /** @psalm-suppress ArgumentTypeCoercion */
        $jwtConfig = Configuration::forAsymmetricSigner(
            $this->moduleConfig->getProtocolSigner(),
            InMemory::plainText($privateKey->getKeyContents(), $privateKey->getPassPhrase() ?? ''),
            InMemory::plainText($publicKey->getKeyContents()),
        );

        if (empty($idTokenHintParam)) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::IdTokenHint->value,
                'Received empty id_token_hint',
                null,
                null,
                $state,
            );
        }

        try {
            /** @var \Lcobucci\JWT\UnencryptedToken $idTokenHint */
            $idTokenHint = $jwtConfig->parser()->parse($idTokenHintParam);

            /** @psalm-suppress ArgumentTypeCoercion */
            $jwtConfig->validator()->assert(
                $idTokenHint,
                new IssuedBy($this->moduleConfig->getIssuer()),
                // Note: although logout spec does not mention it, validating signature seems like an important check
                // to make. However, checking the signature in a key roll-over scenario will fail for ID tokens
                // signed with previous key...
                new SignedWith(
                    $this->moduleConfig->getProtocolSigner(),
                    InMemory::plainText($publicKey->getKeyContents()),
                ),
            );
        } catch (Throwable $exception) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::IdTokenHint->value,
                $exception->getMessage(),
                null,
                null,
                $state,
            );
        }

        return new Result($this->getKey(), $idTokenHint);
    }
}
