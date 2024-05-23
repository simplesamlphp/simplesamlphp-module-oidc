<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Factories\CryptKeyFactory;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use Throwable;

class IdTokenHintRule extends AbstractRule
{
    public function __construct(
        protected ModuleConfig $moduleConfig,
        protected CryptKeyFactory $cryptKeyFactory,
    ) {
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
        array $allowedServerRequestMethods = ['GET'],
    ): ?ResultInterface {
        /** @var string|null $state */
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();

        $idTokenHintParam = $this->getParamFromRequestBasedOnAllowedMethods(
            'id_token_hint',
            $request,
            $loggerService,
            $allowedServerRequestMethods,
        );

        if ($idTokenHintParam === null) {
            return new Result($this->getKey(), $idTokenHintParam);
        }

        $privateKey = $this->cryptKeyFactory->buildPrivateKey();
        $publicKey = $this->cryptKeyFactory->buildPublicKey();
        /** @psalm-suppress ArgumentTypeCoercion */
        $jwtConfig = Configuration::forAsymmetricSigner(
            $this->moduleConfig->getSigner(),
            InMemory::plainText($privateKey->getKeyContents(), $privateKey->getPassPhrase() ?? ''),
            InMemory::plainText($publicKey->getKeyContents()),
        );

        if (empty($idTokenHintParam)) {
            throw OidcServerException::invalidRequest(
                'id_token_hint',
                'Received empty id_token_hint',
                null,
                null,
                $state
            );
        }

        try {
            /** @var UnencryptedToken $idTokenHint */
            $idTokenHint = $jwtConfig->parser()->parse($idTokenHintParam);

            /** @psalm-suppress ArgumentTypeCoercion */
            $jwtConfig->validator()->assert(
                $idTokenHint,
                new IssuedBy($this->moduleConfig->getSimpleSAMLSelfURLHost()),
                // Note: although logout spec does not mention it, validating signature seems like an important check
                // to make. However, checking the signature in a key roll-over scenario will fail for ID tokens
                // signed with previous key...
                new SignedWith(
                    $this->moduleConfig->getSigner(),
                    InMemory::plainText($publicKey->getKeyContents()),
                ),
            );
        } catch (Throwable $exception) {
            throw OidcServerException::invalidRequest('id_token_hint', $exception->getMessage(), null, null, $state);
        }

        return new Result($this->getKey(), $idTokenHint);
    }
}
