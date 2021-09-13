<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\cdc\Client;
use SimpleSAML\Module\oidc\Factories\CryptKeyFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;

class IdTokenHintRule extends AbstractRule
{
    protected ConfigurationService $configurationService;
    protected CryptKeyFactory $cryptKeyFactory;
    protected ClientRepository $clientRepository;

    public function __construct(
        ConfigurationService $configurationService,
        CryptKeyFactory $cryptKeyFactory,
        ClientRepository $clientRepository
    ) {
        $this->configurationService = $configurationService;
        $this->cryptKeyFactory = $cryptKeyFactory;
        $this->clientRepository = $clientRepository;
    }

    /**
     * @inheritDoc
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET']
    ): ?ResultInterface {
        $idTokenHintParam = $this->getParamFromRequestBasedOnAllowedMethods(
            'id_token_hint',
            $request,
            $allowedServerRequestMethods
        );

        if ($idTokenHintParam === null) {
            return new Result($this->getKey(), $idTokenHintParam);
        }

        $privateKey = $this->cryptKeyFactory->buildPrivateKey();
        $publicKey = $this->cryptKeyFactory->buildPublicKey();
        $jwtConfig = Configuration::forAsymmetricSigner(
            $this->configurationService->getSigner(),
            InMemory::plainText($privateKey->getKeyContents(), $privateKey->getPassPhrase() ?? ''),
            InMemory::plainText($publicKey->getKeyContents())
        );

        try {
            /** @var UnencryptedToken $idTokenHint */
            $idTokenHint = $jwtConfig->parser()->parse($idTokenHintParam);

            $jwtConfig->validator()->assert(
                $idTokenHint,
                new IssuedBy($this->configurationService->getSimpleSAMLSelfURLHost()),
                // Checking the signature in a key roll-over scenarios will always fail with current setup,
                // (clients can send 'older' id token signed with 'previous key'), so leaving this out for now...
                //                new SignedWith(
                //                    $this->configurationService->getSigner(),
                //                    InMemory::plainText($publicKey->getKeyContents())
                //                )
            );
        } catch (\Throwable $exception) {
            throw OidcServerException::invalidRequest('id_token_hint', $exception->getMessage());
        }

        $claims = $idTokenHint->claims()->all();

        // Check if client is valid
        if (! isset($claims['aud'])) {
            throw OidcServerException::invalidRequest('id_token_hint', 'aud claim not present');
        }
        $auds = is_array($claims['aud']) ? $claims['aud'] : [$claims['aud']];

        foreach ($auds as $aud) {
            if ($this->clientRepository->findById($aud) === null) {
                throw OidcServerException::invalidRequest('id_token_hint', 'aud claim not valid');
            }
        }

        return new Result($this->getKey(), $idTokenHint);
    }
}
