<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Helpers;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;

class Client
{
    /**
     * The characters of a client ID or secret given by hand. RFC 6749 Appendix A.1 and A.2 allow the printable
     * US-ASCII characters and the space (VSCHAR, %x20-7E). The space is left out: in a value copied from elsewhere,
     * it is far more likely a slip than part of the value.
     */
    final public const string GIVEN_CREDENTIAL_PATTERN = '/^[\x21-\x7E]+$/D';

    /**
     * The length of the client table's id column.
     */
    final public const int GIVEN_IDENTIFIER_MAX_LENGTH = 191;

    /**
     * A floor against a secret typed in rather than issued. RFC 6749 section 10.10 bounds the probability of guessing
     * a generated credential; the entropy of a secret given by hand can not be measured, but its length can.
     */
    final public const int GIVEN_SECRET_MIN_LENGTH = 32;

    /**
     * The length of the client table's secret column.
     */
    final public const int GIVEN_SECRET_MAX_LENGTH = 255;


    public function __construct(protected Http $http)
    {
    }


    /**
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    public function getFromRequest(
        ServerRequestInterface $request,
        ClientRepository $clientRepository,
    ): ClientEntityInterface {
        $params = $this->http->getAllRequestParams($request);
        $clientId = empty($params['client_id']) ? null : (string)$params['client_id'];

        if (!is_string($clientId)) {
            throw new OidcException('Client ID is missing.');
        }

        $client = $clientRepository->findById($clientId);

        if (!$client) {
            throw new OidcException('Client not found.');
        }

        return $client;
    }


    /**
     * Why a client ID given by hand can not be used; none when it can. Whether a client has it already is
     * ClientRepository's to say.
     *
     * The generic client for verifiable credential issuance is refused in any letter case: the database may compare
     * IDs case-insensitively (see ClientRepository::isIdentifierTakenIgnoringCase()).
     *
     * @return string[]
     */
    public function problemsWithGivenIdentifier(string $identifier): array
    {
        $problems = [];

        if (preg_match(self::GIVEN_CREDENTIAL_PATTERN, $identifier) !== 1) {
            $problems[] = Translate::noop('The client ID may only contain printable ASCII characters, and no spaces.');
        }

        if (strlen($identifier) > self::GIVEN_IDENTIFIER_MAX_LENGTH) {
            $problems[] = Translate::noop('The client ID may be at most 191 characters long.');
        }

        // PHP takes "0" for no value, and so does code which tests a client ID for truth. The admin UI's own lookup
        // does (ClientController::getClientFromRequest()), so a client with that ID could not even be managed.
        if ($identifier === '0') {
            $problems[] = Translate::noop('The client ID may not be "0".');
        }

        if (stripos($identifier, ClientEntityFactory::GENERIC_VCI_CLIENT_ID_PREFIX) === 0) {
            $problems[] = Translate::noop(
                'The client ID may not start with "vci_", which is reserved for the generic client for ' .
                'verifiable credential issuance.',
            );
        }

        return $problems;
    }


    /**
     * Why a client secret given by hand can not be used; none when it can.
     *
     * @return string[]
     */
    public function problemsWithGivenSecret(string $secret): array
    {
        $problems = [];

        if (preg_match(self::GIVEN_CREDENTIAL_PATTERN, $secret) !== 1) {
            $problems[] = Translate::noop(
                'The client secret may only contain printable ASCII characters, and no spaces.',
            );
        }

        if (strlen($secret) < self::GIVEN_SECRET_MIN_LENGTH) {
            $problems[] = Translate::noop('The client secret must be at least 32 characters long.');
        }

        if (strlen($secret) > self::GIVEN_SECRET_MAX_LENGTH) {
            $problems[] = Translate::noop('The client secret may be at most 255 characters long.');
        }

        return $problems;
    }
}
