<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use League\OAuth2\Server\Entities\UserEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClaimSetInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;

/**
 * The one place which says what the 'sub' claim of a user is: the value the 'sub' attribute translation yields,
 * else the user's internal identifier. Every token which names the End-User (ID token, access token, and the
 * refresh token payload the access token's subject is carried in) takes it from here, so the subject a client
 * sees is the same in every flow and at every endpoint.
 *
 * The subject is resolved once, when the access token is minted, and then travels with the tokens: userinfo
 * and introspection read it from the presented token rather than resolving it again, so an attribute which
 * changes or disappears after minting can not make an endpoint contradict the ID token (OpenID Connect Core
 * 1.0 section 5.3.2 has the client reject a UserInfo 'sub' which differs from the ID token's).
 */
class SubjectResolver
{
    public function __construct(
        protected readonly ClaimTranslatorExtractor $claimTranslatorExtractor,
        protected readonly LoggerService $loggerService,
    ) {
    }


    /**
     * @throws \RuntimeException When the 'sub' translation yields a value which is not a non-empty string.
     */
    public function resolve(UserEntityInterface&ClaimSetInterface $user): string
    {
        $subject = $this->claimTranslatorExtractor->extractSubject($user->getClaims());

        if ($subject !== null) {
            return $subject;
        }

        // A 'sub' translation with attributes to read is expected to yield a value: the user record was written
        // from the same attributes at login. An emptied translation ('sub' => []) means the internal identifier
        // on purpose, so that one is not worth a warning.
        if ($this->claimTranslatorExtractor->isClaimTranslated('sub')) {
            $this->loggerService->warning(
                'The configured \'sub\' claim translation yields no value for the user; the internal user ' .
                'identifier is used as the subject.',
                ['user_id' => $user->getIdentifier()],
            );
        }

        return $user->getIdentifier();
    }
}
