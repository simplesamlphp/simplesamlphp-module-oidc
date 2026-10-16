<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidcconformance\Auth\Source;

use SimpleSAML\Auth\State;
use SimpleSAML\Error\NoState;
use SimpleSAML\Error\UserAborted;
use SimpleSAML\Module\exampleauth\Auth\Source\UserPass;

/**
 * exampleauth:UserPass with a way to cancel, for the conformance image only: SimpleSAMLphp's login page has no
 * cancel button, and the conformance suite's browser automation can only fill in and click what a page has. Logging
 * in as `cancel`, with any password, stands for the End-User cancelling at the login page: the authentication ends
 * with SimpleSAMLphp's UserAborted, raised through the state's exception handler, as an authentication source which
 * lets the End-User cancel raises it. The OIDC module answers the client with `access_denied`; the suite's
 * "user rejects authentication" test logs in so.
 */
class CancellableUserPass extends UserPass
{
    public const string CANCEL_USERNAME = 'cancel';


    public static function handleLogin(string $authStateId, string $username, string $password): void
    {
        if ($username === self::CANCEL_USERNAME) {
            $state = State::loadState($authStateId, self::STAGEID);
            if ($state === null) {
                throw new NoState();
            }

            State::throwException($state, new UserAborted());
        }

        parent::handleLogin($authStateId, $username, $password);
    }
}
