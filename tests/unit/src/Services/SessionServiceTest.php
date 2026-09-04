<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;
use SimpleSAML\Module\oidc\Services\SessionService;
use SimpleSAML\Session;

/**
 * `getSessionById()` is deliberately not covered: it reaches SimpleSAMLphp's session store statically, so
 * a unit test can neither stand in for that store nor exercise it without one.
 */
#[CoversClass(SessionService::class)]
#[AllowMockObjectsWithoutExpectations]
class SessionServiceTest extends TestCase
{
    protected const string CLIENT_ID = 'client-1';

    protected const string USER_ID = 'user-1';

    protected const string SESSION_ID = 'session-1';


    protected MockObject $sessionMock;

    /**
     * What the session holds, keyed by the data id, read and written through callbacks so that a test can
     * set up state and then assert on what was stored rather than only on what was called.
     *
     * @var array<string,mixed>
     */
    protected array $sessionData = [];


    protected function setUp(): void
    {
        $this->sessionData = [];

        $this->sessionMock = $this->createMock(Session::class);
        $this->sessionMock->method('getData')->willReturnCallback(
            fn(string $type, string $key): mixed => $this->sessionData[$key] ?? null,
        );
        $this->sessionMock->method('setData')->willReturnCallback(
            function (string $type, string $key, mixed $value): void {
                $this->sessionData[$key] = $value;
            },
        );
    }


    protected function sut(): SessionService
    {
        return new SessionService($this->sessionMock);
    }


    protected function association(
        string $clientId = self::CLIENT_ID,
        ?string $sessionId = self::SESSION_ID,
    ): RelyingPartyAssociation {
        return new RelyingPartyAssociation($clientId, self::USER_ID, $sessionId);
    }


    public function testHandsBackTheSessionItWasBuiltWith(): void
    {
        $this->assertSame($this->sessionMock, $this->sut()->getCurrentSession());
    }


    /**
     * Which authentication was performed matters to the ID Token's `auth_time` and to how a `prompt`
     * request is answered, so it is remembered for the length of the session.
     *
     * @throws \Exception
     */
    public function testRemembersWhetherAuthenticationCameFromACookie(): void
    {
        $sut = $this->sut();

        $sut->setIsCookieBasedAuthn(true);
        $this->assertTrue($sut->getIsCookieBasedAuthn());

        $sut->setIsCookieBasedAuthn(false);
        $this->assertFalse($sut->getIsCookieBasedAuthn());
    }


    /**
     * Nothing recorded is not the same answer as "not cookie based": one says this session has not been
     * through authentication yet, the other that it has and was asked for credentials.
     */
    public function testSaysNothingAboutCookieBasedAuthenticationWhenNoneWasRecorded(): void
    {
        $this->assertNull($this->sut()->getIsCookieBasedAuthn());

        // Anything which is not a boolean is not an answer either.
        $this->sessionData[SessionService::SESSION_DATA_ID_IS_COOKIE_BASED_AUTHN] = 'yes';

        $this->assertNull($this->sut()->getIsCookieBasedAuthn());
    }


    /**
     * @throws \Exception
     */
    public function testRemembersWhetherAuthenticationHappenedInThePreviousRequest(): void
    {
        $sut = $this->sut();

        $this->assertFalse($sut->getIsAuthnPerformedInPreviousRequest());

        $sut->setIsAuthnPerformedInPreviousRequest(true);

        $this->assertTrue($sut->getIsAuthnPerformedInPreviousRequest());
    }


    /**
     * The associations are what back-channel logout is delivered to, so one is kept for every client the
     * session was used at.
     *
     * @throws \Exception
     */
    public function testKeepsAnAssociationForEachClientTheSessionWasUsedAt(): void
    {
        $sut = $this->sut();

        $sut->addRelyingPartyAssociation($this->association());
        $sut->addRelyingPartyAssociation($this->association('client-2'));

        $this->assertCount(2, $sut->getRelyingPartyAssociations());
    }


    /**
     * A client the session was used at twice is one client to log out of, not two.
     *
     * @throws \Exception
     */
    public function testTheSameClientIsAssociatedOnlyOnce(): void
    {
        $sut = $this->sut();

        $sut->addRelyingPartyAssociation($this->association());
        $sut->addRelyingPartyAssociation($this->association());

        $this->assertCount(1, $sut->getRelyingPartyAssociations());
    }


    /**
     * The session id is half of what identifies an association, and there is nothing to log out of a
     * session which has none.
     *
     * @throws \Exception
     */
    public function testAssociatesNothingForAnAssociationWithNoSessionId(): void
    {
        $sut = $this->sut();

        $sut->addRelyingPartyAssociation($this->association(sessionId: null));
        $sut->addRelyingPartyAssociation($this->association(sessionId: ''));

        $this->assertSame([], $sut->getRelyingPartyAssociations());
    }


    /**
     * Session data survives serialization and comes back from wherever the session is stored, so what
     * comes back is checked rather than assumed: anything which is not an association is dropped instead
     * of being handed to back-channel logout.
     */
    public function testReadsBackOnlyWhatIsActuallyAnAssociation(): void
    {
        $association = $this->association();

        $this->sessionData[SessionService::SESSION_DATA_ID_RP_ASSOCIATIONS] = [
            'first' => $association,
            'second' => 'not an association',
            'third' => ['also' => 'not an association'],
        ];

        $associations = $this->sut()->getRelyingPartyAssociations();

        $this->assertSame(['first' => $association], $associations);
    }


    public function testReadsBackNothingWhenTheStoredAssociationsAreNotAList(): void
    {
        $this->sessionData[SessionService::SESSION_DATA_ID_RP_ASSOCIATIONS] = 'not a list';

        $this->assertSame([], $this->sut()->getRelyingPartyAssociations());
    }


    /**
     * @throws \Exception
     */
    public function testClearsTheAssociations(): void
    {
        $sut = $this->sut();
        $sut->addRelyingPartyAssociation($this->association());

        $sut->clearRelyingPartyAssociations();

        $this->assertSame([], $sut->getRelyingPartyAssociations());
    }


    /**
     * The static pair is what a logout handler reaches for: it runs against whichever session is being
     * ended, which is not the one this service was built around.
     *
     * @throws \Exception
     */
    public function testReadsAndClearsTheAssociationsOfAnotherSession(): void
    {
        $association = $this->association();
        $this->sessionData[SessionService::SESSION_DATA_ID_RP_ASSOCIATIONS] = ['first' => $association];

        $this->assertSame(
            ['first' => $association],
            SessionService::getRelyingPartyAssociationsForSession($this->sessionMock),
        );

        SessionService::clearRelyingPartyAssociationsForSession($this->sessionMock);

        $this->assertSame([], SessionService::getRelyingPartyAssociationsForSession($this->sessionMock));
    }


    /**
     * Whether the logout was started through OIDC decides whether the module's own logout handler runs,
     * so it is recorded on the session and read back from it during the logout of another session.
     *
     * @throws \Exception
     */
    public function testRemembersWhetherLogoutWasStartedThroughOidc(): void
    {
        $this->assertFalse(SessionService::getIsOidcInitiatedLogoutForSession($this->sessionMock));

        $this->sut()->setIsOidcInitiatedLogout(true);

        $this->assertTrue(SessionService::getIsOidcInitiatedLogoutForSession($this->sessionMock));
    }


    /**
     * @throws \Exception
     */
    public function testRegistersALogoutHandlerWithTheSession(): void
    {
        $this->sessionMock->expects($this->once())
            ->method('registerLogoutHandler')
            ->with('default-sp', 'SomeClass', 'someFunction');

        $this->sut()->registerLogoutHandler('default-sp', 'SomeClass', 'someFunction');
    }


    /**
     * Association and cookie-based-authn data outlive the request but not the session: a session which
     * ended has no clients left to log out of.
     *
     * @throws \Exception
     */
    public function testEverythingItStoresLastsUntilTheSessionEnds(): void
    {
        // Every call is kept, not the last one per key: adding an association and clearing the
        // associations both write the same key, so keying by it would let a wrong timeout on one of them
        // be overwritten by the other and never be seen.
        $timeouts = [];

        $sessionMock = $this->createMock(Session::class);
        $sessionMock->method('setData')->willReturnCallback(
            function (string $type, string $key, mixed $value, mixed $timeout = null) use (&$timeouts): void {
                $timeouts[] = ['key' => $key, 'timeout' => $timeout];
            },
        );

        $sut = new SessionService($sessionMock);
        $sut->setIsCookieBasedAuthn(true);
        $sut->setIsAuthnPerformedInPreviousRequest(true);
        $sut->setIsOidcInitiatedLogout(true);
        $sut->addRelyingPartyAssociation($this->association());
        $sut->clearRelyingPartyAssociations();

        $this->assertCount(5, $timeouts);

        foreach ($timeouts as $index => $call) {
            $this->assertSame(
                Session::DATA_TIMEOUT_SESSION_END,
                $call['timeout'],
                sprintf(
                    'Session data "%s" (write %d) was not stored for the length of the session.',
                    (string)$call['key'],
                    $index + 1,
                ),
            );
        }
    }
}
