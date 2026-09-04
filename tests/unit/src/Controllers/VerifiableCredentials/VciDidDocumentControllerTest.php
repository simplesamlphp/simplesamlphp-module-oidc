<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\VerifiableCredentials;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Controllers\VerifiableCredentials\VciDidDocumentController;
use SimpleSAML\Module\oidc\Factories\DidFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\VerificationMethodTypeEnum;
use SimpleSAML\OpenID\Codebooks\VerificationRelationshipEnum;
use SimpleSAML\OpenID\Did\DidDocument;
use SimpleSAML\OpenID\Did\DidUrl;
use SimpleSAML\OpenID\Did\Factories\DidDocumentFactory;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

#[CoversClass(VciDidDocumentController::class)]
#[AllowMockObjectsWithoutExpectations]
class VciDidDocumentControllerTest extends TestCase
{
    protected const string DID_WEB = 'did:web:example.org';

    protected const array DOCUMENT = ['id' => self::DID_WEB];


    protected MockObject $moduleConfigMock;

    protected MockObject $didFactoryMock;

    protected MockObject $didDocumentFactoryMock;

    protected MockObject $routesMock;

    protected MockObject $loggerServiceMock;

    protected SignatureKeyPairBag $vciSignatureKeyPairBag;


    protected function setUp(): void
    {
        $this->vciSignatureKeyPairBag = new SignatureKeyPairBag();

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciIssuerDidIdentifier')->willReturn(self::DID_WEB);
        $this->moduleConfigMock->method('getVciSignatureKeyPairBag')
            ->willReturn($this->vciSignatureKeyPairBag);

        $didDocumentMock = $this->createMock(DidDocument::class);
        $didDocumentMock->method('jsonSerialize')->willReturn(self::DOCUMENT);

        $this->didDocumentFactoryMock = $this->createMock(DidDocumentFactory::class);
        $this->didDocumentFactoryMock->method('forDidWeb')->willReturn($didDocumentMock);

        $this->didFactoryMock = $this->createMock(DidFactory::class);
        $this->didFactoryMock->method('didDocumentFactory')->willReturn($this->didDocumentFactoryMock);

        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->routesMock = $this->createMock(Routes::class);
        // A real JsonResponse rather than a stand-in, so that the content type this controller sets is
        // checked against what JsonResponse itself would do with it.
        $this->routesMock->method('newJsonResponse')->willReturnCallback(
            static fn(?array $data, int $status = 200, array $headers = []): JsonResponse =>
                new JsonResponse($data, $status, $headers),
        );
        $this->routesMock->method('newResponse')->willReturnCallback(
            static fn(?string $content, int $status = 200, array $headers = []): Response =>
                new Response($content, $status, $headers),
        );
    }


    protected function sut(): VciDidDocumentController
    {
        return new VciDidDocumentController(
            $this->moduleConfigMock,
            $this->didFactoryMock,
            $this->routesMock,
            $this->loggerServiceMock,
        );
    }


    public function testPublishesTheDocumentForTheConfiguredDidWeb(): void
    {
        $response = $this->sut()->didDocument();

        $this->assertSame(Response::HTTP_OK, $response->getStatusCode());
        $this->assertSame(json_encode(self::DOCUMENT), $response->getContent());
        $this->assertSame(
            VciDidDocumentController::MEDIA_TYPE,
            $response->headers->get('Content-Type'),
        );
        $this->assertSame('*', $response->headers->get('Access-Control-Allow-Origin'));
        $this->assertStringContainsString('max-age=', (string)$response->headers->get('Cache-Control'));
    }


    /**
     * Every configured key, not only the pair which is currently signing: a key which has signed a
     * credential still in circulation has to stay resolvable, and only assertionMethod, since these
     * keys are used for nothing else.
     */
    public function testPublishesEveryKeyUnderAssertionMethodOnly(): void
    {
        $this->didDocumentFactoryMock->expects($this->once())
            ->method('forDidWeb')
            ->with(
                $this->callback(
                    fn(DidUrl $did): bool => $did->getDid() === self::DID_WEB,
                ),
                $this->identicalTo($this->vciSignatureKeyPairBag),
                [VerificationRelationshipEnum::AssertionMethod],
                VerificationMethodTypeEnum::JsonWebKey2020,
            );

        $this->sut()->didDocument();
    }


    /**
     * The document is assembled from key material already on disk, so it must not be able to fail on
     * settings which exist to govern resolving other people's DIDs.
     *
     * Building the DID facade instantiates the configured cache adapter and resolves the outbound
     * destination policy. Reaching the document factory through it would let a malformed
     * `vci_cache_adapter`, or an outbound option this endpoint never uses, answer with a 500 - and a
     * credential issued under a did:web identity can only be verified by resolving this document, so
     * such a failure would make credentials already in wallets unverifiable.
     */
    public function testPublishingNeverBuildsTheResolvingFacade(): void
    {
        $this->didFactoryMock->expects($this->never())->method('build');

        $response = $this->sut()->didDocument();

        $this->assertSame(Response::HTTP_OK, $response->getStatusCode());
    }


    public function testAnswersNotFoundWhenNoDidWebIsConfigured(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciIssuerDidIdentifier')->willReturn(null);

        $response = $this->sut()->didDocument();

        $this->assertSame(Response::HTTP_NOT_FOUND, $response->getStatusCode());
        $this->assertSame(
            '*',
            $response->headers->get('Access-Control-Allow-Origin'),
            'A browser based verifier has to be able to tell this from a network failure.',
        );
    }


    /**
     * The identity is retired by removing the identifier, not by switching mode, so publication is
     * decided by that one option and does not consult the mode at all.
     *
     * Stated as never reading the mode rather than as looping over its values, because the mode is
     * also a thing which can be misconfigured: were it read here, a typo in a setting which has no
     * bearing on this document would stop it being served and take every credential issued under the
     * DID down with it.
     */
    public function testPublicationIsDecidedByTheIdentifierAloneAndNeverByTheMode(): void
    {
        $this->moduleConfigMock->expects($this->never())->method('getVciIssuerIdentifierMode');
        $this->moduleConfigMock->expects($this->never())->method('getVciIssuerIdentifier');

        $response = $this->sut()->didDocument();

        $this->assertSame(Response::HTTP_OK, $response->getStatusCode());
        $this->assertSame(json_encode(self::DOCUMENT), $response->getContent());
    }


    /**
     * Not gated on the issuance switch, on the same reasoning as the Status List endpoint: turning
     * issuance off must stop new credentials being issued, not make the existing ones unverifiable.
     */
    public function testKeepsPublishingWhileIssuanceIsDisabled(): void
    {
        $this->moduleConfigMock->expects($this->never())->method('getVciEnabled');

        $response = $this->sut()->didDocument();

        $this->assertSame(Response::HTTP_OK, $response->getStatusCode());
    }


    public function testFailsClosedWhenTheConfiguredIdentifierCanNotBeResolved(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciIssuerDidIdentifier')
            ->willThrowException(new RuntimeException('nope'));

        $this->loggerServiceMock->expects($this->once())->method('error');

        $response = $this->sut()->didDocument();

        $this->assertSame(Response::HTTP_INTERNAL_SERVER_ERROR, $response->getStatusCode());
    }


    /**
     * A document which does not describe the keys actually signing would have a verifier reject valid
     * credentials, which is worse than an outage it can retry.
     */
    public function testFailsClosedWhenTheDocumentCanNotBeBuilt(): void
    {
        $this->didDocumentFactoryMock = $this->createMock(DidDocumentFactory::class);
        $this->didDocumentFactoryMock->method('forDidWeb')
            ->willThrowException(new RuntimeException('nope'));

        $this->didFactoryMock = $this->createMock(DidFactory::class);
        $this->didFactoryMock->method('didDocumentFactory')->willReturn($this->didDocumentFactoryMock);

        $this->loggerServiceMock->expects($this->once())->method('error');

        $response = $this->sut()->didDocument();

        $this->assertSame(Response::HTTP_INTERNAL_SERVER_ERROR, $response->getStatusCode());
        $this->assertSame('', $response->getContent());
    }
}
