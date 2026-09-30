<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Helpers;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Helpers\Client;
use SimpleSAML\Module\oidc\Helpers\Http;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;

#[CoversClass(Client::class)]
#[AllowMockObjectsWithoutExpectations]
class ClientTest extends TestCase
{
    protected MockObject $httpMock;

    protected MockObject $requestMock;

    protected MockObject $clientRepositoryMock;

    protected MockObject $clientEntityMock;


    protected function sut(
        ?Http $http = null,
    ): Client {
        $http ??= $this->httpMock;

        return new Client($http);
    }


    protected function setUp(): void
    {
        $this->httpMock = $this->createMock(Http::class);
        $this->requestMock = $this->createMock(ServerRequestInterface::class);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->clientEntityMock = $this->createMock(ClientEntity::class);
    }


    public function testCanGetFromRequest(): void
    {
        $this->httpMock->expects($this->once())->method('getAllRequestParams')
            ->willReturn(['client_id' => 'clientId']);

        $this->clientRepositoryMock->expects($this->once())->method('findById')
            ->with('clientId')
            ->willReturn($this->clientEntityMock);

        $this->assertInstanceOf(
            ClientEntity::class,
            $this->sut()->getFromRequest($this->requestMock, $this->clientRepositoryMock),
        );
    }


    public function testGetFromRequestThrowsIfNoClientId(): void
    {
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('Client ID');

        $this->sut()->getFromRequest($this->requestMock, $this->clientRepositoryMock);
    }


    public function testGetFromRequestThrowsIfClientNotFound(): void
    {
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('Client not found');

        $this->httpMock->expects($this->once())->method('getAllRequestParams')
            ->willReturn(['client_id' => 'clientId']);
        $this->clientRepositoryMock->expects($this->once())->method('findById')
            ->with('clientId')
            ->willReturn(null);

        $this->sut()->getFromRequest($this->requestMock, $this->clientRepositoryMock);
    }


    public static function givenIdentifierProvider(): array
    {
        return [
            'a name' => ['MozillaThunderbird', []],
            'a URL' => ['https://rp.example.org/client', []],
            'every printable ASCII character but the space' => [implode('', range("\x21", "\x7E")), []],
            'the longest the table takes' => [str_repeat('a', 191), []],
            'vci_ inside' => ['my_vci_client', []],
            'zero, which PHP takes for no value' => ['0', ['"0"']],
            'two zeros' => ['00', []],
            'one character too long' => [str_repeat('a', 192), ['at most 191']],
            'a space' => ['my client', ['printable ASCII']],
            'a tab' => ["my\tclient", ['printable ASCII']],
            'a line break at the end' => ["myclient\n", ['printable ASCII']],
            'a character outside ASCII' => ['klijent-č', ['printable ASCII']],
            'empty' => ['', ['printable ASCII']],
            'the generic VCI client prefix' => ['vci_client', ['"vci_"']],
            'the generic VCI client prefix, in capitals' => ['VCI_client', ['"vci_"']],
            'everything at once' => ['vci_ ' . str_repeat('a', 191), ['printable ASCII', 'at most 191', '"vci_"']],
        ];
    }


    /**
     * @param string[] $expectedProblems A fragment of each problem expected, in order.
     */
    #[DataProvider('givenIdentifierProvider')]
    public function testProblemsWithGivenIdentifier(string $identifier, array $expectedProblems): void
    {
        $problems = $this->sut()->problemsWithGivenIdentifier($identifier);

        $this->assertCount(count($expectedProblems), $problems);
        foreach ($expectedProblems as $index => $expectedProblem) {
            $this->assertStringContainsString($expectedProblem, $problems[$index]);
        }
    }


    public static function givenSecretProvider(): array
    {
        return [
            'the shortest allowed' => [str_repeat('s', 32), []],
            'the longest the table takes' => [str_repeat('s', 255), []],
            'the characters form-urlencoding changes' => ['+/=%:&?#' . str_repeat('s', 24), []],
            'one character too short' => [str_repeat('s', 31), ['at least 32']],
            'one character too long' => [str_repeat('s', 256), ['at most 255']],
            'a space' => [str_repeat('s', 16) . ' ' . str_repeat('s', 16), ['printable ASCII']],
            'a character outside ASCII' => [str_repeat('s', 32) . 'č', ['printable ASCII']],
            'empty' => ['', ['printable ASCII', 'at least 32']],
        ];
    }


    /**
     * @param string[] $expectedProblems A fragment of each problem expected, in order.
     */
    #[DataProvider('givenSecretProvider')]
    public function testProblemsWithGivenSecret(string $secret, array $expectedProblems): void
    {
        $problems = $this->sut()->problemsWithGivenSecret($secret);

        $this->assertCount(count($expectedProblems), $problems);
        foreach ($expectedProblems as $index => $expectedProblem) {
            $this->assertStringContainsString($expectedProblem, $problems[$index]);
        }
    }


    /**
     * The messages name the limits as numbers, since a translatable string can not take them as arguments.
     */
    public function testTheMessagesNameTheLimitsTheConstantsSet(): void
    {
        $this->assertSame(191, Client::GIVEN_IDENTIFIER_MAX_LENGTH);
        $this->assertSame(32, Client::GIVEN_SECRET_MIN_LENGTH);
        $this->assertSame(255, Client::GIVEN_SECRET_MAX_LENGTH);
        $this->assertSame('vci_', ClientEntityFactory::GENERIC_VCI_CLIENT_ID_PREFIX);
    }
}
