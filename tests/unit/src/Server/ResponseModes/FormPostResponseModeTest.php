<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\ResponseModes;

use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Server\ResponseModes\FormPostResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseTypes\HtmlResponse;
use SimpleSAML\OpenID\Codebooks\ResponseModesEnum;
use SimpleSAML\XHTML\Template;

#[CoversClass(FormPostResponseMode::class)]
#[AllowMockObjectsWithoutExpectations]
class FormPostResponseModeTest extends TestCase
{
    protected FormPostResponseMode $sut;


    protected function setUp(): void
    {
        $config = Configuration::loadFromArray([
            'baseurlpath' => 'simplesaml/',
            'module.enable' => ['oidc' => true],
        ], '', 'simplesaml');

        $template = new Template($config, 'oidc:formpost.twig');

        $templateFactory = $this->createMock(TemplateFactory::class);
        $templateFactory->method('build')->willReturnCallback(
            function (
                string $templateName,
                array $data = [],
                ?string $activeHrefPath = null,
                ?bool $includeDefaultMenuItems = null,
                ?bool $showMenu = null,
                ?bool $showModuleName = null,
                ?bool $showSubPageTitle = null,
            ) use ($template) {
                $template->data = array_merge([
                    'showMenu' => $showMenu ?? false,
                    'showModuleName' => $showModuleName ?? false,
                    'showSubpageTitle' => $showSubPageTitle ?? false,
                ], $data);
                return $template;
            },
        );

        $this->sut = new FormPostResponseMode($templateFactory);
    }


    public function testBuildResponseReturnsHtmlWithFormPost(): void
    {
        $result = $this->sut->buildResponse(
            'https://example.org/callback',
            ['code' => 'abc123', 'state' => 'xyz'],
        );

        $this->assertInstanceOf(HtmlResponse::class, $result);

        $body = (string) $result->generateHttpResponse(new Response())->getBody();
        $this->assertStringContainsString('https://example.org/callback', $body);
        $this->assertStringContainsString('abc123', $body);
        $this->assertStringContainsString('xyz', $body);
        $this->assertMatchesRegularExpression('/method=["\']post["\']/i', $body);
    }


    /**
     * A parameter without a value is not posted, as http_build_query() leaves it out of the redirect modes: a
     * response to a request without `state` carries none back (RFC 6749 sections 4.1.2 and 4.2.2), rather than
     * an empty field.
     */
    public function testAParameterWithoutAValueIsNotPosted(): void
    {
        $body = (string)$this->sut->buildResponse(
            'https://example.org/callback',
            ['code' => 'abc123', 'state' => null],
        )->generateHttpResponse(new Response())->getBody();

        $this->assertStringNotContainsString('name="state"', $body);
        $this->assertStringContainsString('name="code" value="abc123"', $body);
    }


    /**
     * Only a null is left out: a state of "0" is a value the client sent, and it goes back as it came.
     */
    public function testAStateOfZeroIsPosted(): void
    {
        $body = (string)$this->sut->buildResponse(
            'https://example.org/callback',
            ['code' => 'abc123', 'state' => '0'],
        )->generateHttpResponse(new Response())->getBody();

        $this->assertStringContainsString('name="state" value="0"', $body);
    }


    /**
     * The value it is kept by where it can not go itself (ResponseModeResolver).
     */
    public function testItsValueIsFormPost(): void
    {
        $this->assertSame(ResponseModesEnum::FormPost, $this->sut->getMode());
    }
}
