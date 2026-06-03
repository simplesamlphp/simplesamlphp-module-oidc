<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\ResponseModes;

use Laminas\Diactoros\Response;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Server\ResponseModes\FormPostResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseTypes\HtmlResponse;
use SimpleSAML\XHTML\Template;

/**
 * @covers \SimpleSAML\Module\oidc\Server\ResponseModes\FormPostResponseMode
 */
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
}
