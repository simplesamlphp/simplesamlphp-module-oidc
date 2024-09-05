<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Result
 */
class ResultTest extends TestCase
{
    protected string $key = 'some-key';
    protected string $value = 'some-value';

    public function testConstruct(): Result
    {
        $result = new Result($this->key, $this->value);
        $this->assertInstanceOf(Result::class, $result);
        return $result;
    }

    public function testConstructWithoutValue(): void
    {
        $this->assertInstanceOf(Result::class, new Result($this->key));
    }

    /**
     * @depends testConstruct
     */
    public function testGetKey(Result $result): void
    {
        $this->assertSame($this->key, $result->getKey());
    }

    /**
     * @depends testConstruct
     *
     */
    public function testGetValue(Result $result): void
    {
        $this->assertSame($this->value, $result->getValue());
    }

    /**
     * @depends testConstruct
     */
    public function testSetValue(Result $result): void
    {
        $newValue = 'new-value';
        $result->setValue($newValue);

        $this->assertSame($newValue, $result->getValue());
    }
}
