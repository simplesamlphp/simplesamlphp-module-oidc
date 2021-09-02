<?php

namespace SimpleSAML\Module\oidc\Utils\Checker;

use PHPUnit\Framework\TestCase;

/**
 * Class ResultTest
 * @package SimpleSAML\Module\oidc\Utils\Checker
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Result
 */
class ResultTest extends TestCase
{
    protected $key = 'some-key';
    protected $value = 'some-value';

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
     *
     * @return void
     */
    public function testGetKey(Result $result): void
    {
        $this->assertSame($this->key, $result->getKey());
    }

    /**
     * @depends testConstruct
     *
     * @return void
     */
    public function testGetValue(Result $result): void
    {
        $this->assertSame($this->value, $result->getValue());
    }

    /**
     * @depends testConstruct
     *
     * @return void
     */
    public function testSetValue(Result $result): void
    {
        $newValue = 'new-value';
        $result->setValue($newValue);

        $this->assertSame($newValue, $result->getValue());
    }
}
