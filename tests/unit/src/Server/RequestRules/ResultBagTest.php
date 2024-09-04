<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Server\RequestRules;

use LogicException;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\ResultBag
 */
class ResultBagTest extends TestCase
{
    protected string $key = 'some-key';
    protected string $value = 'some-value';

    protected Result $result;

    protected ResultBag $resultBag;

    protected function setUp(): void
    {
        $this->result = new Result($this->key, $this->value);
        $this->resultBag = new ResultBag();
    }

    public function testGetAll(): void
    {
        $this->assertEmpty($this->resultBag->getAll());
        $this->resultBag->add($this->result);
        $this->resultBag->add(new Result('second', 'second'));
        $this->assertCount(2, $this->resultBag->getAll());
    }

    public function testAdd(): void
    {
        $this->assertNull($this->resultBag->get($this->key));
        $this->resultBag->add($this->result);
        $this->assertInstanceOf(Result::class, $this->resultBag->get($this->key));
    }

    public function testGetOrFail(): void
    {
        $this->resultBag->add($this->result);
        $this->assertSame($this->result, $this->resultBag->getOrFail($this->key));
        $this->expectException(LogicException::class);
        $this->resultBag->getOrFail('non-existent');
    }

    public function testGet(): void
    {
        $this->assertNull($this->resultBag->get($this->key));
        $this->resultBag->add($this->result);
        $this->assertSame($this->result, $this->resultBag->get($this->key));
    }

    public function testRemove(): void
    {
        $this->assertNull($this->resultBag->get($this->key));
        $this->resultBag->add($this->result);
        $this->assertSame($this->result, $this->resultBag->get($this->key));
        $this->resultBag->remove($this->key);
        $this->assertNull($this->resultBag->get($this->key));
    }
}
