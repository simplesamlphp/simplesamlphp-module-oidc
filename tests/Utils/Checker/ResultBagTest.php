<?php

namespace SimpleSAML\Module\oidc\Utils\Checker;

use PHPUnit\Framework\TestCase;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\ResultBag
 */
class ResultBagTest extends TestCase
{
    protected $key = 'some-key';
    protected $value = 'some-value';

    protected $result;

    protected $resultBag;

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
        $this->expectException(\LogicException::class);
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
