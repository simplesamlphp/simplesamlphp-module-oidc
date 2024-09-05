<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controller\Federation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Controller\Federation\EntityStatementController;

#[CoversClass(EntityStatementController::class)]
class EntityStatementControllerTest extends TestCase
{
    public function testCanInstantiate(): void
    {
        $this->markTestIncomplete();
    }
}
