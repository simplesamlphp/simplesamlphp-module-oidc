<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Utils\ResponseTypeGrantTypeCorrespondence;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\ResponseTypeGrantTypeCorrespondence
 */
class ResponseTypeGrantTypeCorrespondenceTest extends TestCase
{
    public function testRequiredGrantTypesForSupportedResponseTypes(): void
    {
        $this->assertSame(['authorization_code'], ResponseTypeGrantTypeCorrespondence::requiredGrantTypes(['code']));
        $this->assertSame(['implicit'], ResponseTypeGrantTypeCorrespondence::requiredGrantTypes(['id_token']));
        $this->assertSame(['implicit'], ResponseTypeGrantTypeCorrespondence::requiredGrantTypes(['id_token token']));
        $this->assertSame(
            ['authorization_code', 'implicit'],
            ResponseTypeGrantTypeCorrespondence::requiredGrantTypes(['code', 'id_token']),
        );
    }

    public function testRequiredGrantTypesIgnoresUnknownResponseTypes(): void
    {
        $this->assertSame([], ResponseTypeGrantTypeCorrespondence::requiredGrantTypes(['unknown', 'whatever']));
        $this->assertSame([], ResponseTypeGrantTypeCorrespondence::requiredGrantTypes([]));
    }

    public function testMergeAugmentsWithoutDuplicatesAndKeepsOrder(): void
    {
        // refresh_token is preserved; implicit is added because of id_token; authorization_code not duplicated.
        $this->assertSame(
            ['authorization_code', 'refresh_token', 'implicit'],
            ResponseTypeGrantTypeCorrespondence::mergeRequiredGrantTypes(
                ['authorization_code', 'refresh_token'],
                ['code', 'id_token'],
            ),
        );
    }

    public function testMergeDerivesGrantTypesWhenNoneGiven(): void
    {
        $this->assertSame(
            ['implicit'],
            ResponseTypeGrantTypeCorrespondence::mergeRequiredGrantTypes([], ['id_token']),
        );
    }
}
