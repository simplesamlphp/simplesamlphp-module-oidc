<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList\Values;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\StatusList\Values\CredentialStatusChange;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

/**
 * What `CredentialStatusService` answers when a credential's status has been set: where the entry is,
 * what it held before, what it holds now, and whether this call is what put it there.
 *
 * The admin screen and the API answer their callers from it, and the last of those fields is the one
 * they read to tell a change from a repeat, so it is pinned in both of its values.
 */
#[CoversClass(CredentialStatusChange::class)]
class CredentialStatusChangeTest extends TestCase
{
    protected const string STATUS_LIST_ID = '0f3c9a71';

    protected const int IDX = 1234;


    protected function sut(bool $isChanged = true): CredentialStatusChange
    {
        return new CredentialStatusChange(
            self::STATUS_LIST_ID,
            self::IDX,
            StatusTypeEnum::Valid->value,
            StatusTypeEnum::Invalid,
            $isChanged,
        );
    }


    /**
     * The status before is carried as the raw value it was observed as, the status now as the type it
     * was set to; the two are distinct here so that neither can stand in for the other.
     */
    public function testCarriesWhatItWasGiven(): void
    {
        $change = $this->sut();

        $this->assertSame(self::STATUS_LIST_ID, $change->getStatusListId());
        $this->assertSame(self::IDX, $change->getIdx());
        $this->assertSame(StatusTypeEnum::Valid->value, $change->getPreviousStatus());
        $this->assertSame(StatusTypeEnum::Invalid, $change->getStatus());
        $this->assertTrue($change->isChanged());
    }


    public function testTellsARepeatFromAChange(): void
    {
        $this->assertFalse($this->sut(isChanged: false)->isChanged());
    }
}
