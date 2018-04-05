<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\SimpleSAML\Modules\OpenIDConnect\Repositories;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Modules\OpenIDConnect\Entity\UserEntity;
use SimpleSAML\Modules\OpenIDConnect\Repositories\UserRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\DatabaseMigration;

class UserRepositoryTest extends TestCase
{
    protected function setUp()
    {
        $config = [
            'database.dsn' => 'sqlite::memory:',
            'database.username' => null,
            'database.password' => null,
            'database.prefix' => 'phpunit_',
            'database.persistent' => true,
            'database.slaves' => [],
        ];

        \SimpleSAML_Configuration::loadFromArray($config, '', 'simplesaml');
        (new DatabaseMigration())->migrate();
    }

    public function testGetTableName()
    {
        $repository = new UserRepository();

        $this->assertSame('phpunit_oidc_user', $repository->getTableName());
    }

    public function testAddAndFound()
    {
        $repository = new UserRepository();
        $repository->add(UserEntity::fromData('uniqueid'));
        $user = $repository->getUserEntityByIdentifier('uniqueid');

        $this->assertNotNull($user);
        $this->assertSame($user->getIdentifier(), 'uniqueid');
    }

    public function testNotFound()
    {
        $repository = new UserRepository();
        $user = $repository->getUserEntityByIdentifier('unknownid');

        $this->assertNull($user);
    }

    public function testUpdate()
    {
        $repository = new UserRepository();
        $user = $repository->getUserEntityByIdentifier('uniqueid');
        $user->setClaims(['uid' => ['johndoe']]);
        $repository->update($user);

        $user2 = $repository->getUserEntityByIdentifier('uniqueid');
        $this->assertNotSame($user, $user2);
    }

    public function testDelete()
    {
        $repository = new UserRepository();
        $user = $repository->getUserEntityByIdentifier('uniqueid');
        $repository->delete($user);
        $user = $repository->getUserEntityByIdentifier('uniqueid');

        $this->assertNull($user);
    }
}
