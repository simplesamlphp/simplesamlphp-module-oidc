<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories\Entities;

use SimpleSAML\Module\oidc\Entities\ClaimSetEntity;

class ClaimSetEntityFactory
{
    public function build(string $scope, array $claims): ClaimSetEntity
    {
        return new ClaimSetEntity($scope, $claims);
    }
}
