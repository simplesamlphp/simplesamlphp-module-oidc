<?php

declare(strict_types=1);

use Rector\CodeQuality\Rector\Class_\InlineConstructorDefaultToPropertyRector;
use Rector\Config\RectorConfig;
use Rector\Set\ValueObject\LevelSetList;

return static function (RectorConfig $rectorConfig): void {
    $rectorConfig->importNames();
    $rectorConfig->disableParallel();

    $rectorConfig->bootstrapFiles([
        //__DIR__ . '/vendor/autoload.php',
    ]);

    $rectorConfig->paths([
        //__DIR__ . '/docker',
        //__DIR__ . '/hooks',
        //__DIR__ . '/public',
        __DIR__ . '/src',
        //__DIR__ . '/tests',
    ]);

    // register a single rule
    //$rectorConfig->rule(InlineConstructorDefaultToPropertyRector::class);
    $rectorConfig->rule(\Rector\TypeDeclaration\Rector\StmtsAwareInterface\DeclareStrictTypesRector::class);

    // define sets of rules
    $rectorConfig->sets([
        LevelSetList::UP_TO_PHP_81,
    ]);
};
