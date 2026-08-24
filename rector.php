<?php

declare(strict_types=1);

use Rector\CodeQuality\Rector\Class_\InlineConstructorDefaultToPropertyRector;
use Rector\CodeQuality\Rector\ClassMethod\OptionalParametersAfterRequiredRector;
use Rector\CodingStyle\Rector\FuncCall\FunctionFirstClassCallableRector;
use Rector\Config\RectorConfig;
use Rector\TypeDeclaration\Rector\StmtsAwareInterface\DeclareStrictTypesRector;

if (function_exists('sspmodAutoloadPSR4')) {
    spl_autoload_unregister('sspmodAutoloadPSR4');
}

return RectorConfig::configure()
    ->withParallel(timeoutSeconds: 360)
    ->withImportNames(importDocBlockNames: false)
    ->withPaths([
        // TODO v7 mivanci also go trough commented out paths...
        //__DIR__ . '/docker',
        //__DIR__ . '/hooks',
        //__DIR__ . '/public',
        __DIR__ . '/src',
        __DIR__ . '/tests',
    ])
    ->withPhpSets(php83: true)
    ->withSkip([
        FunctionFirstClassCallableRector::class,
        OptionalParametersAfterRequiredRector::class,
    ])
    ->withRules([
        InlineConstructorDefaultToPropertyRector::class,
        DeclareStrictTypesRector::class,
    ]);
