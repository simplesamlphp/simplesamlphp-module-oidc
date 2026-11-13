<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\integration;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionClass;
use ReflectionFunction;
use ReflectionIntersectionType;
use ReflectionNamedType;
use ReflectionProperty;
use ReflectionType;
use ReflectionUnionType;
use RuntimeException;
use SimpleSAML\Configuration;
use SimpleSAML\Kernel;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Stores\Session\LogoutTicketStoreBuilder;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\Session;
use SimpleSAML\SessionHandler;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Controller\ArgumentResolverInterface;
use Symfony\Component\HttpKernel\Controller\ControllerResolverInterface;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouterInterface;
use Throwable;

/**
 * The module's container as SimpleSAMLphp builds it for a request, from the module's routing/services and
 * routing/routes, with every feature switch (each OPTION_*_ENABLED option) on: each route is reached at its path,
 * with each method it takes, and leads to an action whose controller the container can build and whose arguments can
 * be resolved, and the cron hook finds each service it fetches.
 *
 * Booting the Kernel compiles the container, which refuses an autowiring mistake in the constructor of a controller,
 * or of a service the cron hook fetches, and in the constructors of what they are given. Building a controller goes
 * further: it runs those constructors, and the factories services.yml names for what they are given, so such a
 * factory which hands back the wrong type, or a constructor which throws on the configuration, fails here rather
 * than on the first request to that endpoint. A factory class handed to a service, such as DidFactory, is built but
 * not called. Some controllers refuse to be built while their feature is switched off, and the admin ones redirect
 * to a login without an admin session, hence the switches and the session.
 *
 * The compiled container and a signing key pair, found through SimpleSAMLphp's certdir option, go in one temporary
 * directory, removed afterwards. The pair in tests/cert is not used: its file permissions are whatever the
 * checkout gave it, and the key loader reports any it does not expect.
 */
#[CoversNothing]
class ModuleKernelTest extends TestCase
{
    protected const string CONTROLLER_NAMESPACE = 'SimpleSAML\\Module\\oidc\\Controllers\\';

    protected const string ADMIN_SESSION_ID = 'module-kernel-test-admin-session';


    protected static string $workDir;

    protected array $originalServer;


    public static function setUpBeforeClass(): void
    {
        self::$workDir = sys_get_temp_dir() . '/oidc-module-kernel-test-' . bin2hex(random_bytes(8));
        self::createSigningKeyPair(self::$workDir . '/cert');

        Configuration::setConfigDir(dirname(__DIR__, 2) . '/config');
        $config = Configuration::getConfig('config.php')->toArray();
        $config['certdir'] = self::$workDir . '/cert';
        $config['cachedir'] = self::$workDir . '/cache';
        $config['database.dsn'] = 'sqlite::memory:';
        $config['database.username'] = null;
        $config['database.password'] = null;
        // A prefix of its own and no persistent handle, so that this in-memory database is not one another test class
        // connects to.
        $config['database.prefix'] = 'phpunit_kernel_';
        $config['database.persistent'] = false;
        $config['database.secondaries'] = [];
        Configuration::loadFromArray($config, '', 'simplesaml');

        $moduleConfig = Configuration::getConfig(ModuleConfig::DEFAULT_FILE_NAME)->toArray();
        foreach (self::featureSwitches() as $option) {
            $moduleConfig[$option] = true;
        }
        // Once Status Lists are switched on, the cron hook's Status List lifecycle asks for a credential signing key.
        $moduleConfig[ModuleConfig::OPTION_VCI_SIGNATURE_KEY_PAIRS] = [[
            ModuleConfig::KEY_ALGORITHM => SignatureAlgorithmEnum::RS256,
            ModuleConfig::KEY_PRIVATE_KEY_FILENAME => ModuleConfig::DEFAULT_PKI_PRIVATE_KEY_FILENAME,
            ModuleConfig::KEY_PUBLIC_KEY_FILENAME => ModuleConfig::DEFAULT_PKI_CERTIFICATE_FILENAME,
        ]];
        Configuration::setPreLoadedConfig(
            Configuration::loadFromArray($moduleConfig),
            ModuleConfig::DEFAULT_FILE_NAME,
        );

        (new DatabaseMigration())->migrate();
    }


    public static function tearDownAfterClass(): void
    {
        Configuration::clearInternalState();

        (new Filesystem())->remove(self::$workDir);
    }


    protected function setUp(): void
    {
        $this->originalServer = $_SERVER;
    }


    protected function tearDown(): void
    {
        $_SERVER = $this->originalServer;

        Session::clearInternalState();
        (new ReflectionProperty(SessionHandler::class, 'sessionHandler'))->setValue(null, null);
        // Loading the stand-in session copied its track ID to the logger, and building EndSessionController left a
        // ticket store on this class's database behind the builder's static.
        Logger::setTrackId(Logger::NO_TRACKID);
        (new ReflectionProperty(LogoutTicketStoreBuilder::class, 'sessionLogoutTicketStore'))->setValue(null, null);
    }


    /**
     * What SimpleSAMLphp's HttpKernel does with a request up to calling the action: the router matches it, the
     * controller resolver builds the controller from the container, and the argument resolver finds a value for each
     * argument of the action. The action itself is not called. Nothing between resolving and calling checks a value
     * against its parameter (a route's defaults and path variables reach the action as they are), so each is checked
     * here, and strictly: HttpKernel calls the action without strict types, so a numeric string the call would take
     * for an int parameter fails here. A path variable gets a placeholder value, as no route of the module constrains
     * one.
     */
    public function testEveryRouteLeadsToAnActionWhichCanBeCalled(): void
    {
        $_SERVER['HTTP_HOST'] = 'localhost';
        $_SERVER['SERVER_NAME'] = 'localhost';
        $_SERVER['SERVER_PORT'] = '80';
        $_SERVER['REQUEST_URI'] = '/module.php/oidc/jwks';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $this->installAdminSession();
        $container = self::bootKernelWithPublicResolvers();
        $router = self::router($container);
        $controllerResolver = $container->get('controller_resolver');
        $argumentResolver = $container->get('argument_resolver');
        if (
            !$controllerResolver instanceof ControllerResolverInterface ||
            !$argumentResolver instanceof ArgumentResolverInterface
        ) {
            throw new RuntimeException('The container holds no controller or argument resolver.');
        }

        // A route which names no method takes any. Another route matching the same path takes one of them away by
        // naming that method, or every one by naming none, which GET shows; so these are the methods worth trying.
        $routes = self::moduleRoutes($router);
        $namedMethods = ['GET'];
        foreach ($routes as $route) {
            $namedMethods = array_values(array_unique([...$namedMethods, ...$route->getMethods()]));
        }

        $failures = [];
        foreach ($routes as $name => $route) {
            foreach ($route->getMethods() ?: $namedMethods as $method) {
                $failure = self::dispatchUpToTheAction(
                    $router,
                    $controllerResolver,
                    $argumentResolver,
                    $name,
                    Request::create((string)preg_replace('/\{[^}]+\}/', 'x', $route->getPath()), $method),
                );
                if ($failure !== null) {
                    $failures[] = $failure;
                }
            }
        }

        $this->assertSame([], $failures);
    }


    /**
     * The module builds the URLs it hands out from RoutesEnum values (Utils\Routes), and routes.php names each route
     * after its case, so each case has to be a route of that name at that path, and every route the module adds has to
     * be one of them. Without this the test above would also pass for a route file which loads nothing.
     */
    public function testEveryRoutesEnumCaseIsARouteAtItsPath(): void
    {
        $expected = [];
        foreach (RoutesEnum::cases() as $case) {
            $expected[$case->name] = '/' . ModuleConfig::MODULE_NAME . '/' . $case->value;
        }
        ksort($expected);

        $actual = array_map(
            static fn(Route $route): string => $route->getPath(),
            self::moduleRoutes(self::router(self::bootKernel())),
        );
        ksort($actual);

        $this->assertSame($expected, $actual);
    }


    /**
     * A controller with no route serves no request.
     */
    public function testEveryControllerHasARoute(): void
    {
        $routedControllers = [];
        foreach (self::moduleRoutes(self::router(self::bootKernel())) as $route) {
            $controller = $route->getDefault('_controller');
            if (is_array($controller)) {
                $routedControllers[] = (string)$controller[0];
            } else {
                $routedControllers[] = explode('::', (string)$controller, 2)[0];
            }
        }
        $routedControllers = array_values(array_unique($routedControllers));
        sort($routedControllers);

        $this->assertSame(self::controllerClasses(), $routedControllers);
    }


    /**
     * The hook boots the Kernel itself and fetches its services by ID, which works only for a public service; a
     * failure to fetch or run one is reported as a summary line rather than thrown. It runs as from the command line,
     * with no request.
     */
    public function testTheCronHookFindsEveryServiceItFetches(): void
    {
        unset(
            $_SERVER['HTTP_HOST'],
            $_SERVER['SERVER_NAME'],
            $_SERVER['SERVER_PORT'],
            $_SERVER['REQUEST_URI'],
            $_SERVER['REQUEST_METHOD'],
        );
        require_once dirname(__DIR__, 3) . '/hooks/hook_cron.php';

        $croninfo = ['tag' => 'hourly', 'summary' => []];
        oidc_hook_cron($croninfo);

        $this->assertSame(['Module `oidc` clean up. Removed expired entries from storage.'], $croninfo['summary']);
    }


    /**
     * Every option ModuleConfig names OPTION_*_ENABLED, so that a switch added later is switched on here too.
     *
     * @return list<string>
     */
    protected static function featureSwitches(): array
    {
        $switches = [];
        foreach ((new ReflectionClass(ModuleConfig::class))->getConstants() as $name => $value) {
            if (str_starts_with($name, 'OPTION_') && str_ends_with($name, '_ENABLED') && is_string($value)) {
                $switches[] = $value;
            }
        }

        return $switches;
    }


    /**
     * One request through the route test above, up to the action: null when it gets there, or what stopped it.
     */
    protected static function dispatchUpToTheAction(
        RouterInterface $router,
        ControllerResolverInterface $controllerResolver,
        ArgumentResolverInterface $argumentResolver,
        string $routeName,
        Request $request,
    ): ?string {
        $label = sprintf('%s (%s)', $routeName, $request->getMethod());

        try {
            $router->getContext()->fromRequest($request);
            $request->attributes->add($router->matchRequest($request));
            if ($request->attributes->get('_route') !== $routeName) {
                return sprintf(
                    '%s: %s reaches the route %s.',
                    $label,
                    $request->getPathInfo(),
                    var_export($request->attributes->get('_route'), true),
                );
            }

            $controller = $controllerResolver->getController($request);
            if ($controller === false) {
                return sprintf('%s: names no controller.', $label);
            }

            $arguments = $argumentResolver->getArguments($request, $controller);
            $parameters = (new ReflectionFunction($controller(...)))->getParameters();
            foreach ($parameters as $index => $parameter) {
                $type = $parameter->getType();
                $values = $parameter->isVariadic() ? array_slice($arguments, $index) : [$arguments[$index] ?? null];
                foreach ($values as $value) {
                    if ($type !== null && !self::takes($type, $value)) {
                        return sprintf(
                            '%s: the %s found for $%s goes to a parameter of type %s.',
                            $label,
                            get_debug_type($value),
                            $parameter->getName(),
                            (string)$type,
                        );
                    }
                }
            }
        } catch (Throwable $exception) {
            return sprintf('%s: %s: %s', $label, $exception::class, $exception->getMessage());
        }

        return null;
    }


    /**
     * Whether a parameter of the type takes the value under strict types.
     */
    protected static function takes(ReflectionType $type, mixed $value): bool
    {
        if ($value === null && $type->allowsNull()) {
            return true;
        }

        if ($type instanceof ReflectionUnionType) {
            foreach ($type->getTypes() as $member) {
                if (self::takes($member, $value)) {
                    return true;
                }
            }

            return false;
        }

        if ($type instanceof ReflectionIntersectionType) {
            foreach ($type->getTypes() as $member) {
                if (!self::takes($member, $value)) {
                    return false;
                }
            }

            return true;
        }

        if (!$type instanceof ReflectionNamedType) {
            return false;
        }

        return match ($type->getName()) {
            'mixed' => true,
            'string' => is_string($value),
            'int' => is_int($value),
            'float' => is_float($value) || is_int($value),
            'bool' => is_bool($value),
            'true' => $value === true,
            'false' => $value === false,
            'array' => is_array($value),
            'iterable' => is_iterable($value),
            'callable' => is_callable($value),
            'object' => is_object($value),
            default => is_object($value) && is_a($value, $type->getName()),
        };
    }


    protected static function bootKernel(): ContainerInterface
    {
        $kernel = new Kernel(ModuleConfig::MODULE_NAME);
        $kernel->boot();

        return $kernel->getContainer();
    }


    /**
     * The same Kernel, with the two resolvers SimpleSAMLphp's HttpKernel is given made public so that a test can ask
     * them directly; no other definition changes.
     */
    protected static function bootKernelWithPublicResolvers(): ContainerInterface
    {
        $kernel = new class (ModuleConfig::MODULE_NAME) extends Kernel implements CompilerPassInterface {
            public function process(ContainerBuilder $container): void
            {
                foreach (['controller_resolver', 'argument_resolver'] as $serviceId) {
                    $container->getDefinition($serviceId)->setPublic(true);
                }
            }
        };
        $kernel->boot();

        return $kernel->getContainer();
    }


    protected static function router(ContainerInterface $container): RouterInterface
    {
        $router = $container->get('router');
        if (!$router instanceof RouterInterface) {
            throw new RuntimeException('The container holds no router.');
        }

        return $router;
    }


    /**
     * Every route the module adds, by route name. SimpleSAMLphp prefixes the module's routes with the module name and
     * adds a few of its own, which are left out.
     *
     * @return array<string, \Symfony\Component\Routing\Route>
     */
    protected static function moduleRoutes(RouterInterface $router): array
    {
        $routes = [];
        foreach ($router->getRouteCollection() as $name => $route) {
            if (str_starts_with($route->getPath(), '/' . ModuleConfig::MODULE_NAME . '/')) {
                $routes[$name] = $route;
            }
        }

        return $routes;
    }


    /**
     * Every class under src/Controllers which can be instantiated, each of which services.yml makes a controller, read
     * from the file system so that the list does not depend on the service definitions under test.
     *
     * @return list<string>
     */
    protected static function controllerClasses(): array
    {
        $directory = dirname(__DIR__, 3) . '/src/Controllers';
        $classes = [];

        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory));
        foreach ($files as $file) {
            if (!$file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            $relative = substr($file->getPathname(), strlen($directory) + 1, -strlen('.php'));
            $class = self::CONTROLLER_NAMESPACE . str_replace(DIRECTORY_SEPARATOR, '\\', $relative);
            if (class_exists($class) && (new ReflectionClass($class))->isInstantiable()) {
                $classes[] = $class;
            }
        }

        sort($classes);

        return $classes;
    }


    /**
     * A session SimpleSAMLphp takes for an authenticated admin, behind the session handler it caches.
     */
    protected function installAdminSession(): void
    {
        Session::clearInternalState();

        $session = $this->createStub(Session::class);
        $session->method('isValid')->willReturnCallback(static fn(string $authority): bool => $authority === 'admin');

        $sessionHandler = $this->createStub(SessionHandler::class);
        $sessionHandler->method('getCookieSessionId')->willReturn(self::ADMIN_SESSION_ID);
        $sessionHandler->method('loadSession')->willReturnCallback(
            static fn(?string $sessionId): ?Session => $sessionId === self::ADMIN_SESSION_ID ? $session : null,
        );

        (new ReflectionProperty(SessionHandler::class, 'sessionHandler'))->setValue(null, $sessionHandler);
    }


    protected static function createSigningKeyPair(string $certDir): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);

        if ($key === false || !mkdir($certDir, 0700, true) || !openssl_pkey_export($key, $privateKey)) {
            throw new RuntimeException('Could not create a signing key pair in ' . $certDir);
        }

        $files = [
            ModuleConfig::DEFAULT_PKI_PRIVATE_KEY_FILENAME => $privateKey,
            ModuleConfig::DEFAULT_PKI_CERTIFICATE_FILENAME => openssl_pkey_get_details($key)['key'],
        ];

        foreach ($files as $name => $contents) {
            if (file_put_contents($certDir . '/' . $name, $contents) === false) {
                throw new RuntimeException('Could not write ' . $name . ' to ' . $certDir);
            }
            chmod($certDir . '/' . $name, 0600);
        }
    }
}
