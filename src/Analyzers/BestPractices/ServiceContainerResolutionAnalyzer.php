<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\CloningVisitor;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\NodeVisitorAbstract;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects manual service container resolution in application code.
 *
 * Checks for:
 * - app()->make() calls
 * - resolve() function calls
 * - App::make() static calls
 * - Container::getInstance() usage
 * - app()->bind() / singleton() outside service providers
 * - Recommends constructor injection
 *
 * Whitelisted contexts (where manual resolution is legitimate):
 * - Migrations: Don't support constructor DI, must use app() helper
 * - Seeders: Often need dynamic service resolution
 * - Factories: May need service resolution for test data
 * - Commands: Sometimes need conditional service resolution
 * - Service Providers: Legitimate container binding location
 * - Jobs: Queued jobs may need conditional resolution
 * - Listeners: Event listeners with conditional dependencies
 * - Middleware: Conditional resolution based on request context
 * - Observers: Model observers with dynamic dependencies
 * - Handlers: Various handler classes
 * - Closures: Support parameter-level DI but not constructor DI. Resolution is skipped
 *   because most closure contexts (collection callbacks, event listeners, queue jobs)
 *   don't support automatic injection, and distinguishing route closures from other
 *   closures is unreliable. Note: Binding inside closures is still flagged as it's always wrong.
 * - Route files: Use closures without DI support
 *
 * Configuration:
 * - whitelist_dirs: Directories to skip (e.g., tests, database/migrations, routes)
 * - whitelist_classes: Class name patterns to skip (e.g., *Command, *Job, *Listener)
 * - whitelist_methods: Non-resolution methods to skip (e.g., bound, has, call, tagged)
 * - whitelist_services: Service aliases that are legitimate to resolve (e.g., config, request)
 * - detect_psr_get: Whether to detect PSR-11 get() method (default: false)
 * - detect_manual_instantiation: Whether to detect new Class() for service patterns (default: false)
 * - manual_instantiation_patterns: Class name patterns to flag for manual instantiation
 */
class ServiceContainerResolutionAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Known Laravel ServiceProvider FQNs.
     *
     * @var array<string>
     */
    private const SERVICE_PROVIDER_CLASSES = [
        'Illuminate\\Support\\ServiceProvider',
        'Illuminate\\Foundation\\Support\\Providers\\RouteServiceProvider',
        'Illuminate\\Foundation\\Support\\Providers\\EventServiceProvider',
        'Illuminate\\Foundation\\Support\\Providers\\AuthServiceProvider',
    ];

    /** @var array<string> */
    private array $whitelistDirs = [];

    /** @var array<string> */
    private array $whitelistClasses = [];

    /** @var array<string> */
    private array $whitelistMethods = [];

    /** @var array<string> */
    private array $whitelistServices = [];

    private bool $detectPsrGet = false;

    private bool $detectManualInstantiation = false;

    /** @var array<string> */
    private array $manualInstantiationPatterns = [];

    /** @var array<string> */
    private array $manualInstantiationExcludePatterns = [];

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'service-container-resolution',
            name: 'Service Container Resolution Analyzer',
            description: 'Detects manual service container resolution that should use dependency injection',
            category: Category::BestPractices,
            severity: Severity::Medium,
            tags: ['dependency-injection', 'architecture', 'testability', 'laravel', 'ioc'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/service-container-resolution',
            timeToFix: 25
        );
    }

    /**
     * Load configuration from config repository.
     */
    private function loadConfiguration(): void
    {
        $baseKey = 'shieldci.analyzers.best-practices.service-container-resolution';

        // Load whitelist_dirs
        $configDirs = $this->config->get("{$baseKey}.whitelist_dirs", [
            'tests',
            'database/migrations',  // Migrations don't support constructor DI
            'database/seeders',
            'database/factories',
            'routes',               // Route files use closures without DI support
        ]);
        $this->whitelistDirs = is_array($configDirs) ? $configDirs : [];

        // Load whitelist_classes
        $configClasses = $this->config->get("{$baseKey}.whitelist_classes", [
            '*Command',
            '*Seeder',
            'DatabaseSeeder',
            '*Job',
            '*Listener',
            '*Middleware',
            '*Observer',
            '*Factory',
            '*Handler',
        ]);
        $this->whitelistClasses = is_array($configClasses) ? $configClasses : [];

        // Load whitelist_methods (non-resolution methods that are legitimate)
        $configMethods = $this->config->get("{$baseKey}.whitelist_methods", [
            // Environment checks
            'environment',
            'isLocal',
            'isProduction',
            'runningInConsole',
            'runningUnitTests',
            // Container inspection (not resolution)
            'bound',
            'has',
            'resolved',
            'isShared',
            'isAlias',
            // Method injection (legitimate pattern)
            'call',
            // Tagged services (legitimate pattern)
            'tagged',
            // Contextual binding configuration
            'when',
            'needs',
            'give',
            'giveTagged',
            'giveConfig',
            // Service decoration
            'extend',
            'alias',
            // Lifecycle hooks
            'terminating',
            'booted',
            'booting',
            // Path helpers
            'basePath',
            'configPath',
            'databasePath',
            'resourcePath',
            'storagePath',
            'publicPath',
            'langPath',
            'bootstrapPath',
            // Locale methods
            'getLocale',
            'setLocale',
            'isLocale',
            'currentLocale',
            // App info
            'version',
            'name',
            // Error handling
            'abort',
            // Testing/cleanup (usually in tests)
            'flush',
            'forgetInstance',
            'forgetInstances',
            'forgetScopedInstances',
        ]);
        $this->whitelistMethods = is_array($configMethods) ? $configMethods : [];

        // Load whitelist_services (service aliases that are legitimate to resolve)
        $configServices = $this->config->get("{$baseKey}.whitelist_services", [
            'config',
            'request',
            'log',
            'cache',
            'session',
            'view',
            'validator',
            'translator',
            'events',
            'files',
            'router',
            'db',
            'auth',
            'hash',
            'cookie',
            'queue',
            'mail',
            'url',
            'redirect',
            'blade.compiler',
            'encrypter',
        ]);
        $this->whitelistServices = is_array($configServices) ? $configServices : [];

        // Load detect_psr_get (whether to detect PSR-11 get() method)
        $detectGet = $this->config->get("{$baseKey}.detect_psr_get", false);
        $this->detectPsrGet = is_bool($detectGet) ? $detectGet : false;

        // Load detect_manual_instantiation (optional feature, disabled by default)
        $detectInstantiation = $this->config->get("{$baseKey}.detect_manual_instantiation", false);
        $this->detectManualInstantiation = is_bool($detectInstantiation) ? $detectInstantiation : false;

        // Load manual_instantiation_patterns
        $instantiationPatterns = $this->config->get("{$baseKey}.manual_instantiation_patterns", [
            '*Service',
            '*Repository',
            '*Handler',
        ]);
        $this->manualInstantiationPatterns = is_array($instantiationPatterns) ? $instantiationPatterns : [];

        // Load manual_instantiation_exclude_patterns (reduces false positives)
        $excludePatterns = $this->config->get("{$baseKey}.manual_instantiation_exclude_patterns", [
            '*DTO',
            '*Data',
            '*ValueObject',
            '*Request',
            '*Response',
            '*Entity',
            '*Model',
        ]);
        $this->manualInstantiationExcludePatterns = is_array($excludePatterns) ? $excludePatterns : [];
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration
        $this->loadConfiguration();

        $issues = [];

        foreach ($this->getPhpFiles() as $file) {
            // Skip whitelisted directories
            if ($this->isWhitelistedDirectory($file)) {
                continue;
            }

            try {
                $ast = $this->parser->parseFile($file);
            } catch (\Throwable $e) {
                // Skip files with parse errors
                continue;
            }

            if (empty($ast)) {
                continue;
            }

            // Check if service provider using already-parsed AST (avoids double parsing)
            if ($this->isServiceProviderFromAst($ast, $file)) {
                continue;
            }

            $visitor = new ServiceContainerVisitor(
                $this->whitelistClasses,
                $this->whitelistMethods,
                $this->whitelistServices,
                $this->detectPsrGet,
                $this->detectManualInstantiation,
                $this->manualInstantiationPatterns,
                $this->manualInstantiationExcludePatterns
            );
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssue(
                    message: "Manual service resolution in '{$issue['location']}': {$issue['pattern']}",
                    location: new Location($file, $issue['line']),
                    severity: $issue['severity'],
                    recommendation: $this->getRecommendation($issue['pattern'], $issue['location'], $issue['argument_type'] ?? 'unknown'),
                    metadata: [
                        'pattern' => $issue['pattern'],
                        'location' => $issue['location'],
                        'class' => $issue['class'],
                        'file' => $file,
                        'argument_type' => $issue['argument_type'] ?? 'unknown',
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('No manual service container resolution detected');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} instance(s) of manual service container resolution",
            $issues
        );
    }

    /**
     * Check if file is in a whitelisted directory.
     */
    private function isWhitelistedDirectory(string $file): bool
    {
        foreach ($this->whitelistDirs as $dir) {
            $normalizedDir = str_replace('\\', '/', $dir);
            $normalizedFile = str_replace('\\', '/', $file);

            if (str_contains($normalizedFile, "/{$normalizedDir}/") ||
                str_contains($normalizedFile, "{$normalizedDir}/")) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if AST represents a service provider by checking class extends.
     *
     * Uses PhpParser's NameResolver to resolve all class names to FQN before
     * checking, ensuring accurate detection even when using short names like
     * `extends ServiceProvider` with a `use` statement.
     *
     * Uses CloningVisitor to clone nodes before NameResolver modifies them,
     * preserving the original AST for subsequent pattern matching in analysis.
     *
     * @param  array<Node>  $ast
     */
    private function isServiceProviderFromAst(array $ast, string $file): bool
    {
        // Use CloningVisitor to clone nodes before NameResolver modifies them
        $traverser = new NodeTraverser;
        $traverser->addVisitor(new CloningVisitor);
        $traverser->addVisitor(new NameResolver);
        $resolvedAst = $traverser->traverse($ast);

        foreach ($resolvedAst as $node) {
            if ($node instanceof Stmt\Namespace_) {
                foreach ($node->stmts as $stmt) {
                    if ($stmt instanceof Stmt\Class_) {
                        if ($this->extendsServiceProvider($stmt)) {
                            return true;
                        }
                    }
                }
            } elseif ($node instanceof Stmt\Class_) {
                if ($this->extendsServiceProvider($node)) {
                    return true;
                }
            }
        }

        // Fallback to filename check for edge cases (no class found, etc.)
        return str_ends_with($file, 'ServiceProvider.php');
    }

    /**
     * Check if class extends a ServiceProvider.
     *
     * After NameResolver has been applied, parent class names should be FQN.
     * We check against known ServiceProvider FQNs and Illuminate namespace patterns.
     *
     * Note: This does NOT use a simple suffix check like `str_ends_with('ServiceProvider')`
     * because that would incorrectly skip classes like `PaymentServiceProviderFake`
     * that extend a custom `PaymentServiceProvider` (which is NOT a Laravel ServiceProvider).
     */
    private function extendsServiceProvider(Stmt\Class_ $class): bool
    {
        if ($class->extends === null) {
            return false;
        }

        $parent = ltrim($class->extends->toString(), '\\');

        // Direct FQN match against known ServiceProvider classes
        if (in_array($parent, self::SERVICE_PROVIDER_CLASSES, true)) {
            return true;
        }

        // FQN ends with \ServiceProvider (namespace separator required to avoid false positives)
        // This catches custom ServiceProvider base classes in user namespaces
        if (str_ends_with($parent, '\\ServiceProvider')) {
            return true;
        }

        // Illuminate namespace service providers (catches any Illuminate-based provider)
        if (str_starts_with($parent, 'Illuminate\\') && str_ends_with($parent, 'ServiceProvider')) {
            return true;
        }

        return false;
    }

    /**
     * Get recommendation for container resolution.
     */
    private function getRecommendation(string $pattern, string $location, string $argumentType): string
    {
        $base = "Manual service container resolution detected using '{$pattern}' in '{$location}'. ";

        // Binding-specific recommendation
        if (str_contains($pattern, 'bind') || str_contains($pattern, 'singleton') ||
            str_contains($pattern, 'instance') || str_contains($pattern, 'scoped')) {
            return $base."Container bindings should be registered in a ServiceProvider's register() method. "
                ."Example:\n\n"
                ."// In AppServiceProvider::register()\n"
                .'$this->app->bind(Interface::class, Implementation::class);';
        }

        // Manual instantiation recommendation
        if (str_contains($pattern, 'new ')) {
            return $base."Consider using constructor injection to let Laravel's container manage dependencies:\n\n"
                ."public function __construct(\n"
                ."    private readonly YourService \$service\n"
                .') {}';
        }

        // Resolution recommendation with examples
        return $base.'Manual resolution is a service locator anti-pattern that hides dependencies and makes testing difficult. '
            ."Consider using constructor injection instead:\n\n"
            ."public function __construct(\n"
            ."    private readonly YourService \$service\n"
            .") {}\n\n"
            ."Or use method injection for controller methods:\n\n"
            ."public function index(YourService \$service): Response\n"
            ."{\n"
            ."    // \$service is automatically injected\n"
            .'}';
    }
}

/**
 * Visitor to detect service container resolution.
 */
class ServiceContainerVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{pattern: string, location: string, class: string, line: int, severity: Severity, argument_type: string}>
     */
    private array $issues = [];

    /**
     * Track seen issues to avoid duplicates (key: "line:pattern").
     *
     * @var array<string, bool>
     */
    private array $seenIssues = [];

    /**
     * Current namespace.
     */
    private ?string $currentNamespace = null;

    /**
     * Current class name.
     */
    private ?string $currentClass = null;

    /**
     * Current method name.
     */
    private ?string $currentMethod = null;

    /**
     * Closure depth (closures don't support constructor DI).
     */
    private int $closureDepth = 0;

    /**
     * Namespaces where severity should be escalated to High.
     * These classes are fully DI-capable and manual resolution is almost always wrong.
     *
     * @var array<string>
     */
    private array $highSeverityNamespaces = [
        'App\\Http\\Controllers',
        'App\\Services',
        'App\\Repositories',
    ];

    /**
     * @param  array<string>  $whitelistClasses
     * @param  array<string>  $whitelistMethods
     * @param  array<string>  $whitelistServices
     * @param  array<string>  $manualInstantiationPatterns
     * @param  array<string>  $manualInstantiationExcludePatterns
     */
    public function __construct(
        private array $whitelistClasses = [],
        private array $whitelistMethods = [],
        private array $whitelistServices = [],
        private bool $detectPsrGet = false,
        private bool $detectManualInstantiation = false,
        private array $manualInstantiationPatterns = [],
        private array $manualInstantiationExcludePatterns = []
    ) {}

    public function enterNode(Node $node)
    {
        // Track namespace entry
        if ($node instanceof Stmt\Namespace_) {
            $this->currentNamespace = $node->name ? $node->name->toString() : null;

            return null;
        }

        // Track class entry
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = $node->name ? $node->name->toString() : 'Anonymous';

            return null;
        }

        // Track method entry
        if ($node instanceof Stmt\ClassMethod) {
            $this->currentMethod = $node->name->toString();

            return null;
        }

        // Track closure entry (closures don't support constructor DI)
        if ($node instanceof Expr\Closure || $node instanceof Expr\ArrowFunction) {
            $this->closureDepth++;

            return null;
        }

        // Skip if class is whitelisted
        if ($this->isWhitelistedClass()) {
            return null;
        }

        // Detect app()->make() pattern
        if ($node instanceof Expr\MethodCall) {
            // Check for app()->make()
            if ($this->isAppHelper($node->var) && $node->name instanceof Node\Identifier) {
                $methodName = $node->name->toString();

                // Skip whitelisted methods like app()->environment()
                if (in_array($methodName, $this->whitelistMethods, true)) {
                    return null;
                }

                // Build resolution methods list based on config
                $resolutionMethods = ['make', 'makeWith', 'resolve'];
                if ($this->detectPsrGet) {
                    $resolutionMethods[] = 'get';
                }

                if (in_array($methodName, $resolutionMethods, true)) {
                    // Skip resolution calls inside closures (closures don't support DI)
                    if ($this->closureDepth > 0) {
                        return null;
                    }

                    $argumentType = $this->getArgumentType($node->args);
                    $this->addIssue(
                        pattern: "app()->{$methodName}()",
                        line: $node->getStartLine(),
                        severity: $this->getSeverityForContext($argumentType),
                        argumentType: $argumentType
                    );
                }

                // Detect app()->bind() / singleton() outside service providers
                // These are ALWAYS problematic, even in closures
                if (in_array($methodName, ['bind', 'singleton', 'instance', 'scoped'], true)) {
                    $this->addIssue(
                        pattern: "app()->{$methodName}()",
                        line: $node->getStartLine(),
                        severity: Severity::High,
                        argumentType: 'binding'
                    );
                }
            }

            // Detect Container::getInstance()->make()
            if ($node->var instanceof Expr\StaticCall &&
                $node->var->class instanceof Node\Name &&
                $this->isContainerClass($node->var->class) &&
                $node->var->name instanceof Node\Identifier &&
                $node->var->name->toString() === 'getInstance') {

                if ($node->name instanceof Node\Identifier) {
                    $methodName = $node->name->toString();

                    $resolutionMethods = ['make', 'makeWith', 'resolve'];
                    if ($this->detectPsrGet) {
                        $resolutionMethods[] = 'get';
                    }

                    if (in_array($methodName, $resolutionMethods, true)) {
                        // Skip resolution calls inside closures
                        if ($this->closureDepth > 0) {
                            return null;
                        }

                        $argumentType = $this->getArgumentType($node->args);
                        $this->addIssue(
                            pattern: "Container::getInstance()->{$methodName}()",
                            line: $node->getStartLine(),
                            severity: $this->getSeverityForContext($argumentType),
                            argumentType: $argumentType
                        );
                    }
                }
            }

            // Detect $this->app->make() pattern (common in ServiceProviders but flagged elsewhere)
            if ($node->var instanceof Expr\PropertyFetch &&
                $node->var->var instanceof Expr\Variable &&
                $node->var->var->name === 'this' &&
                $node->var->name instanceof Node\Identifier &&
                $node->var->name->toString() === 'app') {

                if ($node->name instanceof Node\Identifier) {
                    $methodName = $node->name->toString();

                    // Skip whitelisted methods
                    if (in_array($methodName, $this->whitelistMethods, true)) {
                        return null;
                    }

                    $resolutionMethods = ['make', 'makeWith', 'resolve'];
                    if ($this->detectPsrGet) {
                        $resolutionMethods[] = 'get';
                    }

                    if (in_array($methodName, $resolutionMethods, true)) {
                        if ($this->closureDepth > 0) {
                            return null;
                        }

                        $argumentType = $this->getArgumentType($node->args);
                        $this->addIssue(
                            pattern: "\$this->app->{$methodName}()",
                            line: $node->getStartLine(),
                            severity: $this->getSeverityForContext($argumentType),
                            argumentType: $argumentType
                        );
                    }

                    // Detect $this->app->bind() etc. outside service providers
                    if (in_array($methodName, ['bind', 'singleton', 'instance', 'scoped'], true)) {
                        $this->addIssue(
                            pattern: "\$this->app->{$methodName}()",
                            line: $node->getStartLine(),
                            severity: Severity::High,
                            argumentType: 'binding'
                        );
                    }
                }
            }

            // Detect $container->make() / $app->make() variable patterns
            if ($node->var instanceof Expr\Variable &&
                is_string($node->var->name) &&
                in_array($node->var->name, ['container', 'app'], true)) {

                if ($node->name instanceof Node\Identifier) {
                    $methodName = $node->name->toString();

                    $resolutionMethods = ['make', 'makeWith', 'resolve'];
                    if ($this->detectPsrGet) {
                        $resolutionMethods[] = 'get';
                    }

                    if (in_array($methodName, $resolutionMethods, true)) {
                        if ($this->closureDepth > 0) {
                            return null;
                        }

                        $argumentType = $this->getArgumentType($node->args);
                        $varName = $node->var->name;
                        $this->addIssue(
                            pattern: "\${$varName}->{$methodName}()",
                            line: $node->getStartLine(),
                            severity: $this->getSeverityForContext($argumentType),
                            argumentType: $argumentType
                        );
                    }
                }
            }
        }

        // Detect App::make() static calls
        if ($node instanceof Expr\StaticCall) {
            if ($node->class instanceof Node\Name) {
                $className = $node->class->toString();

                if (($className === 'App' || str_ends_with($className, '\\App')) &&
                    $node->name instanceof Node\Identifier) {
                    $methodName = $node->name->toString();

                    $resolutionMethods = ['make', 'makeWith', 'resolve'];
                    if ($this->detectPsrGet) {
                        $resolutionMethods[] = 'get';
                    }

                    if (in_array($methodName, $resolutionMethods, true)) {
                        // Skip resolution calls inside closures
                        if ($this->closureDepth > 0) {
                            return null;
                        }

                        $argumentType = $this->getArgumentType($node->args);
                        $this->addIssue(
                            pattern: "App::{$methodName}()",
                            line: $node->getStartLine(),
                            severity: $this->getSeverityForContext($argumentType),
                            argumentType: $argumentType
                        );
                    }
                }
            }
        }

        // Detect resolve() function calls and app(Something::class)
        if ($node instanceof Expr\FuncCall) {
            if ($node->name instanceof Node\Name) {
                $functionName = $node->name->toString();

                // Detect resolve(Something::class)
                if ($functionName === 'resolve') {
                    // Skip resolution calls inside closures
                    if ($this->closureDepth > 0) {
                        return null;
                    }

                    $argumentType = $this->getArgumentType($node->args);
                    $this->addIssue(
                        pattern: 'resolve()',
                        line: $node->getStartLine(),
                        severity: $this->getSeverityForContext($argumentType),
                        argumentType: $argumentType
                    );
                }

                // Detect app(Something::class) - shorthand for app()->make()
                if ($functionName === 'app' && ! empty($node->args)) {
                    // Skip resolution calls inside closures
                    if ($this->closureDepth > 0) {
                        return null;
                    }

                    // Check if first argument is a whitelisted service alias
                    $firstArg = $node->args[0];
                    if (! $firstArg instanceof Node\VariadicPlaceholder &&
                        $firstArg->value instanceof Node\Scalar\String_) {
                        $serviceName = $firstArg->value->value;
                        if (in_array($serviceName, $this->whitelistServices, true)) {
                            return null; // Skip whitelisted service aliases
                        }
                    }

                    $argumentType = $this->getArgumentType($node->args);
                    $this->addIssue(
                        pattern: 'app()',
                        line: $node->getStartLine(),
                        severity: $this->getSeverityForContext($argumentType),
                        argumentType: $argumentType
                    );
                }
            }
        }

        // Detect manual instantiation (optional feature)
        if ($this->detectManualInstantiation && $node instanceof Expr\New_) {
            if ($node->class instanceof Node\Name) {
                $className = $node->class->toString();
                if ($this->matchesManualInstantiationPattern($className)) {
                    // Skip if inside closures (no DI available)
                    if ($this->closureDepth > 0) {
                        return null;
                    }

                    $this->addIssue(
                        pattern: "new {$className}()",
                        line: $node->getStartLine(),
                        severity: Severity::Low,
                        argumentType: 'instantiation'
                    );
                }
            }
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Clear method context on exit
        if ($node instanceof Stmt\ClassMethod) {
            $this->currentMethod = null;
        }

        // Clear class context on exit
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = null;
        }

        // Clear namespace context on exit
        if ($node instanceof Stmt\Namespace_) {
            $this->currentNamespace = null;
        }

        // Track closure exit
        if ($node instanceof Expr\Closure || $node instanceof Expr\ArrowFunction) {
            $this->closureDepth--;
        }

        return null;
    }

    /**
     * Add an issue with deduplication.
     */
    private function addIssue(string $pattern, int $line, Severity $severity, string $argumentType): void
    {
        $key = "{$line}:{$pattern}";

        // Skip if already seen (deduplication)
        if (isset($this->seenIssues[$key])) {
            return;
        }

        $this->seenIssues[$key] = true;
        $this->issues[] = [
            'pattern' => $pattern,
            'location' => $this->getLocation(),
            'class' => $this->currentClass ?? 'Unknown',
            'line' => $line,
            'severity' => $severity,
            'argument_type' => $argumentType,
        ];
    }

    /**
     * Get fully qualified class name.
     */
    private function getFullyQualifiedClassName(): ?string
    {
        if ($this->currentClass === null) {
            return null;
        }

        return $this->currentNamespace !== null
            ? $this->currentNamespace.'\\'.$this->currentClass
            : $this->currentClass;
    }

    /**
     * Check if current class is whitelisted.
     */
    private function isWhitelistedClass(): bool
    {
        if ($this->currentClass === null) {
            return false;
        }

        // Get FQN for namespace-aware matching
        $fqn = $this->getFullyQualifiedClassName();

        foreach ($this->whitelistClasses as $pattern) {
            // Check against short class name
            if ($this->matchesPattern($this->currentClass, $pattern)) {
                return true;
            }

            // Check against FQN if available
            if ($fqn !== null && $this->matchesPattern($fqn, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if class name matches pattern (supports wildcards and namespace patterns).
     */
    private function matchesPattern(string $className, string $pattern): bool
    {
        // Convert wildcard pattern to regex
        // First replace ** with placeholder for recursive match
        $pattern = str_replace('**', 'RECURSIVE_PLACEHOLDER', $pattern);
        // Then replace * with placeholder for single segment match
        $pattern = str_replace('*', 'WILDCARD_PLACEHOLDER', $pattern);
        $pattern = preg_quote($pattern, '/');
        // Convert placeholders to regex
        $pattern = str_replace('RECURSIVE_PLACEHOLDER', '.*', $pattern);
        $pattern = str_replace('WILDCARD_PLACEHOLDER', '[^\\\\]*', $pattern);
        $regex = '/^'.$pattern.'$/i';

        return (bool) preg_match($regex, $className);
    }

    /**
     * Check if expression is app() helper call.
     */
    private function isAppHelper(Node $expr): bool
    {
        if ($expr instanceof Expr\FuncCall) {
            if ($expr->name instanceof Node\Name) {
                return $expr->name->toString() === 'app';
            }
        }

        return false;
    }

    /**
     * Check if a class name refers to Laravel's Container.
     *
     * Strictly checks for Container, Illuminate\Container\Container,
     * or any class ending with \Container (namespace separator required).
     * This avoids false positives like MyContainerHelper.
     */
    private function isContainerClass(Node\Name $name): bool
    {
        $className = ltrim($name->toString(), '\\');

        return $className === 'Container'
            || $className === 'Illuminate\\Container\\Container'
            || str_ends_with($className, '\\Container');
    }

    /**
     * Get argument type from function/method args.
     *
     * @param  array<Node\Arg|Node\VariadicPlaceholder>  $args
     */
    private function getArgumentType(array $args): string
    {
        if (empty($args)) {
            return 'none';
        }

        // Skip VariadicPlaceholder
        $firstArg = $args[0];
        if ($firstArg instanceof Node\VariadicPlaceholder) {
            return 'unknown';
        }

        $firstArg = $firstArg->value;

        // Class constant (e.g., Service::class)
        if ($firstArg instanceof Expr\ClassConstFetch) {
            return 'class';
        }

        // String literal (e.g., 'service.name')
        if ($firstArg instanceof Node\Scalar\String_) {
            return 'string';
        }

        // Variable (e.g., $serviceName)
        if ($firstArg instanceof Expr\Variable) {
            return 'variable';
        }

        return 'unknown';
    }

    /**
     * Get severity based on argument type.
     */
    private function getSeverityByArgumentType(string $argumentType): Severity
    {
        return match ($argumentType) {
            'class' => Severity::Medium,      // app(Service::class) - Type-safe
            'string' => Severity::High,       // app('service') - String-based, fragile
            'variable' => Severity::Medium,   // app($var) - Dynamic
            default => Severity::Medium,      // Unknown
        };
    }

    /**
     * Get severity for the current context, escalating to High for Controllers/Services.
     *
     * Classes in Controllers, Services, and Repositories namespaces are fully DI-capable,
     * so using manual resolution is almost always a mistake and deserves higher severity.
     */
    private function getSeverityForContext(string $argumentType): Severity
    {
        $baseSeverity = $this->getSeverityByArgumentType($argumentType);

        // Don't escalate if already High or Critical
        if ($baseSeverity !== Severity::Medium) {
            return $baseSeverity;
        }

        // Escalate to High for Controllers, Services, and Repositories
        if ($this->currentNamespace !== null) {
            foreach ($this->highSeverityNamespaces as $ns) {
                if (str_starts_with($this->currentNamespace, $ns)) {
                    return Severity::High;
                }
            }
        }

        return $baseSeverity;
    }

    /**
     * Get current location string with fully qualified class name.
     */
    private function getLocation(): string
    {
        if ($this->currentMethod !== null) {
            $fqcn = $this->getFullyQualifiedClassName() ?? $this->currentClass ?? 'Unknown';

            return $fqcn.'::'.$this->currentMethod;
        }

        if ($this->currentClass !== null) {
            return $this->getFullyQualifiedClassName() ?? $this->currentClass;
        }

        return 'global scope';
    }

    /**
     * Check if class name matches manual instantiation patterns.
     *
     * Checks exclusion patterns first to avoid false positives for DTOs,
     * value objects, and other legitimate instantiations.
     */
    private function matchesManualInstantiationPattern(string $className): bool
    {
        // Check exclusions first - if it matches an exclusion, don't flag it
        foreach ($this->manualInstantiationExcludePatterns as $pattern) {
            if ($this->matchesPattern($className, $pattern)) {
                return false;
            }
        }

        // Then check inclusion patterns
        foreach ($this->manualInstantiationPatterns as $pattern) {
            if ($this->matchesPattern($className, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{pattern: string, location: string, class: string, line: int, severity: Severity, argument_type: string}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
