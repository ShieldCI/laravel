<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeTraverser;
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
 * Configuration:
 * - whitelist_dirs: Directories to skip (e.g., tests, database/seeders)
 * - whitelist_classes: Class name patterns to skip (e.g., *Command, *Seeder)
 * - whitelist_methods: Methods to skip (e.g., environment, isLocal)
 */
class ServiceContainerResolutionAnalyzer extends AbstractFileAnalyzer
{
    /** @var array<string> */
    private array $whitelistDirs = [];

    /** @var array<string> */
    private array $whitelistClasses = [];

    /** @var array<string> */
    private array $whitelistMethods = [];

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
            'database/seeders',
            'database/factories',
        ]);
        $this->whitelistDirs = is_array($configDirs) ? $configDirs : [];

        // Load whitelist_classes
        $configClasses = $this->config->get("{$baseKey}.whitelist_classes", [
            '*Command',
            '*Seeder',
            'DatabaseSeeder',
        ]);
        $this->whitelistClasses = is_array($configClasses) ? $configClasses : [];

        // Load whitelist_methods
        $configMethods = $this->config->get("{$baseKey}.whitelist_methods", [
            'environment',
            'isLocal',
            'isProduction',
            'runningInConsole',
            'runningUnitTests',
        ]);
        $this->whitelistMethods = is_array($configMethods) ? $configMethods : [];
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

            // Skip service providers - they legitimately use container
            if ($this->isServiceProvider($file)) {
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

            $visitor = new ServiceContainerVisitor($this->whitelistClasses, $this->whitelistMethods);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssue(
                    message: "Manual service resolution in '{$issue['location']}': {$issue['pattern']}",
                    location: new Location($file, $issue['line']),
                    severity: $issue['severity'],
                    recommendation: $this->getRecommendation($issue['pattern'], $issue['location']),
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
     * Check if file is a service provider by parsing AST and checking extends.
     */
    private function isServiceProvider(string $file): bool
    {
        try {
            $ast = $this->parser->parseFile($file);
        } catch (\Throwable $e) {
            // Can't parse, fallback to filename check
            return str_ends_with($file, 'ServiceProvider.php');
        }

        if (empty($ast)) {
            return str_ends_with($file, 'ServiceProvider.php');
        }

        foreach ($ast as $node) {
            if ($node instanceof Stmt\Namespace_) {
                foreach ($node->stmts as $stmt) {
                    if ($stmt instanceof Stmt\Class_) {
                        if ($stmt->extends instanceof Node\Name) {
                            $parent = $stmt->extends->toString();
                            if (str_contains($parent, 'ServiceProvider')) {
                                return true;
                            }
                        }
                    }
                }
            } elseif ($node instanceof Stmt\Class_) {
                if ($node->extends instanceof Node\Name) {
                    $parent = $node->extends->toString();
                    if (str_contains($parent, 'ServiceProvider')) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Get recommendation for container resolution.
     */
    private function getRecommendation(string $pattern, string $location): string
    {
        return "Found manual service container resolution using '{$pattern}' in '{$location}'. Manual resolution is a service locator anti-pattern that hides dependencies and makes testing difficult. ";
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
     * Current class name.
     */
    private ?string $currentClass = null;

    /**
     * Current method name.
     */
    private ?string $currentMethod = null;

    /**
     * @param  array<string>  $whitelistClasses
     * @param  array<string>  $whitelistMethods
     */
    public function __construct(
        private array $whitelistClasses = [],
        private array $whitelistMethods = []
    ) {}

    public function enterNode(Node $node)
    {
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

                if (in_array($methodName, ['make', 'makeWith', 'resolve', 'get'], true)) {
                    $argumentType = $this->getArgumentType($node->args);
                    $this->issues[] = [
                        'pattern' => "app()->{$methodName}()",
                        'location' => $this->getLocation(),
                        'class' => $this->currentClass ?? 'Unknown',
                        'line' => $node->getStartLine(),
                        'severity' => $this->getSeverityByArgumentType($argumentType),
                        'argument_type' => $argumentType,
                    ];
                }

                // Detect app()->bind() / singleton() outside service providers
                if (in_array($methodName, ['bind', 'singleton', 'instance', 'scoped'], true)) {
                    $this->issues[] = [
                        'pattern' => "app()->{$methodName}()",
                        'location' => $this->getLocation(),
                        'class' => $this->currentClass ?? 'Unknown',
                        'line' => $node->getStartLine(),
                        'severity' => Severity::High,
                        'argument_type' => 'binding',
                    ];
                }
            }

            // Detect Container::getInstance()->make()
            if ($node->var instanceof Expr\StaticCall &&
                $node->var->class instanceof Node\Name &&
                str_contains($node->var->class->toString(), 'Container') &&
                $node->var->name instanceof Node\Identifier &&
                $node->var->name->toString() === 'getInstance') {

                if ($node->name instanceof Node\Identifier) {
                    $methodName = $node->name->toString();
                    if (in_array($methodName, ['make', 'makeWith', 'resolve', 'get'], true)) {
                        $argumentType = $this->getArgumentType($node->args);
                        $this->issues[] = [
                            'pattern' => "Container::getInstance()->{$methodName}()",
                            'location' => $this->getLocation(),
                            'class' => $this->currentClass ?? 'Unknown',
                            'line' => $node->getStartLine(),
                            'severity' => $this->getSeverityByArgumentType($argumentType),
                            'argument_type' => $argumentType,
                        ];
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
                    if (in_array($methodName, ['make', 'makeWith', 'resolve', 'get'], true)) {
                        $argumentType = $this->getArgumentType($node->args);
                        $this->issues[] = [
                            'pattern' => "App::{$methodName}()",
                            'location' => $this->getLocation(),
                            'class' => $this->currentClass ?? 'Unknown',
                            'line' => $node->getStartLine(),
                            'severity' => $this->getSeverityByArgumentType($argumentType),
                            'argument_type' => $argumentType,
                        ];
                    }
                }
            }
        }

        // Detect resolve() function calls
        if ($node instanceof Expr\FuncCall) {
            if ($node->name instanceof Node\Name) {
                $functionName = $node->name->toString();

                // Detect resolve(Something::class)
                if ($functionName === 'resolve') {
                    $argumentType = $this->getArgumentType($node->args);
                    $this->issues[] = [
                        'pattern' => 'resolve()',
                        'location' => $this->getLocation(),
                        'class' => $this->currentClass ?? 'Unknown',
                        'line' => $node->getStartLine(),
                        'severity' => $this->getSeverityByArgumentType($argumentType),
                        'argument_type' => $argumentType,
                    ];
                }

                // Detect app(Something::class) - shorthand for app()->make()
                if ($functionName === 'app' && ! empty($node->args)) {
                    $argumentType = $this->getArgumentType($node->args);
                    $this->issues[] = [
                        'pattern' => 'app()',
                        'location' => $this->getLocation(),
                        'class' => $this->currentClass ?? 'Unknown',
                        'line' => $node->getStartLine(),
                        'severity' => $this->getSeverityByArgumentType($argumentType),
                        'argument_type' => $argumentType,
                    ];
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

        return null;
    }

    /**
     * Check if current class is whitelisted.
     */
    private function isWhitelistedClass(): bool
    {
        if ($this->currentClass === null) {
            return false;
        }

        foreach ($this->whitelistClasses as $pattern) {
            if ($this->matchesPattern($this->currentClass, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if class name matches pattern (supports wildcards).
     */
    private function matchesPattern(string $className, string $pattern): bool
    {
        // Convert wildcard pattern to regex
        // First replace * with placeholder, then preg_quote, then convert placeholder to .*
        $pattern = str_replace('*', 'WILDCARD_PLACEHOLDER', $pattern);
        $pattern = preg_quote($pattern, '/');
        $pattern = str_replace('WILDCARD_PLACEHOLDER', '.*', $pattern);
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
     * Get current location string.
     */
    private function getLocation(): string
    {
        if ($this->currentMethod !== null) {
            return ($this->currentClass ?? 'Unknown').'::'.$this->currentMethod;
        }

        if ($this->currentClass !== null) {
            return $this->currentClass;
        }

        return 'global scope';
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
