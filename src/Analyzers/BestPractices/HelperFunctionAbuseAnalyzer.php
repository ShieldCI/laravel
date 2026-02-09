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

/**
 * Detects excessive use of Laravel helper functions.
 *
 * Checks for:
 * - Multiple helper function calls in same class
 * - Threshold violations
 * - Recommends proper dependency injection
 * - Controllers and services primarily affected
 *
 * Whitelisted contexts (where helper usage is acceptable):
 * - Service Providers: Need helpers for bootstrapping
 * - Console Commands: Often need dynamic resolution
 * - Tests: Flexibility for testing
 * - Seeders: Need service resolution for data generation
 * - Migrations: Don't support constructor DI
 *
 * Helper categories:
 * - DEPENDENCY_HIDING_HELPERS: Counted (hide real dependencies)
 * - DEBUG_HELPERS: Not counted (handled by DebugModeAnalyzer)
 * - LOW_PRIORITY_HELPERS: Not counted (simple utilities, rarely abused)
 *
 * Note: Utility helpers (collect, tap, value, optional, now, today, etc.)
 * are intentionally excluded as they don't hide dependencies.
 *
 * Note: Helper calls inside closures and arrow functions are counted,
 * as they still represent hidden dependencies within the class.
 */
class HelperFunctionAbuseAnalyzer extends AbstractFileAnalyzer
{
    public const DEFAULT_THRESHOLD = 5;

    /**
     * Helpers that HIDE dependencies (counted by default).
     * These create implicit dependencies that make testing difficult.
     *
     * @var array<string>
     */
    public const DEPENDENCY_HIDING_HELPERS = [
        'app', 'auth', 'cache', 'config', 'cookie', 'event', 'logger', 'old',
        'redirect', 'request', 'response', 'route', 'session', 'storage_path',
        'url', 'view', 'abort', 'abort_if', 'abort_unless', 'dispatch',
        'info', 'policy', 'resolve', 'validator', 'report',
    ];

    /**
     * Debug helpers - handled by DebugModeAnalyzer.
     *
     * @var array<string>
     */
    public const DEBUG_HELPERS = ['dd', 'dump'];

    /**
     * Simple crypto/utility helpers - rarely abused.
     *
     * @var array<string>
     */
    public const LOW_PRIORITY_HELPERS = ['bcrypt'];

    /**
     * All helpers combined (for backward compatibility).
     *
     * @var array<string>
     */
    public const DEFAULT_HELPER_FUNCTIONS = [
        'app', 'auth', 'cache', 'config', 'cookie', 'event', 'logger', 'old',
        'redirect', 'request', 'response', 'route', 'session', 'storage_path',
        'url', 'view', 'abort', 'abort_if', 'abort_unless', 'bcrypt',
        'collect', 'dd', 'dispatch', 'info', 'now', 'optional', 'policy',
        'resolve', 'retry', 'tap', 'throw_if', 'throw_unless', 'today',
        'validator', 'value', 'report',
    ];

    /** @var array<string> Default directories to whitelist */
    private const DEFAULT_WHITELIST_DIRS = [
        'tests',
        'database/migrations',
        'database/seeders',
        'database/factories',
    ];

    /** @var array<string> Default class patterns to whitelist */
    private const DEFAULT_WHITELIST_CLASSES = [
        '*ServiceProvider',
        '*Command',
        '*Seeder',
        '*Test',
        '*TestCase',
    ];

    private int $threshold;

    /** @var array<string> */
    private array $helperFunctions;

    /** @var array<string> */
    private array $whitelistDirs;

    /** @var array<string> */
    private array $whitelistClasses;

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'helper-function-abuse',
            name: 'Helper Function Abuse Analyzer',
            description: 'Detects excessive use of Laravel helper functions that hide dependencies and hinder testing',
            category: Category::BestPractices,
            severity: Severity::Low,
            tags: ['testability', 'dependency-injection', 'laravel', 'helpers', 'code-quality'],
            timeToFix: 25
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration from config file (best-practices.helper-function-abuse)
        $analyzerConfig = $this->config->get('shieldci.analyzers.best-practices.helper-function-abuse', []);
        $analyzerConfig = is_array($analyzerConfig) ? $analyzerConfig : [];

        $configThreshold = $analyzerConfig['threshold'] ?? self::DEFAULT_THRESHOLD;
        $this->threshold = is_int($configThreshold) && $configThreshold >= 1
            ? $configThreshold
            : self::DEFAULT_THRESHOLD;

        // Load whitelist configuration
        $configDirs = $analyzerConfig['whitelist_dirs'] ?? self::DEFAULT_WHITELIST_DIRS;
        $this->whitelistDirs = is_array($configDirs) ? $configDirs : self::DEFAULT_WHITELIST_DIRS;

        $configClasses = $analyzerConfig['whitelist_classes'] ?? self::DEFAULT_WHITELIST_CLASSES;
        $this->whitelistClasses = is_array($configClasses) ? $configClasses : self::DEFAULT_WHITELIST_CLASSES;

        // Build helper list - backward compatible with custom helper_functions config
        $helperFuncs = $analyzerConfig['helper_functions'] ?? null;
        $this->helperFunctions = (is_array($helperFuncs) && ! empty($helperFuncs))
            ? $helperFuncs
            : self::DEPENDENCY_HIDING_HELPERS;

        $issues = [];
        $threshold = $this->threshold;
        $helpers = $this->helperFunctions;

        foreach ($this->getPhpFiles() as $file) {
            // Skip whitelisted directories
            if ($this->isWhitelistedDirectory($file)) {
                continue;
            }

            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new HelperFunctionVisitor($helpers, $threshold, $this->whitelistClasses);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssueWithSnippet(
                    message: "Class '{$issue['class']}' uses {$issue['count']} helper function calls (threshold: {$threshold})",
                    filePath: $file,
                    lineNumber: $issue['line'],
                    severity: $this->getSeverityForCount($issue['count'], $threshold),
                    recommendation: $this->getRecommendation($issue['class'], $issue['helpers'], $issue['count']),
                    metadata: [
                        'class' => $issue['class'],
                        'helpers' => $issue['helpers'],
                        'count' => $issue['count'],
                        'threshold' => $threshold,
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('No excessive helper function usage detected');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} class(es) with excessive helper function usage",
            $issues
        );
    }

    /**
     * Get severity based on helper count.
     */
    private function getSeverityForCount(int $count, int $threshold): Severity
    {
        $excess = $count - $threshold;

        // 20+ helpers over threshold is a serious issue
        if ($excess >= 20) {
            return Severity::High;
        }

        // 10-19 helpers over threshold is moderate
        if ($excess >= 10) {
            return Severity::Medium;
        }

        // Just over threshold is low priority
        return Severity::Low;
    }

    /**
     * Get recommendation for helper function abuse.
     *
     * @param  array<string, int>  $helpers
     */
    private function getRecommendation(string $class, array $helpers, int $count): string
    {
        $helperList = [];
        arsort($helpers);
        foreach ($helpers as $helper => $usageCount) {
            $helperList[] = "{$helper}() ({$usageCount}x)";
        }
        $helperString = implode(', ', $helperList);

        return "Class '{$class}' uses {$count} helper function calls: {$helperString}. "
            .'While Laravel helpers are convenient, excessive use hides dependencies and makes unit testing difficult. '
            .'Consider injecting dependencies via constructor (e.g., Config, Request, Session contracts) instead of using global helpers.';
    }

    /**
     * Check if file is in a whitelisted directory.
     */
    private function isWhitelistedDirectory(string $file): bool
    {
        $normalizedFile = str_replace('\\', '/', $file);

        foreach ($this->whitelistDirs as $dir) {
            $normalizedDir = trim(str_replace('\\', '/', $dir), '/');

            // Match complete path segments: /tests/ or starts with tests/ or ends with /tests
            if (preg_match('#(?:^|/)'.preg_quote($normalizedDir, '#').'(?:/|$)#', $normalizedFile)) {
                return true;
            }
        }

        return false;
    }
}

/**
 * Visitor to track helper function usage.
 *
 * Uses a class stack pattern to properly handle nested classes (including anonymous classes).
 * Helper calls inside anonymous classes are attributed to the anonymous class, not the outer class.
 */
class HelperFunctionVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{class: string, helpers: array<string, int>, count: int, line: int}>
     */
    private array $issues = [];

    /**
     * Stack to track nested class contexts.
     * Each entry contains: class name (null for anonymous), start line, and helper counts.
     *
     * @var array<int, array{class: string|null, line: int, helpers: array<string, int>}>
     */
    private array $classStack = [];

    /**
     * @param  array<string>  $helperFunctions
     * @param  array<string>  $whitelistClasses
     */
    public function __construct(
        private array $helperFunctions,
        private int $threshold,
        private array $whitelistClasses = []
    ) {}

    public function enterNode(Node $node)
    {
        // Track class entry (including anonymous classes)
        if ($node instanceof Stmt\Class_) {
            $className = $node->name?->toString();  // null for anonymous

            $this->classStack[] = [
                'class' => $className,
                'line' => $node->getStartLine(),
                'helpers' => [],
            ];

            return null;
        }

        // Track trait entry
        if ($node instanceof Stmt\Trait_) {
            $this->classStack[] = [
                'class' => $node->name?->toString(),
                'line' => $node->getStartLine(),
                'helpers' => [],
            ];

            return null;
        }

        // Only track helpers inside classes or traits
        if (empty($this->classStack)) {
            return null;
        }

        // Detect helper function calls
        if ($node instanceof Expr\FuncCall) {
            if ($node->name instanceof Node\Name) {
                $functionName = $node->name->toString();

                // Check if it's a tracked helper - attribute to innermost class
                if (in_array($functionName, $this->helperFunctions, true)) {
                    $index = array_key_last($this->classStack);
                    if (! isset($this->classStack[$index]['helpers'][$functionName])) {
                        $this->classStack[$index]['helpers'][$functionName] = 0;
                    }
                    $this->classStack[$index]['helpers'][$functionName]++;
                }
            }
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Check helper count on class or trait exit
        if ($node instanceof Stmt\Class_ || $node instanceof Stmt\Trait_) {
            if (empty($this->classStack)) {
                return null;
            }

            $context = array_pop($this->classStack);

            // Skip anonymous classes (class === null)
            if ($context['class'] === null) {
                return null;
            }

            // Skip whitelisted classes (e.g., ServiceProviders, Commands, Tests)
            if ($this->isWhitelistedClass($context['class'])) {
                return null;
            }

            $helperCount = array_sum($context['helpers']);

            if ($helperCount > $this->threshold) {
                $this->issues[] = [
                    'class' => $context['class'],
                    'helpers' => $context['helpers'],
                    'count' => $helperCount,
                    'line' => $context['line'],
                ];
            }
        }

        return null;
    }

    /**
     * Check if given class matches a whitelisted pattern.
     */
    private function isWhitelistedClass(string $className): bool
    {
        foreach ($this->whitelistClasses as $pattern) {
            if ($this->matchesPattern($className, $pattern)) {
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
        $pattern = str_replace('*', 'WILDCARD_PLACEHOLDER', $pattern);
        $pattern = preg_quote($pattern, '/');
        $pattern = str_replace('WILDCARD_PLACEHOLDER', '.*', $pattern);
        $regex = '/^'.$pattern.'$/i';

        return (bool) preg_match($regex, $className);
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{class: string, helpers: array<string, int>, count: int, line: int}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
