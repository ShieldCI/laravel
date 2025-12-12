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
 */
class HelperFunctionAbuseAnalyzer extends AbstractFileAnalyzer
{
    public const DEFAULT_THRESHOLD = 5;

    /** @var array<string> */
    public const DEFAULT_HELPER_FUNCTIONS = [
        'app', 'auth', 'cache', 'config', 'cookie', 'event', 'logger', 'old',
        'redirect', 'request', 'response', 'route', 'session', 'storage_path',
        'url', 'view', 'abort', 'abort_if', 'abort_unless', 'bcrypt',
        'collect', 'dd', 'dispatch', 'info', 'now', 'optional', 'policy',
        'resolve', 'retry', 'tap', 'throw_if', 'throw_unless', 'today',
        'validator', 'value', 'report',
    ];

    private int $threshold;

    /** @var array<string> */
    private array $helperFunctions;

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
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/helper-function-abuse',
            timeToFix: 25
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration from config file (best_practices.helper-function-abuse)
        $analyzerConfig = $this->config->get('shieldci.analyzers.best_practices.helper-function-abuse', []);
        $analyzerConfig = is_array($analyzerConfig) ? $analyzerConfig : [];

        $this->threshold = $analyzerConfig['threshold'] ?? self::DEFAULT_THRESHOLD;
        $helperFuncs = $analyzerConfig['helper_functions'] ?? null;
        $this->helperFunctions = (is_array($helperFuncs) && ! empty($helperFuncs))
            ? $helperFuncs
            : self::DEFAULT_HELPER_FUNCTIONS;

        $issues = [];
        $threshold = $this->threshold;
        $helpers = $this->helperFunctions;

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new HelperFunctionVisitor($helpers, $threshold);
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
        foreach ($helpers as $helper => $usageCount) {
            $helperList[] = "{$helper}() ({$usageCount}x)";
        }
        $helperString = implode(', ', $helperList);

        return "Class '{$class}' uses {$count} helper function calls: {$helperString}. While Laravel helpers are convenient, excessive use hides dependencies and makes unit testing difficult. ";
    }
}

/**
 * Visitor to track helper function usage.
 */
class HelperFunctionVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{class: string, helpers: array<string, int>, count: int, line: int}>
     */
    private array $issues = [];

    /**
     * Current class name.
     */
    private ?string $currentClass = null;

    /**
     * Current class start line.
     */
    private int $currentClassLine = 0;

    /**
     * Helper function calls in current class.
     *
     * @var array<string, int>
     */
    private array $currentHelpers = [];

    /**
     * @param  array<string>  $helperFunctions
     */
    public function __construct(
        private array $helperFunctions,
        private int $threshold
    ) {}

    public function enterNode(Node $node)
    {
        // Track class entry
        if ($node instanceof Stmt\Class_) {
            // Skip anonymous classes
            if ($node->name === null) {
                return null;
            }

            $this->currentClass = $node->name->toString();
            $this->currentClassLine = $node->getStartLine();
            $this->currentHelpers = [];

            return null;
        }

        // Track trait entry
        if ($node instanceof Stmt\Trait_) {
            if ($node->name === null) {
                return null;
            }

            $this->currentClass = $node->name->toString();
            $this->currentClassLine = $node->getStartLine();
            $this->currentHelpers = [];

            return null;
        }

        // Only track inside classes or traits
        if ($this->currentClass === null) {
            return null;
        }

        // Detect helper function calls
        if ($node instanceof Expr\FuncCall) {
            if ($node->name instanceof Node\Name) {
                $functionName = $node->name->toString();

                // Check if it's a tracked helper
                if (in_array($functionName, $this->helperFunctions, true)) {
                    if (! isset($this->currentHelpers[$functionName])) {
                        $this->currentHelpers[$functionName] = 0;
                    }
                    $this->currentHelpers[$functionName]++;
                }
            }
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Check helper count on class or trait exit
        if ($node instanceof Stmt\Class_ || $node instanceof Stmt\Trait_) {
            // Skip anonymous classes
            if ($node instanceof Stmt\Class_ && $node->name === null) {
                return null;
            }

            $helperCount = array_sum($this->currentHelpers);

            if ($helperCount > $this->threshold) {
                $this->issues[] = [
                    'class' => $this->currentClass ?? 'Unknown',
                    'helpers' => $this->currentHelpers,
                    'count' => $helperCount,
                    'line' => $this->currentClassLine,
                ];
            }

            // Reset state
            $this->currentClass = null;
            $this->currentClassLine = 0;
            $this->currentHelpers = [];
        }

        return null;
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
