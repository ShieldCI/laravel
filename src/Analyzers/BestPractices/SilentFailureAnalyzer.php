<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\Node;
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
 * Detects empty catch blocks and error suppression.
 */
class SilentFailureAnalyzer extends AbstractFileAnalyzer
{
    /** @var array<string> */
    private array $whitelistDirs = [];

    /** @var array<string> */
    private array $whitelistClasses = [];

    /** @var array<string> */
    private array $whitelistExceptions = [];

    /** @var array<string> */
    private array $whitelistErrorSuppressionFunctions = [];

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {
        $this->loadConfiguration();
    }

    private function loadConfiguration(): void
    {
        $baseKey = 'shieldci.analyzers.best-practices.silent-failure';

        // Load whitelisted directories (tests, seeders, etc.)
        $configDirs = $this->config->get("{$baseKey}.whitelist_dirs", [
            'tests',
            'database/seeders',
            'database/factories',
        ]);
        $this->whitelistDirs = is_array($configDirs) ? $configDirs : [];

        // Load whitelisted classes (test classes, seeders, etc.)
        $configClasses = $this->config->get("{$baseKey}.whitelist_classes", [
            '*Test',
            '*TestCase',
            '*Seeder',
            'DatabaseSeeder',
        ]);
        $this->whitelistClasses = is_array($configClasses) ? $configClasses : [];

        // Load whitelisted exception types (expected exceptions that can be safely caught)
        $configExceptions = $this->config->get("{$baseKey}.whitelist_exceptions", [
            'ModelNotFoundException',
            'NotFoundException',
            'NotFoundHttpException',
            'ValidationException',
        ]);
        $this->whitelistExceptions = is_array($configExceptions) ? $configExceptions : [];

        // Load whitelisted functions for error suppression (legitimate uses of @)
        $configFunctions = $this->config->get("{$baseKey}.whitelist_error_suppression_functions", [
            'unlink',
            'fopen',
            'file_get_contents',
            'mkdir',
            'rmdir',
        ]);
        $this->whitelistErrorSuppressionFunctions = is_array($configFunctions) ? $configFunctions : [];
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'silent-failure',
            name: 'Silent Failure Analyzer',
            description: 'Detects empty catch blocks and error suppression that hide failures',
            category: Category::BestPractices,
            severity: Severity::Medium,
            tags: ['laravel', 'exceptions', 'error-handling', 'debugging', 'monitoring'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/silent-failure',
            timeToFix: 20
        );
    }

    private function isWhitelistedDirectory(string $file): bool
    {
        foreach ($this->whitelistDirs as $dir) {
            $normalizedDir = str_replace('\\', '/', $dir);
            $normalizedFile = str_replace('\\', '/', $file);

            if (str_contains($normalizedFile, '/'.$normalizedDir.'/') ||
                str_starts_with($normalizedFile, $normalizedDir.'/')) {
                return true;
            }
        }

        return false;
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $phpFiles = $this->getPhpFiles();

        foreach ($phpFiles as $file) {
            // Skip whitelisted directories
            if ($this->isWhitelistedDirectory($file)) {
                continue;
            }

            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new SilentFailureVisitor(
                    $this->whitelistClasses,
                    $this->whitelistExceptions,
                    $this->whitelistErrorSuppressionFunctions
                );
                $traverser = new NodeTraverser;
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getIssues() as $issue) {
                    $issues[] = $this->createIssue(
                        message: $issue['message'],
                        location: new Location($this->getRelativePath($file), $issue['line']),
                        severity: $issue['severity'],
                        recommendation: $issue['recommendation'],
                        code: $issue['code'] ?? null,
                    );
                }
            } catch (\Throwable $e) {
                continue;
            }
        }

        if (empty($issues)) {
            return $this->passed('No silent failures detected');
        }

        return $this->failed(
            sprintf('Found %d silent failure(s)', count($issues)),
            $issues
        );
    }
}

class SilentFailureVisitor extends NodeVisitorAbstract
{
    private array $issues = [];

    private ?string $currentClass = null;

    /**
     * @param  array<string>  $whitelistClasses
     * @param  array<string>  $whitelistExceptions
     * @param  array<string>  $whitelistErrorSuppressionFunctions
     */
    public function __construct(
        private array $whitelistClasses = [],
        private array $whitelistExceptions = [],
        private array $whitelistErrorSuppressionFunctions = []
    ) {}

    public function enterNode(Node $node): ?Node
    {
        // Track current class name
        if ($node instanceof Node\Stmt\Class_) {
            $this->currentClass = $node->name?->toString();
        }

        // Skip whitelisted classes
        if ($this->isWhitelistedClass($this->currentClass)) {
            return null;
        }

        // Check for empty catch blocks
        if ($node instanceof Node\Stmt\TryCatch) {
            foreach ($node->catches as $catch) {
                // Get exception type
                $exceptionType = null;
                if (! empty($catch->types)) {
                    $exceptionType = $catch->types[0]->toString();
                }

                // Skip whitelisted exception types
                if ($exceptionType && $this->isWhitelistedException($exceptionType)) {
                    continue;
                }

                if (empty($catch->stmts)) {
                    $this->issues[] = [
                        'message' => 'Empty catch block silently swallows exceptions',
                        'line' => $catch->getLine(),
                        'severity' => Severity::High,
                        'recommendation' => 'Never use empty catch blocks. At minimum, log the exception. If you truly need to ignore an exception, add a comment explaining why',
                        'code' => null,
                    ];
                } else {
                    // Check if catch block has logging, reporting, or rethrow
                    $hasLogging = false;
                    $hasRethrow = false;

                    foreach ($catch->stmts as $stmt) {
                        // Check for logging or error reporting
                        if ($this->isLoggingOrReportingStatement($stmt)) {
                            $hasLogging = true;
                        }

                        // Check for rethrow (statement form)
                        if ($stmt instanceof Node\Stmt\Throw_) {
                            $hasRethrow = true;
                        }

                        // Check for rethrow (expression form in PHP 8)
                        if ($stmt instanceof Node\Stmt\Expression &&
                            $stmt->expr instanceof Node\Expr\Throw_) {
                            $hasRethrow = true;
                        }

                        // Check for return/continue/break with value (graceful fallback)
                        if ($this->hasGracefulFallback($stmt)) {
                            $hasLogging = true; // Treat as handled
                        }
                    }

                    if (! $hasLogging && ! $hasRethrow) {
                        $this->issues[] = [
                            'message' => 'Catch block does not log exception or rethrow',
                            'line' => $catch->getLine(),
                            'severity' => Severity::Medium,
                            'recommendation' => 'Always log caught exceptions using Log::error(), report(), or rethrow them. Silent failures make debugging extremely difficult',
                            'code' => null,
                        ];
                    }
                }
            }
        }

        // Check for error suppression operator (@)
        if ($node instanceof Node\Expr\ErrorSuppress) {
            // Check if it's a whitelisted function call
            if ($this->isWhitelistedErrorSuppression($node->expr)) {
                return null;
            }

            $this->issues[] = [
                'message' => 'Error suppression operator (@) hides errors',
                'line' => $node->getLine(),
                'severity' => Severity::Medium,
                'recommendation' => 'Avoid using @ operator. Handle errors explicitly with try-catch or check return values. Error suppression makes debugging difficult',
                'code' => null,
            ];
        }

        return null;
    }

    private function isLoggingOrReportingStatement(Node $stmt): bool
    {
        if (! $stmt instanceof Node\Stmt\Expression) {
            return false;
        }

        $expr = $stmt->expr;

        // Check for Log::* calls (Log::error, Log::warning, etc.)
        if ($expr instanceof Node\Expr\StaticCall) {
            if ($expr->class instanceof Node\Name && $expr->class->toString() === 'Log') {
                return true;
            }
        }

        // Check for function calls
        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            $functionName = $expr->name->toString();

            // Laravel error reporting helpers
            if (in_array($functionName, ['logger', 'report', 'rescue'], true)) {
                return true;
            }
        }

        // Check for method calls
        if ($expr instanceof Node\Expr\MethodCall && $expr->name instanceof Node\Identifier) {
            $method = $expr->name->toString();

            // Logger methods (PSR-3)
            if (in_array($method, ['error', 'warning', 'info', 'debug', 'log', 'critical', 'alert', 'emergency', 'notice'], true)) {
                return true;
            }

            // Error reporting service methods (Sentry, Bugsnag, etc.)
            if (in_array($method, ['captureException', 'notifyException', 'report'], true)) {
                return true;
            }
        }

        // Check for static calls to error reporting services
        if ($expr instanceof Node\Expr\StaticCall && $expr->class instanceof Node\Name) {
            $className = $expr->class->toString();

            // Sentry: \Sentry\captureException()
            if (str_contains($className, 'Sentry')) {
                return true;
            }

            // Bugsnag: Bugsnag::notifyException()
            if (str_contains($className, 'Bugsnag')) {
                return true;
            }

            // Raygun, Rollbar, etc.
            if (in_array($className, ['Raygun', 'Rollbar', 'Honeybadger'], true)) {
                return true;
            }
        }

        // Check for namespace function calls like \Sentry\captureException()
        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name\FullyQualified) {
            $functionName = $expr->name->toString();

            if (str_contains($functionName, 'Sentry\\captureException') ||
                str_contains($functionName, 'Bugsnag\\') ||
                str_contains($functionName, 'report')) {
                return true;
            }
        }

        return false;
    }

    private function hasGracefulFallback(Node $stmt): bool
    {
        // Check for return with a value (graceful fallback)
        if ($stmt instanceof Node\Stmt\Return_ && $stmt->expr !== null) {
            return true;
        }

        // Check for assignment (setting a default value)
        if ($stmt instanceof Node\Stmt\Expression &&
            $stmt->expr instanceof Node\Expr\Assign) {
            return true;
        }

        return false;
    }

    private function isWhitelistedErrorSuppression(Node $expr): bool
    {
        if (! $expr instanceof Node\Expr\FuncCall) {
            return false;
        }

        if (! $expr->name instanceof Node\Name) {
            return false;
        }

        $functionName = $expr->name->toString();

        foreach ($this->whitelistErrorSuppressionFunctions as $allowed) {
            if ($functionName === $allowed) {
                return true;
            }
        }

        return false;
    }

    protected function matchesPattern(string $className, string $pattern): bool
    {
        // Convert wildcard pattern to regex
        $pattern = str_replace('*', 'WILDCARD_PLACEHOLDER', $pattern);
        $pattern = preg_quote($pattern, '/');
        $pattern = str_replace('WILDCARD_PLACEHOLDER', '.*', $pattern);
        $regex = '/^'.$pattern.'$/i';

        return (bool) preg_match($regex, $className);
    }

    private function isWhitelistedClass(?string $className): bool
    {
        if ($className === null) {
            return false;
        }

        foreach ($this->whitelistClasses as $pattern) {
            if ($this->matchesPattern($className, $pattern)) {
                return true;
            }
        }

        return false;
    }

    private function isWhitelistedException(string $exceptionType): bool
    {
        foreach ($this->whitelistExceptions as $pattern) {
            if ($this->matchesPattern($exceptionType, $pattern)) {
                return true;
            }
        }

        return false;
    }

    public function getIssues(): array
    {
        return $this->issues;
    }
}
