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

    /** @var array<string> */
    private array $whitelistErrorSuppressionStaticMethods = [];

    /** @var array<string> */
    private array $whitelistErrorSuppressionInstanceMethods = [];

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

        // Load whitelisted static methods for error suppression (e.g., @Storage::delete())
        $configStaticMethods = $this->config->get("{$baseKey}.whitelist_error_suppression_static_methods", [
            'Storage::delete',
            'Storage::deleteDirectory',
            'File::delete',
            'File::deleteDirectory',
        ]);
        $this->whitelistErrorSuppressionStaticMethods = is_array($configStaticMethods) ? $configStaticMethods : [];

        // Load whitelisted instance methods for error suppression (e.g., @$file->delete())
        $configInstanceMethods = $this->config->get("{$baseKey}.whitelist_error_suppression_instance_methods", [
            'delete',
            'close',
            'unlink',
        ]);
        $this->whitelistErrorSuppressionInstanceMethods = is_array($configInstanceMethods) ? $configInstanceMethods : [];
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
                    $this->whitelistErrorSuppressionFunctions,
                    $this->whitelistErrorSuppressionStaticMethods,
                    $this->whitelistErrorSuppressionInstanceMethods
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

    private int $whitelistedClassDepth = 0;

    private int $catchBlockDepth = 0;

    /** @var array<string> Exception types too broad to whitelist in unions */
    private array $broadExceptionTypes = ['Throwable', 'Exception', 'Error'];

    /** @var array<string> Variable name patterns that indicate fallback intent */
    private array $fallbackVariablePatterns = [
        'default', 'fallback', 'backup', 'cached', 'empty', 'placeholder', 'alternative',
    ];

    /** @var array<string> Method name patterns that indicate fallback intent */
    private array $fallbackMethodPatterns = [
        'default', 'fallback', 'backup', 'empty', 'cached',
        'retry', 'attempt', 'recover', 'restore',
    ];

    /** @var array<string> Static class names commonly used for fallback operations */
    private array $fallbackStaticClasses = [
        'Cache', 'Config', 'Session', 'Storage', 'Redis',
    ];

    /**
     * @param  array<string>  $whitelistClasses
     * @param  array<string>  $whitelistExceptions
     * @param  array<string>  $whitelistErrorSuppressionFunctions
     * @param  array<string>  $whitelistErrorSuppressionStaticMethods
     * @param  array<string>  $whitelistErrorSuppressionInstanceMethods
     */
    public function __construct(
        private array $whitelistClasses = [],
        private array $whitelistExceptions = [],
        private array $whitelistErrorSuppressionFunctions = [],
        private array $whitelistErrorSuppressionStaticMethods = [],
        private array $whitelistErrorSuppressionInstanceMethods = []
    ) {}

    public function enterNode(Node $node): ?Node
    {
        // Track current class name and whitelisted depth
        if ($node instanceof Node\Stmt\Class_) {
            $this->currentClass = $node->name?->toString();

            if ($this->whitelistedClassDepth > 0 || $this->isWhitelistedClass($this->currentClass)) {
                $this->whitelistedClassDepth++;
            }
        }

        // Skip whitelisted classes (depth > 0 means we're inside a whitelisted class, including nested anonymous classes)
        if ($this->whitelistedClassDepth > 0) {
            return null;
        }

        // Track catch block entry for error suppression severity
        if ($node instanceof Node\Stmt\Catch_) {
            $this->catchBlockDepth++;
        }

        // Check for empty catch blocks
        if ($node instanceof Node\Stmt\TryCatch) {
            foreach ($node->catches as $catch) {
                // Skip if any exception type in the union is whitelisted
                if ($this->hasWhitelistedExceptionType($catch->types)) {
                    continue;
                }

                // Check if catch block is empty or only contains comments (Nop statements)
                if ($this->isEmptyOrCommentOnlyCatch($catch)) {
                    // Check if catch block has an explanatory comment (intentional ignore)
                    if ($this->hasExplanatoryComment($catch)) {
                        continue;
                    }

                    $this->issues[] = [
                        'message' => 'Empty catch block silently swallows exceptions',
                        'line' => $catch->getLine(),
                        'severity' => Severity::High,
                        'recommendation' => 'Never use empty catch blocks. At minimum, log the exception. If you truly need to ignore an exception, add a comment explaining why',
                        'code' => null,
                    ];
                } else {
                    // Get exception variable name
                    $exceptionVar = $catch->var?->name;
                    $exceptionVarName = is_string($exceptionVar) ? $exceptionVar : null;

                    // Recursively check if catch block has logging, reporting, fallback, or rethrow
                    $hasLogging = $this->subtreeContainsMatch($catch->stmts, function (Node $n): bool {
                        return $this->isLoggingOrReportingStatement($n) || $this->hasGracefulFallback($n);
                    });

                    $hasRethrow = $this->subtreeContainsMatch($catch->stmts, function (Node $n): bool {
                        return $n instanceof Node\Stmt\Throw_
                            || ($n instanceof Node\Stmt\Expression && $n->expr instanceof Node\Expr\Throw_);
                    });

                    // Bug 3: Flag broad exception types even with logging (unless rethrowing)
                    // This check happens BEFORE the exception variable check to ensure we always warn
                    $broadInfo = $this->getBroadExceptionInfo($catch->types);
                    if ($broadInfo['isBroad'] && ! $hasRethrow) {
                        $broadTypeStr = implode('|', $broadInfo['types']);
                        $this->issues[] = [
                            'message' => "Catching {$broadTypeStr} is overly broad and can mask fatal errors",
                            'line' => $catch->getLine(),
                            'severity' => Severity::High,
                            'recommendation' => "Catch specific exception types instead of {$broadTypeStr}. Broad catches hide programming errors like TypeError, ArgumentCountError",
                            'code' => null,
                        ];
                    }

                    // Check if exception variable is used (indicates it's being handled)
                    if ($this->usesExceptionVariable($catch->stmts, $exceptionVarName)) {
                        continue;
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

            // Bug 5: Severity differentiation for error suppression
            $severity = $this->getErrorSuppressionSeverity($node);
            $this->issues[] = [
                'message' => $this->getErrorSuppressionMessage($severity),
                'line' => $node->getLine(),
                'severity' => $severity,
                'recommendation' => $severity === Severity::High
                    ? 'Dynamic or nested error suppression is highly discouraged. Use explicit try-catch with logging'
                    : 'Avoid using @ operator. Handle errors explicitly with try-catch or check return values',
                'code' => null,
            ];
        }

        return null;
    }

    /**
     * Reset class context when leaving a class to prevent context leaking in multi-class files.
     */
    public function leaveNode(Node $node): ?Node
    {
        if ($node instanceof Node\Stmt\Class_) {
            if ($this->whitelistedClassDepth > 0) {
                $this->whitelistedClassDepth--;
            }
            $this->currentClass = null;
        }

        // Track catch block exit for error suppression severity
        if ($node instanceof Node\Stmt\Catch_) {
            $this->catchBlockDepth--;
        }

        return null;
    }

    /**
     * Check if the catch block is empty or only contains Nop statements (comments only).
     */
    private function isEmptyOrCommentOnlyCatch(Node\Stmt\Catch_ $catch): bool
    {
        if (empty($catch->stmts)) {
            return true;
        }

        // Check if all statements are Nop (comment-only)
        foreach ($catch->stmts as $stmt) {
            if (! $stmt instanceof Node\Stmt\Nop) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if the catch block has an explanatory comment indicating intentional empty catch.
     * Only considers comments that appear to explicitly justify the empty catch block.
     */
    private function hasExplanatoryComment(Node\Stmt\Catch_ $catch): bool
    {
        $allComments = [];

        // Collect comments attached to the catch node
        $allComments = array_merge($allComments, $catch->getComments());

        // Collect comments inside the catch block (attached to Nop statements)
        foreach ($catch->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\Nop) {
                $allComments = array_merge($allComments, $stmt->getComments());
            }
        }

        // Collect comments from attributes
        /** @var array<\PhpParser\Comment> $attributes */
        $attributes = $catch->getAttribute('comments', []);
        $allComments = array_merge($allComments, $attributes);

        // Check if any comment indicates intentional ignoring
        foreach ($allComments as $comment) {
            if ($this->isIntentionalIgnoreComment($comment->getText())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a comment text indicates intentional exception ignoring.
     */
    private function isIntentionalIgnoreComment(string $commentText): bool
    {
        $lowerText = strtolower($commentText);

        // Bug 4: Tightened patterns - removed vague 'expected' and 'acceptable'
        // Added more specific patterns instead
        $intentionalPatterns = [
            'intentional',
            'intentionally',
            'deliberately',
            'on purpose',
            'expected to fail',      // More specific than 'expected'
            'expected exception',    // More specific than 'expected'
            'safe to ignore',
            'safely ignore',
            'safely ignored',
            'can be ignored',
            'may be ignored',
            'optional',
            'not critical',
            'non-critical',
            'best effort',
            'best-effort',
            'fire and forget',
            'fire-and-forget',
            'no action needed',
            'no action required',
            'nothing to do',
            'noop',
            'no-op',
            '@suppress',
            '@ignore',
            'phpstan-ignore',
            'psalm-suppress',
            'swallow',
            'don\'t care',
            'doesn\'t matter',
            'not important',
        ];

        foreach ($intentionalPatterns as $pattern) {
            if (str_contains($lowerText, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the exception variable is used within the catch block statements.
     *
     * @param  array<Node>  $stmts
     */
    private function usesExceptionVariable(array $stmts, ?string $exceptionVar): bool
    {
        if ($exceptionVar === null) {
            return false;
        }

        foreach ($stmts as $stmt) {
            if ($this->nodeContainsVariable($stmt, $exceptionVar)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Recursively check if a node contains a reference to the given variable.
     */
    private function nodeContainsVariable(Node $node, string $varName): bool
    {
        // Check if this node is the variable
        if ($node instanceof Node\Expr\Variable && $node->name === $varName) {
            return true;
        }

        // Recursively check child nodes
        foreach ($node->getSubNodeNames() as $name) {
            $subNode = $node->$name;
            if ($subNode instanceof Node) {
                if ($this->nodeContainsVariable($subNode, $varName)) {
                    return true;
                }
            } elseif (is_array($subNode)) {
                foreach ($subNode as $child) {
                    if ($child instanceof Node && $this->nodeContainsVariable($child, $varName)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Recursively check if any node in the subtree satisfies the predicate.
     *
     * @param  array<Node|mixed>  $nodes
     * @param  callable(Node): bool  $predicate
     */
    private function subtreeContainsMatch(array $nodes, callable $predicate): bool
    {
        foreach ($nodes as $node) {
            if (! $node instanceof Node) {
                continue;
            }
            if ($predicate($node)) {
                return true;
            }
            foreach ($node->getSubNodeNames() as $name) {
                $subNode = $node->$name;
                if ($subNode instanceof Node) {
                    if ($this->subtreeContainsMatch([$subNode], $predicate)) {
                        return true;
                    }
                } elseif (is_array($subNode)) {
                    if ($this->subtreeContainsMatch($subNode, $predicate)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private function isLoggingOrReportingStatement(Node $stmt): bool
    {
        if (! $stmt instanceof Node\Stmt\Expression) {
            return false;
        }

        $expr = $stmt->expr;

        // Check for Log::* calls (Log::error, Log::warning, etc.)
        if ($expr instanceof Node\Expr\StaticCall && $expr->class instanceof Node\Name) {
            $className = $expr->class->toString();

            if ($className === 'Log') {
                return true;
            }

            // DB::rollback()
            if ($className === 'DB' && $expr->name instanceof Node\Identifier && $expr->name->toString() === 'rollback') {
                return true;
            }

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

        // Check for function calls
        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            $functionName = $expr->name->toString();

            // Bug 1: Removed 'rescue' from this list - it's a fallback, not logging
            // Laravel error reporting helpers
            if (in_array($functionName, ['logger', 'report'], true)) {
                return true;
            }

            // Laravel abort helpers
            if (in_array($functionName, ['abort', 'abort_if', 'abort_unless'], true)) {
                return true;
            }

            // Bug 1: rescue() with third parameter = true reports exceptions
            if ($functionName === 'rescue' && count($expr->args) >= 3) {
                $thirdArg = $expr->args[2]->value ?? null;
                if ($thirdArg instanceof Node\Expr\ConstFetch &&
                    strtolower($thirdArg->name->toString()) === 'true') {
                    return true;
                }
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

            // Notification method: $user->notify(), $notifiable->notify()
            if ($method === 'notify') {
                return true;
            }

            // Session flash methods: session()->flash(), session()->put()
            if (in_array($method, ['flash', 'put', 'push'], true) && $this->isSessionMethodCall($expr)) {
                return true;
            }

            // Custom handler method calls on $this (e.g., $this->logError(), $this->handleException())
            if ($expr->var instanceof Node\Expr\Variable && $expr->var->name === 'this') {
                $handlerPatterns = ['log', 'error', 'exception', 'report', 'handle', 'notify', 'fail'];
                foreach ($handlerPatterns as $pattern) {
                    if (stripos($method, $pattern) !== false) {
                        return true;
                    }
                }
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

    /**
     * Check if a method call is on a session object.
     */
    private function isSessionMethodCall(Node\Expr\MethodCall $expr): bool
    {
        // Check for session()->flash() pattern
        if ($expr->var instanceof Node\Expr\FuncCall &&
            $expr->var->name instanceof Node\Name &&
            $expr->var->name->toString() === 'session') {
            return true;
        }

        // Check for $session->flash() pattern
        if ($expr->var instanceof Node\Expr\Variable &&
            is_string($expr->var->name) &&
            str_contains(strtolower($expr->var->name), 'session')) {
            return true;
        }

        return false;
    }

    private function hasGracefulFallback(Node $stmt): bool
    {
        // Check for return (with or without value — void return is a valid early exit)
        if ($stmt instanceof Node\Stmt\Return_) {
            return true;
        }

        // Check for continue (common in loops wrapping try/catch)
        if ($stmt instanceof Node\Stmt\Continue_) {
            return true;
        }

        // Check for break (common in loops wrapping try/catch)
        if ($stmt instanceof Node\Stmt\Break_) {
            return true;
        }

        // Check for assignment — NEW: require semantic intent for fallback
        if ($stmt instanceof Node\Stmt\Expression &&
            $stmt->expr instanceof Node\Expr\Assign) {
            return $this->isSemanticFallbackAssignment($stmt->expr);
        }

        // Bug 1: rescue() function call is a fallback mechanism
        if ($stmt instanceof Node\Stmt\Expression &&
            $stmt->expr instanceof Node\Expr\FuncCall &&
            $stmt->expr->name instanceof Node\Name &&
            $stmt->expr->name->toString() === 'rescue') {
            return true;
        }

        return false;
    }

    /**
     * Determine if an assignment represents a semantic fallback (not just arbitrary assignment).
     *
     * Passes: $default = new GuestUser(); $config = $this->getDefaultConfig(); $val = Cache::get('key', $default);
     * Fails: $x = true; $hasError = true; $data = [];
     */
    private function isSemanticFallbackAssignment(Node\Expr\Assign $assign): bool
    {
        $var = $assign->var;
        $expr = $assign->expr;

        // 1. Variable name indicates fallback (e.g., $default, $fallback, $cached)
        if ($var instanceof Node\Expr\Variable && is_string($var->name)) {
            if ($this->isFallbackVariableName($var->name)) {
                return true;
            }
        }

        // 2. RHS is method call with fallback semantics (e.g., $this->getDefaultConfig())
        if ($expr instanceof Node\Expr\MethodCall) {
            return $this->isFallbackMethodCall($expr);
        }

        // 3. RHS is static call (Cache::get with default, Config::get, etc.)
        if ($expr instanceof Node\Expr\StaticCall) {
            return $this->isFallbackStaticCall($expr);
        }

        // 4. RHS is function call with fallback semantics
        if ($expr instanceof Node\Expr\FuncCall) {
            return $this->isFallbackFunctionCall($expr);
        }

        // 5. RHS is null coalescing with meaningful alternative
        if ($expr instanceof Node\Expr\BinaryOp\Coalesce) {
            return $this->isSemanticCoalesce($expr);
        }

        // 6. RHS is ternary with meaningful alternative
        if ($expr instanceof Node\Expr\Ternary) {
            return $this->isSemanticTernary($expr);
        }

        // 7. RHS is new instance (factory pattern)
        if ($expr instanceof Node\Expr\New_) {
            return true;
        }

        // FAIL: Simple scalars, empty arrays, arbitrary expressions
        return false;
    }

    /**
     * Check if variable name indicates fallback intent.
     */
    private function isFallbackVariableName(string $name): bool
    {
        $lowerName = strtolower($name);
        foreach ($this->fallbackVariablePatterns as $pattern) {
            if (str_contains($lowerName, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if method call has fallback semantics (method name contains fallback patterns).
     */
    private function isFallbackMethodCall(Node\Expr\MethodCall $call): bool
    {
        if (! $call->name instanceof Node\Identifier) {
            return false;
        }
        $methodName = strtolower($call->name->toString());
        foreach ($this->fallbackMethodPatterns as $pattern) {
            if (str_contains($methodName, strtolower($pattern))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if static call represents a fallback pattern.
     *
     * Examples: Cache::get('key', $default), Cache::remember(), Config::get()
     */
    private function isFallbackStaticCall(Node\Expr\StaticCall $call): bool
    {
        if (! $call->class instanceof Node\Name || ! $call->name instanceof Node\Identifier) {
            return false;
        }

        $className = $call->class->toString();
        $shortName = str_contains($className, '\\')
            ? substr($className, strrpos($className, '\\') + 1)
            : $className;

        if (! in_array($shortName, $this->fallbackStaticClasses, true)) {
            return false;
        }

        $methodName = $call->name->toString();

        // Cache::get with default parameter (2+ args)
        if ($methodName === 'get' && count($call->args) >= 2) {
            return true;
        }

        // Cache::remember, rememberForever always have fallback
        if (in_array($methodName, ['remember', 'rememberForever', 'pull'], true)) {
            return true;
        }

        return false;
    }

    /**
     * Check if function call has fallback semantics.
     */
    private function isFallbackFunctionCall(Node\Expr\FuncCall $call): bool
    {
        if (! $call->name instanceof Node\Name) {
            return false;
        }
        $funcName = strtolower($call->name->toString());
        foreach ($this->fallbackMethodPatterns as $pattern) {
            if (str_contains($funcName, strtolower($pattern))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if null coalescing has a meaningful alternative (not just a scalar).
     *
     * Passes: $cached ?? $this->compute(); $data ?? new EmptyCollection();
     * Fails: $data ?? [];
     */
    private function isSemanticCoalesce(Node\Expr\BinaryOp\Coalesce $coalesce): bool
    {
        $right = $coalesce->right;

        // Meaningful: method call, static call, function call, new instance
        return $right instanceof Node\Expr\MethodCall
            || $right instanceof Node\Expr\StaticCall
            || $right instanceof Node\Expr\FuncCall
            || $right instanceof Node\Expr\New_;
    }

    /**
     * Check if ternary has a meaningful alternative in else branch.
     */
    private function isSemanticTernary(Node\Expr\Ternary $ternary): bool
    {
        // Check else branch has meaningful alternative
        $else = $ternary->else;

        return $else instanceof Node\Expr\MethodCall
            || $else instanceof Node\Expr\StaticCall
            || $else instanceof Node\Expr\FuncCall
            || $else instanceof Node\Expr\New_;
    }

    /**
     * Check if the suppressed expression is whitelisted.
     *
     * Supports:
     * - Function calls: @unlink(), @\unlink()
     * - Static method calls: @Storage::delete()
     * - Instance method calls: @$file->delete()
     * - Does NOT whitelist dynamic calls: @$func() (always flagged)
     */
    private function isWhitelistedErrorSuppression(Node $expr): bool
    {
        if ($expr instanceof Node\Expr\FuncCall) {
            return $this->isWhitelistedFunctionCall($expr);
        }

        if ($expr instanceof Node\Expr\StaticCall) {
            return $this->isWhitelistedStaticMethodCall($expr);
        }

        if ($expr instanceof Node\Expr\MethodCall) {
            return $this->isWhitelistedInstanceMethodCall($expr);
        }

        return false;
    }

    /**
     * Check if a function call is whitelisted (handles both simple and namespaced).
     */
    private function isWhitelistedFunctionCall(Node\Expr\FuncCall $expr): bool
    {
        if (! $expr->name instanceof Node\Name) {
            // Dynamic function call like @$func() - not whitelisted
            return false;
        }

        $functionName = $expr->name->toString();
        $shortName = str_contains($functionName, '\\')
            ? substr($functionName, strrpos($functionName, '\\') + 1)
            : $functionName;

        foreach ($this->whitelistErrorSuppressionFunctions as $pattern) {
            if ($this->matchesPattern($functionName, $pattern) ||
                $this->matchesPattern($shortName, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a static method call is whitelisted (e.g., Storage::delete).
     */
    private function isWhitelistedStaticMethodCall(Node\Expr\StaticCall $expr): bool
    {
        if (! $expr->class instanceof Node\Name) {
            // Dynamic class like @$class::method() - not whitelisted
            return false;
        }

        if (! $expr->name instanceof Node\Identifier) {
            // Dynamic method like @Storage::$method() - not whitelisted
            return false;
        }

        $fullClassName = $expr->class->toString();
        $shortClassName = $expr->class->getLast();
        $methodName = $expr->name->toString();

        $fullPattern = $fullClassName.'::'.$methodName;
        $shortPattern = $shortClassName.'::'.$methodName;

        foreach ($this->whitelistErrorSuppressionStaticMethods as $pattern) {
            if ($this->matchesPattern($fullPattern, $pattern) ||
                $this->matchesPattern($shortPattern, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if an instance method call is whitelisted (matches by method name only).
     */
    private function isWhitelistedInstanceMethodCall(Node\Expr\MethodCall $expr): bool
    {
        if (! $expr->name instanceof Node\Identifier) {
            // Dynamic method like @$obj->$method() - not whitelisted
            return false;
        }

        $methodName = $expr->name->toString();

        foreach ($this->whitelistErrorSuppressionInstanceMethods as $pattern) {
            if ($this->matchesPattern($methodName, $pattern)) {
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

    /**
     * Check if any exception type in the catch is whitelisted.
     *
     * For union types like `catch (ModelNotFoundException|RuntimeException $e)`,
     * if ANY type is whitelisted, we skip the entire catch block. This is because
     * whitelisted exceptions are expected exceptions that can be safely caught,
     * and if a developer intentionally catches a whitelisted exception alongside
     * others, the entire catch is intentional.
     *
     * Bug 2: However, broad types (Throwable/Exception/Error) cannot be whitelisted
     * in unions because catching them is always dangerous.
     *
     * @param  array<Node\Name>  $types
     */
    private function hasWhitelistedExceptionType(array $types): bool
    {
        // Bug 2: Broad types (Throwable/Exception/Error) cannot be whitelisted
        if ($this->containsBroadExceptionType($types)) {
            return false;
        }

        foreach ($types as $type) {
            if ($this->isWhitelistedException($type->toString())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if any exception type in the array is a broad exception type.
     *
     * @param  array<Node\Name>  $types
     */
    private function containsBroadExceptionType(array $types): bool
    {
        foreach ($types as $type) {
            $typeName = $type->toString();
            $shortName = str_contains($typeName, '\\')
                ? substr($typeName, strrpos($typeName, '\\') + 1)
                : $typeName;

            if (in_array($shortName, $this->broadExceptionTypes, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get information about broad exception types in the catch.
     *
     * @param  array<Node\Name>  $types
     * @return array{isBroad: bool, types: array<string>}
     */
    private function getBroadExceptionInfo(array $types): array
    {
        $broadTypes = [];
        foreach ($types as $type) {
            $typeName = $type->toString();
            $shortName = str_contains($typeName, '\\')
                ? substr($typeName, strrpos($typeName, '\\') + 1)
                : $typeName;

            if (in_array($shortName, $this->broadExceptionTypes, true)) {
                $broadTypes[] = $shortName;
            }
        }

        return ['isBroad' => ! empty($broadTypes), 'types' => $broadTypes];
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

    /**
     * Bug 5: Determine severity for error suppression based on context.
     */
    private function getErrorSuppressionSeverity(Node\Expr\ErrorSuppress $node): Severity
    {
        $expr = $node->expr;

        // Inside catch = double silencing = High
        if ($this->catchBlockDepth > 0) {
            return Severity::High;
        }

        // Dynamic function @$func() = High
        if ($expr instanceof Node\Expr\FuncCall && ! $expr->name instanceof Node\Name) {
            return Severity::High;
        }

        // Dynamic static @$class::method() = High
        if ($expr instanceof Node\Expr\StaticCall && ! $expr->class instanceof Node\Name) {
            return Severity::High;
        }

        // Dynamic instance @$obj->$method() = High
        if ($expr instanceof Node\Expr\MethodCall && ! $expr->name instanceof Node\Identifier) {
            return Severity::High;
        }

        return Severity::Medium;
    }

    /**
     * Bug 5: Get appropriate message for error suppression based on severity.
     */
    private function getErrorSuppressionMessage(Severity $severity): string
    {
        if ($this->catchBlockDepth > 0) {
            return 'Error suppression operator (@) inside catch block creates double silencing';
        }
        if ($severity === Severity::High) {
            return 'Dynamic error suppression is particularly dangerous';
        }

        return 'Error suppression operator (@) hides errors';
    }

    public function getIssues(): array
    {
        return $this->issues;
    }
}
