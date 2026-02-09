<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

/**
 * Detects Model::unguard() calls that disable mass assignment protection.
 *
 * Checks for:
 * - Model::unguard() static calls
 * - Eloquent::unguard() calls
 * - Missing reguard() after unguard()
 * - Unguarded model usage in production code
 */
class UnguardedModelsAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'unguarded-models',
            name: 'Unguarded Models Analyzer',
            description: 'Detects Model::unguard() usage that disables mass assignment protection',
            category: Category::Security,
            severity: Severity::High,
            tags: ['eloquent', 'mass-assignment', 'models', 'security', 'unguard'],
            timeToFix: 20
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check all PHP files for unguard() calls
        foreach ($this->getPhpFiles() as $file) {
            $relativePath = $this->getRelativePath($file);

            if ($this->shouldSkipFile($relativePath)) {
                continue;
            }

            $this->checkFileForUnguard($file, $relativePath, $issues);
        }

        if (empty($issues)) {
            return $this->passed('No unguarded models detected');
        }

        return $this->resultBySeverity(
            sprintf('Found %d instances of unguarded models', count($issues)),
            $issues
        );
    }

    /**
     * Check a file for unguard() usage.
     */
    private function checkFileForUnguard(string $file, string $relativePath, array &$issues): void
    {
        $ast = $this->parser->parseFile($file);
        if (empty($ast)) {
            return;
        }

        $content = FileParser::readFile($file);
        if ($content === null) {
            return;
        }

        // Quick check to avoid parsing if no unguard() present
        if (! str_contains($content, 'unguard')) {
            return;
        }

        // Resolve all class names using NameResolver
        $traverser = new NodeTraverser;
        $traverser->addVisitor(new NameResolver);
        $ast = $traverser->traverse($ast);

        $this->evaluateStaticCalls($ast, $file, $relativePath, $issues);
    }

    /**
     * Normalize path for comparison (lowercase, forward slashes).
     */
    private function normalizePath(string $path): string
    {
        return strtolower(str_replace('\\', '/', $path));
    }

    /**
     * Get severity based on file context.
     */
    private function getSeverityForContext(string $relativePath): Severity
    {
        $normalized = $this->normalizePath($relativePath);

        if ($this->containsAny($normalized, ['app/http/controllers', 'http/controllers', 'app/models', 'models/', 'app/services', 'services/'])) {
            return Severity::Critical;
        }

        if ($this->containsAny($normalized, ['database/seeders', 'database/seeds'])) {
            return Severity::Medium;
        }

        // Service providers: Common but discouraged pattern for global unguard
        if ($this->containsAny($normalized, ['app/providers', 'providers/'])) {
            return Severity::Medium;
        }

        if ($this->containsAny($normalized, ['tests/', '/tests', 'test.php'])) {
            return Severity::Low;
        }

        return Severity::High;
    }

    /**
     * Get context-aware recommendation based on file location.
     */
    private function getRecommendationForContext(string $relativePath): string
    {
        $normalized = $this->normalizePath($relativePath);

        // Service providers: Acknowledge the pattern but warn about production use
        if ($this->containsAny($normalized, ['app/providers', 'providers/'])) {
            return 'While Model::unguard() in service providers is a documented pattern, it globally disables mass assignment protection for your entire application. Consider: (1) Use $fillable/$guarded properties on individual models instead, (2) Use the safe scoped pattern: Model::unguarded(fn() => User::create($data)), (3) If absolutely needed, wrap in environment check: if (!app()->environment("production")) { Model::unguard(); }';
        }

        // Default recommendation for all other contexts
        return 'Use the safe scoped pattern: Model::unguarded(function() { /* operations */ }) which automatically re-guards. Alternatively: (1) Call Model::reguard() immediately after importing in the same method/function scope, (2) Use $fillable/$guarded properties on models, or (3) Use forceFill() for trusted data.';
    }

    /**
     * Check if haystack contains any of the needles as complete path segments.
     * Prevents false positives like "services_backup" matching "services".
     *
     * @param  array<string>  $needles
     */
    private function containsAny(string $haystack, array $needles): bool
    {
        foreach ($needles as $needle) {
            if ($needle === '') {
                continue;
            }

            if ($this->containsPathSegment($haystack, $needle)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a path segment exists in the haystack.
     * Ensures segment boundaries (directory separators or start/end of string).
     */
    private function containsPathSegment(string $haystack, string $needle): bool
    {
        $needle = rtrim($needle, '/');

        // Check if needle appears as a complete path segment:
        // - At the start of path: "services/foo" or "app/services/foo"
        // - In the middle: "foo/services/bar"
        // - At the end: "foo/services"
        return str_starts_with($haystack, $needle.'/')
            || str_contains($haystack, '/'.$needle.'/')
            || str_ends_with($haystack, '/'.$needle)
            || $haystack === $needle; // Exact match (rare but possible)
    }

    private function shouldSkipFile(string $relativePath): bool
    {
        $normalized = $this->normalizePath($relativePath);

        return str_starts_with($normalized, 'vendor/') || str_contains($normalized, '/vendor/');
    }

    private function evaluateStaticCalls(array $ast, string $file, string $relativePath, array &$issues): void
    {
        /** @var array<Node\Expr\StaticCall> $staticCalls */
        $staticCalls = $this->parser->findNodes($ast, Node\Expr\StaticCall::class);

        if (empty($staticCalls)) {
            return;
        }

        // Build a map of method/function nodes to track scope boundaries
        $methodMap = $this->buildMethodScopeMap($ast);

        $unguardCalls = [];
        $reguardCalls = [];

        foreach ($staticCalls as $call) {
            // Only process static calls with Identifier method names
            if (! ($call->name instanceof Node\Identifier)) {
                continue;
            }

            // Get fully qualified name from NameResolver
            if (! $call->class instanceof Node\Name) {
                continue;
            }

            $method = $call->name->toString();

            // Get fully qualified name from NameResolver
            $resolvedName = $call->class->getAttribute('resolvedName');
            $resolvedClassName = $resolvedName instanceof Node\Name
                ? $resolvedName->toString()
                : $call->class->toString();

            if (! $this->isEloquentClass($resolvedClassName)) {
                continue;
            }

            // Skip Model::unguarded(closure) - this is the SAFE scoped pattern
            if ($method === 'unguarded' && $this->hasClosureArgument($call)) {
                continue; // Safe pattern - automatically handles reguard
            }

            if ($method === 'unguard') {
                $unguardCalls[] = $call;
            }

            if ($method === 'reguard') {
                $reguardCalls[] = $call;
            }
        }

        if (empty($unguardCalls)) {
            return;
        }

        // Track which reguard calls have been consumed
        $consumedReguards = [];

        // Check each unguard call for a matching reguard in the same scope
        foreach ($unguardCalls as $unguardCall) {
            $unguardScope = $this->findEnclosingScope($unguardCall, $methodMap);
            $hasMatchingReguard = false;

            // Find the first available (unconsumed) reguard in the same scope after this unguard
            foreach ($reguardCalls as $index => $reguardCall) {
                // Skip already consumed reguards
                if (in_array($index, $consumedReguards, true)) {
                    continue;
                }

                $reguardScope = $this->findEnclosingScope($reguardCall, $methodMap);

                // Only pair if they're in the same scope AND reguard comes after unguard
                if ($unguardScope === $reguardScope && $reguardCall->getLine() > $unguardCall->getLine()) {
                    $hasMatchingReguard = true;
                    $consumedReguards[] = $index; // Mark this reguard as consumed
                    break;
                }
            }

            if ($hasMatchingReguard) {
                continue;
            }

            $classLabel = $unguardCall->class instanceof Node\Name ? $unguardCall->class->toString() : 'Model';

            $issues[] = $this->createIssueWithSnippet(
                message: sprintf(
                    'Model mass assignment protection disabled without re-guarding (%s::unguard())',
                    $classLabel
                ),
                filePath: $file,
                lineNumber: $unguardCall->getLine(),
                severity: $this->getSeverityForContext($relativePath),
                recommendation: $this->getRecommendationForContext($relativePath)
            );
        }
    }

    /**
     * Check if a class name represents an Eloquent Model class.
     *
     * Only returns true for known Eloquent base classes to avoid false positives
     * on unrelated classes that happen to have an unguard() method.
     *
     * Note: 'Eloquent' class does not exist in modern Laravel (5.x+).
     * Only Model class (short name or fully qualified) is checked.
     */
    private function isEloquentClass(?string $className): bool
    {
        // If we can't determine the class name, don't assume it's Eloquent
        // This prevents false positives on unrelated classes
        if ($className === null) {
            return false;
        }

        $normalized = ltrim(strtolower($className), '\\');

        return in_array($normalized, [
            'model',
            'illuminate\\database\\eloquent\\model',
        ], true);
    }

    /**
     * Check if a static call has a closure/callable argument.
     * Used to detect the safe Model::unguarded(function() {...}) pattern.
     */
    private function hasClosureArgument(Node\Expr\StaticCall $call): bool
    {
        if (empty($call->args)) {
            return false;
        }

        // Check if any argument is a Closure or Arrow function
        foreach ($call->args as $arg) {
            if ($arg->value instanceof Node\Expr\Closure || $arg->value instanceof Node\Expr\ArrowFunction) {
                return true;
            }
        }

        return false;
    }

    /**
     * Build a map of all method/function scopes in the AST.
     *
     * @return array<Node\Stmt\ClassMethod|Node\Stmt\Function_|Node\Expr\Closure>
     */
    private function buildMethodScopeMap(array $ast): array
    {
        /** @var array<Node\Stmt\ClassMethod|Node\Stmt\Function_|Node\Expr\Closure> $scopes */
        $scopes = [];

        // Find all class methods
        /** @var array<Node\Stmt\ClassMethod> $methods */
        $methods = $this->parser->findNodes($ast, Node\Stmt\ClassMethod::class);
        foreach ($methods as $method) {
            $scopes[] = $method;
        }

        // Find all standalone functions
        /** @var array<Node\Stmt\Function_> $functions */
        $functions = $this->parser->findNodes($ast, Node\Stmt\Function_::class);
        foreach ($functions as $function) {
            $scopes[] = $function;
        }

        // Find all closures/anonymous functions
        /** @var array<Node\Expr\Closure> $closures */
        $closures = $this->parser->findNodes($ast, Node\Expr\Closure::class);
        foreach ($closures as $closure) {
            $scopes[] = $closure;
        }

        return $scopes;
    }

    /**
     * Find the enclosing method/function scope for a given node.
     *
     * Returns a unique identifier for the scope (line range).
     * If not in any method/function, returns null (global scope).
     *
     * @param  array<Node\Stmt\ClassMethod|Node\Stmt\Function_|Node\Expr\Closure>  $scopeMap
     */
    private function findEnclosingScope(Node $node, array $scopeMap): ?string
    {
        $nodeLine = $node->getLine();

        foreach ($scopeMap as $scope) {
            $startLine = $scope->getStartLine();
            $endLine = $scope->getEndLine();

            // Check if node is within this scope's line range
            if ($nodeLine >= $startLine && $nodeLine <= $endLine) {
                // Return a unique identifier for this scope (start-end line range)
                return "{$startLine}:{$endLine}";
            }
        }

        // Not in any method/function - global scope
        return null;
    }
}
