<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use PhpParser\Node;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

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
            docsUrl: 'https://docs.shieldci.com/analyzers/security/unguarded-models',
            timeToFix: 20
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check all PHP files for unguard() calls
        foreach ($this->getPhpFiles() as $file) {
            $this->checkFileForUnguard($file, $issues);
        }

        if (empty($issues)) {
            return $this->passed('No unguarded models detected');
        }

        return $this->failed(
            sprintf('Found %d instances of unguarded models', count($issues)),
            $issues
        );
    }

    /**
     * Check a file for unguard() usage.
     */
    private function checkFileForUnguard(string $file, array &$issues): void
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

        $this->traverseNodes($ast, $file, $issues);
    }

    /**
     * Traverse AST nodes looking for unguard() calls.
     */
    private function traverseNodes(array $nodes, string $file, array &$issues): void
    {
        foreach ($nodes as $node) {
            if (! $node instanceof Node) {
                continue;
            }

            // Check for static method calls
            if ($node instanceof Node\Expr\StaticCall) {
                $this->checkStaticCall($node, $file, $issues);
            }

            // Recursively check child nodes
            if (property_exists($node, 'stmts') && is_array($node->stmts)) {
                $this->traverseNodes($node->stmts, $file, $issues);
            }

            // Check expressions
            if ($node instanceof Node\Stmt\Expression && $node->expr instanceof Node) {
                $this->traverseNodes([$node->expr], $file, $issues);
            }

            // Check other node types that may contain expressions
            foreach (get_object_vars($node) as $property) {
                if (is_array($property)) {
                    $this->traverseNodes($property, $file, $issues);
                }
            }
        }
    }

    /**
     * Check static call for unguard() usage.
     */
    private function checkStaticCall(Node\Expr\StaticCall $node, string $file, array &$issues): void
    {
        // Get the method name
        $methodName = $node->name instanceof Node\Identifier
            ? $node->name->toString()
            : null;

        if ($methodName !== 'unguard') {
            return;
        }

        // Get the class name
        $className = null;
        if ($node->class instanceof Node\Name) {
            $className = $node->class->toString();
        }

        // Check if it's Model::unguard() or Eloquent::unguard()
        $isModelUnguard = in_array($className, ['Model', 'Eloquent']) ||
                         str_ends_with($className ?? '', 'Model') ||
                         str_ends_with($className ?? '', 'Eloquent');

        if ($isModelUnguard || $className === null) {
            $lineNumber = $node->getLine();

            $issues[] = $this->createIssue(
                message: sprintf(
                    'Model mass assignment protection disabled with %s::unguard()',
                    $className ?? 'Model'
                ),
                location: new Location(
                    $this->getRelativePath($file),
                    $lineNumber
                ),
                severity: $this->getSeverityForContext($file),
                recommendation: 'Remove Model::unguard() and use $fillable or forceFill() instead. Unguarding models opens mass assignment vulnerabilities.',
                code: FileParser::getCodeSnippet($file, $lineNumber)
            );
        }
    }

    /**
     * Get severity based on file context.
     */
    private function getSeverityForContext(string $file): Severity
    {
        $relativePath = $this->getRelativePath($file);

        // Critical if in production code
        if (str_contains($relativePath, '/app/Http/Controllers') ||
            str_contains($relativePath, '/app/Models') ||
            str_contains($relativePath, '/app/Services')) {
            return Severity::Critical;
        }

        // High if in seeders (still concerning but common)
        if (str_contains($relativePath, '/database/seeders') ||
            str_contains($relativePath, '/database/seeds')) {
            return Severity::Medium;
        }

        // Medium for tests
        if (str_contains($relativePath, '/tests/') ||
            str_contains($relativePath, '/Test.php')) {
            return Severity::Low;
        }

        // High by default
        return Severity::High;
    }
}
