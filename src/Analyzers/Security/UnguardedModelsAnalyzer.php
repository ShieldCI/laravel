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
            $relativePath = $this->getRelativePath($file);

            if ($this->shouldSkipFile($relativePath)) {
                continue;
            }

            $this->checkFileForUnguard($file, $relativePath, $issues);
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

        if ($this->containsAny($normalized, ['tests/', '/tests', 'test.php'])) {
            return Severity::Low;
        }

        return Severity::High;
    }

    /**
     * @param  array<string>  $needles
     */
    private function containsAny(string $haystack, array $needles): bool
    {
        foreach ($needles as $needle) {
            if ($needle === '') {
                continue;
            }

            if (str_contains($haystack, rtrim($needle, '/'))) {
                return true;
            }
        }

        return false;
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

        $unguardCalls = [];
        $reguardLines = [];

        foreach ($staticCalls as $call) {
            // Only process static calls with Identifier method names
            if (! ($call->name instanceof Node\Identifier)) {
                continue;
            }

            $method = $call->name->toString();
            $className = $call->class instanceof Node\Name ? $call->class->toString() : null;

            if (! $this->isEloquentClass($className)) {
                continue;
            }

            if ($method === 'unguard') {
                $unguardCalls[] = $call;
            }

            if ($method === 'reguard') {
                $reguardLines[] = $call->getLine();
            }
        }

        if (empty($unguardCalls)) {
            return;
        }

        sort($reguardLines);
        usort($unguardCalls, fn (Node\Expr\StaticCall $a, Node\Expr\StaticCall $b) => $a->getLine() <=> $b->getLine());

        foreach ($unguardCalls as $call) {
            $lineNumber = $call->getLine();

            if ($this->consumeReguardAfterLine($reguardLines, $lineNumber)) {
                continue;
            }

            $classLabel = $call->class instanceof Node\Name ? $call->class->toString() : 'Model';

            $issues[] = $this->createIssue(
                message: sprintf(
                    'Model mass assignment protection disabled without re-guarding (%s::unguard())',
                    $classLabel
                ),
                location: new Location(
                    $relativePath,
                    $lineNumber
                ),
                severity: $this->getSeverityForContext($relativePath),
                recommendation: 'Call Model::reguard() immediately after importing or use $fillable/forceFill() instead of globally unguarding models.',
                code: FileParser::getCodeSnippet($file, $lineNumber)
            );
        }
    }

    private function isEloquentClass(?string $className): bool
    {
        if ($className === null) {
            return true;
        }

        $normalized = ltrim(strtolower($className), '\\');

        return in_array($normalized, [
            'model',
            'eloquent',
            'illuminate\\database\\eloquent\\model',
            'illuminate\\database\\eloquent\\eloquent',
        ], true);
    }

    /**
     * Check if there's a reguard() call after this unguard() and consume it.
     * Also removes any reguard() calls that appear before this unguard() (they belong to previous unguards).
     *
     * @param  array<int>  $reguardLines
     */
    private function consumeReguardAfterLine(array &$reguardLines, int $lineNumber): bool
    {
        // Remove all reguards at or before this unguard (they belong to previous unguards)
        foreach ($reguardLines as $index => $reguardLine) {
            if ($reguardLine <= $lineNumber) {
                unset($reguardLines[$index]);
            }
        }
        $reguardLines = array_values($reguardLines);

        // Now check if there's a reguard after this unguard
        if (! empty($reguardLines)) {
            // Consume the first reguard after this unguard
            array_shift($reguardLines);

            return true;
        }

        return false;
    }
}
