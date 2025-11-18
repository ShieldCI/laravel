<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\InspectsCode;
use ShieldCI\Support\ConfigSuggester;
use ShieldCI\Support\FileTypeDetector;

/**
 * Detects env() calls outside of configuration files.
 *
 * Checks for:
 * - env() function calls in controllers, models, services
 * - env() calls that will break when config is cached
 * - Recommends using config() instead of env()
 *
 * Uses the InspectsCode trait for AST parsing abstraction.
 */
class EnvCallAnalyzer extends AbstractFileAnalyzer
{
    use InspectsCode;

    /**
     * AST parser for static call detection.
     */
    private \ShieldCI\AnalyzersCore\Support\AstParser $staticParser;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'env-call-outside-config',
            name: 'Env Calls Outside Config',
            description: 'Detects env() function calls outside configuration files that break when config is cached',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['configuration', 'cache', 'performance', 'env'],
            docsUrl: 'https://laravel.com/docs/configuration#configuration-caching'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Find all env() function calls and Env::get() static calls, excluding config and test directories
        $envCalls = $this->findFunctionCalls(
            functionName: 'env',
            paths: ['app', 'routes', 'database', 'resources/views'],
            excludePaths: ['/config/', '/tests/', '/Tests/']
        );

        // Also find Env::get() static calls
        $envStaticCalls = $this->findEnvStaticCalls();

        // Combine both types of calls
        $allCalls = array_merge($envCalls, $envStaticCalls);

        if (empty($allCalls)) {
            return $this->passed('No env() calls detected outside configuration files');
        }

        // Create issues for each env() call found
        $issues = [];

        foreach ($allCalls as $call) {
            $varName = $call['args'][0] ?? null;
            $filePath = $call['file'];
            $line = $call['node']->getLine();
            $callType = $call['type'] ?? 'function';

            // Ensure varName is string|null for ConfigSuggester
            $varNameString = is_string($varName) ? $varName : null;

            $message = $callType === 'static'
                ? 'Env::get() call detected outside configuration files'
                : 'env() call detected outside configuration files';

            $issues[] = $this->createIssue(
                message: $message,
                location: new Location($filePath, $line),
                severity: Severity::High,
                recommendation: ConfigSuggester::getRecommendation($varNameString),
                code: $this->getCodeSnippet($filePath, $line),
                metadata: [
                    'function' => $callType === 'static' ? 'Env::get' : 'env',
                    'variable' => $varNameString,
                    'file_type' => FileTypeDetector::detect($filePath),
                ]
            );
        }

        return $this->failed(
            sprintf('Found %d env() calls outside configuration files', count($issues)),
            $issues
        );
    }

    /**
     * Find Env::get() static calls outside configuration files.
     *
     * @return array<int, array{file: string, node: \PhpParser\Node\Expr\StaticCall, args: array<int, mixed>, type: string}>
     */
    private function findEnvStaticCalls(): array
    {
        if (! isset($this->staticParser)) {
            $this->staticParser = new \ShieldCI\AnalyzersCore\Support\AstParser;
        }

        $results = [];

        // Set paths to analyze
        $this->setPaths(['app', 'routes', 'database', 'resources/views']);

        foreach ($this->getPhpFiles() as $file) {
            $filePath = $file instanceof \SplFileInfo ? $file->getPathname() : (string) $file;

            // Skip excluded paths (config and tests)
            if ($this->shouldExcludeEnvFile($filePath)) {
                continue;
            }

            try {
                $ast = $this->staticParser->parseFile($filePath);
                $calls = $this->findEnvStaticCallsInAst($ast);

                foreach ($calls as $call) {
                    $results[] = [
                        'file' => $filePath,
                        'node' => $call,
                        'args' => $this->extractStaticCallArguments($call),
                        'type' => 'static',
                    ];
                }
            } catch (\Throwable $e) {
                // Skip files that can't be parsed
                continue;
            }
        }

        return $results;
    }

    /**
     * Find Env::get() static calls in AST.
     *
     * @param  array<\PhpParser\Node>  $ast
     * @return array<int, \PhpParser\Node\Expr\StaticCall>
     */
    private function findEnvStaticCallsInAst(array $ast): array
    {
        $nodeFinder = new \PhpParser\NodeFinder;
        $staticCalls = $nodeFinder->findInstanceOf($ast, \PhpParser\Node\Expr\StaticCall::class);

        $matches = [];

        foreach ($staticCalls as $staticCall) {
            // Check if it's Env::get() or \Illuminate\Support\Facades\Env::get()
            // Also handles use statements (e.g., use Illuminate\Support\Facades\Env; Env::get())
            if ($staticCall->class instanceof \PhpParser\Node\Name) {
                $className = $staticCall->class->toString();
                
                // Check for Env facade (handles both short name and fully qualified)
                // Matches: Env, \Env, Illuminate\Support\Facades\Env, \Illuminate\Support\Facades\Env
                // Note: PhpParser doesn't resolve use statements automatically, so we check both
                $isEnv = $className === 'Env' 
                    || $className === 'Illuminate\Support\Facades\Env'
                    || $className === '\Illuminate\Support\Facades\Env';

                if ($isEnv && $staticCall->name instanceof \PhpParser\Node\Identifier && $staticCall->name->toString() === 'get') {
                    $matches[] = $staticCall;
                }
            }
        }

        return $matches;
    }

    /**
     * Extract arguments from a static call.
     *
     * @return array<int, mixed>
     */
    private function extractStaticCallArguments(\PhpParser\Node\Expr\StaticCall $staticCall): array
    {
        $args = [];

        foreach ($staticCall->args as $index => $arg) {
            $args[$index] = $this->extractStaticArgumentValue($arg->value);
        }

        return $args;
    }

    /**
     * Extract value from a node (for static calls).
     */
    private function extractStaticArgumentValue(\PhpParser\Node $node): mixed
    {
        if ($node instanceof \PhpParser\Node\Scalar\String_) {
            return $node->value;
        }

        if ($node instanceof \PhpParser\Node\Scalar\LNumber || $node instanceof \PhpParser\Node\Scalar\DNumber) {
            return $node->value;
        }

        if ($node instanceof \PhpParser\Node\Expr\ConstFetch) {
            return $node->name->toString();
        }

        // For complex expressions, return null
        return null;
    }

    /**
     * Check if file should be excluded for env() detection.
     */
    private function shouldExcludeEnvFile(string $filePath): bool
    {
        $excludePaths = ['/config/', '/tests/', '/Tests/'];

        foreach ($excludePaths as $excludePath) {
            if (str_contains($filePath, $excludePath)) {
                return true;
            }
        }

        return false;
    }
}
