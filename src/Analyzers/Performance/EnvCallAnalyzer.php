<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\DNumber;
use PhpParser\Node\Scalar\LNumber;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\GroupUse;
use PhpParser\Node\Stmt\Use_;
use PhpParser\Node\Stmt\UseUse;
use PhpParser\NodeFinder;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
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
     * Paths to search for env() calls.
     */
    private const SEARCH_PATHS = ['app', 'routes', 'database', 'resources/views'];

    /**
     * Path patterns to exclude from analysis.
     */
    private const EXCLUDE_PATHS = ['/config/', '/tests/', '/Tests/'];

    /**
     * AST parser for static call detection.
     */
    private ?AstParser $staticParser = null;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'env-call-outside-config',
            name: 'Env Calls Outside Config Analyzer',
            description: 'Detects env() function calls outside configuration files that break when config is cached',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['configuration', 'cache', 'performance', 'env'],
            timeToFix: 30
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Find all env() function calls and Env::get() static calls in a single parse pass
        $excludePaths = $this->getNormalizedExcludePaths();

        // Single parse pass detects both env() functions and Env::get() static calls
        $allCalls = $this->findAllEnvCalls($excludePaths);

        if (count($allCalls) === 0) {
            return $this->passed('No env() calls detected outside configuration files');
        }

        // Create issues for each env() call found
        $issues = [];

        foreach ($allCalls as $call) {
            // Validate call structure
            if (! isset($call['file'], $call['node'], $call['args'])) {
                continue;
            }

            $varName = $call['args'][0] ?? null;
            $filePath = $call['file'];
            $node = $call['node'];

            if (! $node instanceof \PhpParser\Node) {
                continue;
            }

            $line = $node->getLine();
            $callType = $call['type'] ?? 'function';

            // Ensure varName is string|null for ConfigSuggester
            $varNameString = is_string($varName) ? $varName : null;

            $message = $callType === 'static'
                ? 'Env::get() call detected outside configuration files'
                : 'env() call detected outside configuration files';

            $issues[] = $this->createIssueWithSnippet(
                message: $message,
                filePath: $filePath,
                lineNumber: $line,
                severity: Severity::High,
                recommendation: ConfigSuggester::getRecommendation($varNameString),
                code: $callType === 'static' ? 'Env::get' : 'env',
                metadata: [
                    'function' => $callType === 'static' ? 'Env::get' : 'env',
                    'variable' => $varNameString,
                    'file_type' => FileTypeDetector::detect($filePath),
                ]
            );
        }

        return $this->resultBySeverity(
            sprintf('Found %d env() call(s) outside configuration files', count($issues)),
            $issues
        );
    }

    /**
     * Get the static parser instance (lazy initialization).
     */
    private function getStaticParser(): AstParser
    {
        if ($this->staticParser === null) {
            $this->staticParser = new AstParser;
        }

        return $this->staticParser;
    }

    /**
     * Find all env() calls (both function and Env::get() static calls) in a single parse pass.
     *
     * Parses each file only once to detect both patterns, avoiding duplicate AST parsing.
     *
     * @param  array<int, string>  $excludePaths
     * @return array<int, array{file: string, node: \PhpParser\Node, args: array<int, mixed>, type: string}>
     */
    private function findAllEnvCalls(array $excludePaths): array
    {
        $results = [];
        $parser = $this->getStaticParser();

        // Set paths to analyze
        $this->setPaths(self::SEARCH_PATHS);

        foreach ($this->getPhpFiles() as $file) {
            $filePath = $file instanceof \SplFileInfo ? $file->getPathname() : (string) $file;

            // Skip excluded paths (config and tests)
            if ($this->shouldExcludeEnvFile($filePath, $excludePaths)) {
                continue;
            }

            try {
                // Parse file once
                $ast = $parser->parseFile($filePath);

                // Find both env() function calls and Env::get() static calls in this AST
                $nodeFinder = new NodeFinder;

                // 1. Find env() function calls
                $functionCalls = $nodeFinder->findInstanceOf($ast, \PhpParser\Node\Expr\FuncCall::class);
                foreach ($functionCalls as $funcCall) {
                    if ($funcCall->name instanceof \PhpParser\Node\Name
                        && $funcCall->name->toString() === 'env'
                    ) {
                        $results[] = [
                            'file' => $filePath,
                            'node' => $funcCall,
                            'args' => $this->extractFunctionCallArguments($funcCall),
                            'type' => 'function',
                        ];
                    }
                }

                // 2. Find Env::get() static calls
                $envClasses = $this->getEnvClassAliases($ast);
                $staticCalls = $this->findEnvStaticCallsInAst($ast, $envClasses);

                foreach ($staticCalls as $call) {
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
     * Extract arguments from a function call.
     *
     * @return array<int, mixed>
     */
    private function extractFunctionCallArguments(\PhpParser\Node\Expr\FuncCall $funcCall): array
    {
        $args = [];

        foreach ($funcCall->args as $index => $arg) {
            $args[$index] = $this->extractStaticArgumentValue($arg->value);
        }

        return $args;
    }

    /**
     * Find Env::get() static calls in AST.
     *
     * @param  array<\PhpParser\Node>  $ast
     * @return array<int, StaticCall>
     */
    /**
     * @param  array<int, string>  $envClasses
     */
    private function findEnvStaticCallsInAst(array $ast, array $envClasses): array
    {
        $nodeFinder = new NodeFinder;
        $staticCalls = $nodeFinder->findInstanceOf($ast, StaticCall::class);

        $matches = [];

        foreach ($staticCalls as $staticCall) {
            // Check if it's Env::get() or \Illuminate\Support\Facades\Env::get()
            // Also handles use statements (e.g., use Illuminate\Support\Facades\Env; Env::get())
            if (! ($staticCall->class instanceof Name)) {
                continue;
            }

            $className = ltrim($staticCall->class->toString(), '\\');
            $isEnv = in_array($className, $envClasses, true);

            if ($isEnv
                && $staticCall->name instanceof Identifier
                && $staticCall->name->toString() === 'get'
            ) {
                $matches[] = $staticCall;
            }
        }

        return $matches;
    }

    /**
     * Extract arguments from a static call.
     *
     * @return array<int, mixed>
     */
    private function extractStaticCallArguments(StaticCall $staticCall): array
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
        if ($node instanceof String_) {
            return $node->value;
        }

        if ($node instanceof LNumber || $node instanceof DNumber) {
            return $node->value;
        }

        if ($node instanceof ConstFetch) {
            return $node->name->toString();
        }

        // For complex expressions, return null
        return null;
    }

    /**
     * Check if file should be excluded for env() detection.
     */
    /**
     * @param  array<int, string>|null  $excludePaths
     */
    protected function shouldExcludeEnvFile(string $filePath, ?array $excludePaths = null): bool
    {
        $paths = $excludePaths ?? $this->getNormalizedExcludePaths();
        foreach ($paths as $excludePath) {
            if (str_contains($filePath, $excludePath)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Normalize exclude paths for different directory separators.
     *
     * @return array<int, string>
     */
    private function getNormalizedExcludePaths(): array
    {
        $paths = [];

        foreach (self::EXCLUDE_PATHS as $path) {
            $paths[] = $path;
            $windowsPath = str_replace('/', '\\', $path);
            if ($windowsPath !== $path) {
                $paths[] = $windowsPath;
            }
        }

        return array_values(array_unique($paths));
    }

    /**
     * @param  array<\PhpParser\Node>  $ast
     * @return array<int, string>
     */
    private function getEnvClassAliases(array $ast): array
    {
        $aliases = ['Env', 'Illuminate\\Support\\Facades\\Env'];
        $nodeFinder = new NodeFinder;

        /** @var array<int, Use_> $useStatements */
        $useStatements = $nodeFinder->findInstanceOf($ast, Use_::class);

        foreach ($useStatements as $useStatement) {
            /** @var array<int, UseUse> $useItems */
            $useItems = $useStatement->uses;
            $this->collectEnvAliasFromUses($useItems, $aliases);
        }

        /** @var array<int, GroupUse> $groupUses */
        $groupUses = $nodeFinder->findInstanceOf($ast, GroupUse::class);

        foreach ($groupUses as $groupUse) {
            $prefix = ltrim($groupUse->prefix->toString(), '\\');
            /** @var array<int, UseUse> $groupUseItems */
            $groupUseItems = $groupUse->uses;
            $this->collectEnvAliasFromUses($groupUseItems, $aliases, $prefix);
        }

        return array_values(array_unique($aliases));
    }

    /**
     * @param  array<int, UseUse>  $uses
     * @param  array<int, string>  $aliases
     */
    private function collectEnvAliasFromUses(array $uses, array &$aliases, ?string $prefix = null): void
    {
        foreach ($uses as $use) {
            if (! $use instanceof UseUse) {
                continue;
            }

            $name = ltrim($use->name->toString(), '\\');
            $fullName = $prefix ? $prefix.'\\'.$name : $name;

            if ($fullName === 'Illuminate\\Support\\Facades\\Env') {
                $alias = $use->alias?->toString() ?? $use->name->getLast();
                $aliases[] = $alias;
            }
        }
    }
}
