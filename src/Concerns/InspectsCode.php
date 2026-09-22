<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PhpParser\NodeFinder;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;

/**
 * Trait for inspecting code using AST parsing.
 *
 * Provides common functionality for analyzing PHP code:
 * - Finding function calls in files
 * - Extracting function arguments
 * - Parsing config file arrays
 * - Filtering files by paths
 */
trait InspectsCode
{
    /**
     * The shared parser, never a private instance.
     *
     * AstParser records every file it was handed and could not parse. Nothing in this
     * package reads that log back yet; consolidating onto the one instance the container
     * hands out is what makes reading it possible later, because a parser of our own
     * would log the files this analyzer skipped where no consumer could ever reach them.
     * Until a consumer lands, an unparseable file is still reported as a pass.
     *
     * Its AST cache is drained between analyzers by AnalyzerManager::clearParserCache(),
     * which is what keeps the memory behaviour of #302 while the instance is shared.
     */
    private AstParser $parser;

    /**
     * Resolve the shared AST parser.
     *
     * Does nothing when one was injected: an analyzer that declares AstParser in its
     * constructor assigns this property before any parsing starts, and the container
     * hands it the same singleton.
     *
     * Note that the property is private to this trait, so only a class that both uses
     * the trait and writes its own constructor can pre-assign it. Consumers that do not
     * (CookieSecurityAnalyzer, HSTSHeaderAnalyzer, and the AnalyzesEnvFiles consumers)
     * reach the singleton through this container lookup instead.
     */
    private function initializeParser(): void
    {
        if (! isset($this->parser)) {
            $this->parser = app(AstParser::class);
        }
    }

    /**
     * No-op retained for backward compatibility.
     *
     * This used to unset a private parser so its AST cache could be collected. The
     * parser is now the container singleton, so there is no private cache to release
     * and unsetting it here would only force another container lookup. The shared
     * cache is drained by AnalyzerManager::clearParserCache() instead.
     *
     * Call sites in AnalyzerManager and AnalyzeCommand are method_exists() guarded and
     * do not need this, but the method is public API on a published package, so it stays
     * until the next major.
     *
     * @deprecated Draining the shared cache is AnalyzerManager::clearParserCache()'s job.
     */
    public function clearAstParserCache(): void
    {
        // Intentionally empty: see the note above.
    }

    /**
     * Find all function calls matching the given name in specified paths.
     *
     * @param  string  $functionName  The function name to search for
     * @param  array<int, string>  $paths  Paths to search in (relative to base path)
     * @param  array<int, string>  $excludePaths  Path patterns to exclude
     * @return array<int, array{file: string, node: FuncCall, args: array<int, mixed>}>
     */
    protected function findFunctionCalls(
        string $functionName,
        array $paths = ['app', 'routes', 'database', 'resources/views'],
        array $excludePaths = ['/config/']
    ): array {
        $this->initializeParser();

        $results = [];

        // Set paths to analyze
        $this->setPaths($paths);

        foreach ($this->getPhpFiles() as $file) {
            $filePath = $file instanceof \SplFileInfo ? $file->getPathname() : (string) $file;

            // Skip excluded paths
            if ($this->shouldExcludeFile($filePath, $excludePaths)) {
                continue;
            }

            try {
                $ast = $this->parser->parseFile($filePath);
                $calls = $this->findFunctionCallsInAst($ast, $functionName);

                foreach ($calls as $call) {
                    $results[] = [
                        'file' => $filePath,
                        'node' => $call,
                        'args' => $this->extractFunctionArguments($call),
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
     * Parse a PHP config file and extract top-level array key-value pairs.
     *
     * Delegates to ConfigFileHelper::parseConfigArray() in analyzers-core.
     *
     * @return array<string, array{value: mixed, line: int, isEnvCall: bool, envDefault: mixed, envHasDefault: bool}>
     */
    protected function parseConfigArray(string $filePath): array
    {
        return ConfigFileHelper::parseConfigArray($filePath);
    }

    /**
     * Get the effective value from a parsed config entry.
     *
     * When the value is an env() call, returns its default argument;
     * otherwise returns the literal value.
     *
     * @param  array{value: mixed, line: int, isEnvCall: bool, envDefault: mixed, envHasDefault: bool}  $entry
     */
    protected function resolveConfigValue(array $entry): mixed
    {
        if ($entry['isEnvCall']) {
            return $entry['envDefault'];
        }

        return $entry['value'];
    }

    /**
     * Find function calls in AST.
     *
     * @param  array<Node>  $ast
     * @return array<int, FuncCall>
     */
    private function findFunctionCallsInAst(array $ast, string $functionName): array
    {
        $nodeFinder = new NodeFinder;
        $functionCalls = $nodeFinder->findInstanceOf($ast, FuncCall::class);

        $matches = [];

        foreach ($functionCalls as $funcCall) {
            if ($funcCall->name instanceof Name && $funcCall->name->toString() === $functionName) {
                $matches[] = $funcCall;
            }
        }

        return $matches;
    }

    /**
     * Extract arguments from a function call.
     *
     * @return array<int, mixed>
     */
    private function extractFunctionArguments(FuncCall $funcCall): array
    {
        $args = [];

        foreach ($funcCall->args as $index => $arg) {
            // A first-class callable (env(...)) yields a VariadicPlaceholder, which has no value.
            if ($arg instanceof Node\Arg) {
                $args[$index] = $this->extractArgumentValue($arg->value);
            }
        }

        return $args;
    }

    /**
     * Extract value from a node.
     */
    private function extractArgumentValue(Node $node): mixed
    {
        if ($node instanceof Node\Scalar\String_) {
            return $node->value;
        }

        if ($node instanceof Node\Scalar\LNumber || $node instanceof Node\Scalar\DNumber) {
            return $node->value;
        }

        if ($node instanceof Node\Expr\ConstFetch) {
            return $node->name->toString();
        }

        // For complex expressions, return null
        return null;
    }

    /**
     * Check if file should be excluded.
     *
     * @param  array<int, string>  $excludePaths
     */
    private function shouldExcludeFile(string $filePath, array $excludePaths): bool
    {
        foreach ($excludePaths as $excludePath) {
            if (str_contains($filePath, $excludePath)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Abstract methods that must be provided by the using class.
     */
    abstract protected function setPaths(array $paths);

    abstract protected function getPhpFiles(): iterable;
}
