<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use PhpParser\Node;
use PhpParser\Node\ArrayItem;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\Return_;
use PhpParser\NodeFinder;
use ShieldCI\AnalyzersCore\Support\AstParser;

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
    private AstParser $parser;

    /**
     * Initialize the AST parser.
     */
    private function initializeParser(): void
    {
        if (! isset($this->parser)) {
            $this->parser = new AstParser;
        }
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
     * Handles value types: String_, LNumber, DNumber, ConstFetch (true/false/null), FuncCall (env()).
     *
     * @return array<string, array{value: mixed, line: int, isEnvCall: bool, envDefault: mixed}>
     */
    protected function parseConfigArray(string $filePath): array
    {
        $this->initializeParser();

        $ast = $this->parser->parseFile($filePath);

        if ($ast === []) {
            return [];
        }

        $nodeFinder = new NodeFinder;

        /** @var Return_|null $returnNode */
        $returnNode = $nodeFinder->findFirstInstanceOf($ast, Return_::class);

        if (! $returnNode instanceof Return_ || ! $returnNode->expr instanceof Array_) {
            return [];
        }

        $result = [];

        foreach ($returnNode->expr->items as $item) {
            if (! $item instanceof ArrayItem) {
                continue;
            }

            if (! $item->key instanceof Node\Scalar\String_) {
                continue;
            }

            $key = $item->key->value;
            $line = $item->getStartLine();
            $isEnvCall = false;
            $envDefault = null;
            $value = $this->extractConfigValue($item->value);

            if ($item->value instanceof FuncCall
                && $item->value->name instanceof Name
                && $item->value->name->toString() === 'env'
            ) {
                $isEnvCall = true;
                $value = null;

                if (isset($item->value->args[1])) {
                    $envDefault = $this->extractConfigValue($item->value->args[1]->value);
                }
            }

            $result[$key] = [
                'value' => $value,
                'line' => $line,
                'isEnvCall' => $isEnvCall,
                'envDefault' => $envDefault,
            ];
        }

        return $result;
    }

    /**
     * Extract a typed PHP value from an AST node.
     *
     * Returns actual PHP values: true, false, null for constants;
     * string for String_ nodes; int/float for numeric nodes.
     */
    private function extractConfigValue(Node $node): mixed
    {
        if ($node instanceof Node\Scalar\String_) {
            return $node->value;
        }

        if ($node instanceof Node\Scalar\LNumber || $node instanceof Node\Scalar\DNumber) {
            return $node->value;
        }

        if ($node instanceof ConstFetch) {
            return match (strtolower($node->name->toString())) {
                'true' => true,
                'false' => false,
                'null' => null,
                default => $node->name->toString(),
            };
        }

        return null;
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
            $args[$index] = $this->extractArgumentValue($arg->value);
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
