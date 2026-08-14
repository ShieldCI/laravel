<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use ShieldCI\AnalyzersCore\Support\FileParser;

/**
 * Shared helpers for analyzers that reason about .env files and the env()
 * keys read by the application's config/ directory.
 *
 * Env::get() calls in config files are deliberately not scanned: a key read
 * only via Env::get() counts as "never seen in config", which keeps missing
 * variables graded conservatively (High) rather than risking a false green.
 */
trait AnalyzesEnvFiles
{
    use InspectsCode;

    /**
     * Parse environment file and return key-value pairs with error tracking.
     *
     * `variables` maps each key to its raw line; `values` maps each key to
     * its trimmed, unquoted value.
     *
     * @return array{variables: array<string, string>, values: array<string, string>, error: string|null}
     */
    protected function parseEnvFileWithErrors(string $filePath): array
    {
        if (! file_exists($filePath)) {
            return ['variables' => [], 'values' => [], 'error' => 'File does not exist'];
        }

        if (! is_readable($filePath)) {
            return ['variables' => [], 'values' => [], 'error' => 'File is not readable'];
        }

        $lines = FileParser::getLines($filePath);

        if (empty($lines)) {
            // Empty file is valid, not an error
            return ['variables' => [], 'values' => [], 'error' => null];
        }

        $variables = [];
        $values = [];

        foreach ($lines as $line) {
            $line = trim($line);

            // Skip empty lines and comments
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            // Parse KEY=VALUE format
            if (preg_match('/^([A-Z_][A-Z0-9_]*)\s*=/', $line, $matches)) {
                $key = $matches[1];
                $variables[$key] = $line;
                $values[$key] = $this->extractEnvValue($line);
            }
        }

        return ['variables' => $variables, 'values' => $values, 'error' => null];
    }

    /**
     * Parse environment file and return commented-out variables with error tracking.
     *
     * Note: Parsing errors for commented variables are non-critical and ignored.
     *
     * @return array{variables: array<string, string>, error: string|null}
     */
    protected function parseCommentedVariablesWithErrors(string $filePath): array
    {
        if (! file_exists($filePath) || ! is_readable($filePath)) {
            // Not an error - file might not exist yet or have permission issues already reported
            return ['variables' => [], 'error' => null];
        }

        $lines = FileParser::getLines($filePath);

        if (empty($lines)) {
            return ['variables' => [], 'error' => null];
        }

        $commentedVars = [];

        foreach ($lines as $line) {
            $line = trim($line);

            // Skip empty lines
            if ($line === '') {
                continue;
            }

            // Look for commented variable definitions: # KEY=VALUE or #KEY=VALUE
            if (preg_match('/^#\s*([A-Z_][A-Z0-9_]*)\s*=/', $line, $matches)) {
                $key = $matches[1];
                $commentedVars[$key] = $line;
            }
        }

        return ['variables' => $commentedVars, 'error' => null];
    }

    /**
     * Scan the application's config/ directory for env() calls and fold them
     * into per-key usage info.
     *
     * `hasDefault` is true only when every call for the key supplies a real
     * default (a bare env('KEY') or an explicit null default means the app
     * reads null when the variable is unset). `default` carries the scalar
     * default's .env textual form when it is statically known and consistent
     * across calls; null when unknown.
     *
     * @return array<string, array{hasDefault: bool, default: string|null, file: string, line: int}>
     */
    protected function collectConfigEnvKeyUsages(): array
    {
        $usages = [];

        foreach ($this->findFunctionCalls('env', ['config'], []) as $call) {
            $key = $call['args'][0] ?? null;

            if (! is_string($key) || $key === '') {
                continue; // dynamic or non-literal key
            }

            [$hasDefault, $default] = $this->classifyEnvDefault($call['node'], $call['args']);

            if (! isset($usages[$key])) {
                $usages[$key] = [
                    'hasDefault' => $hasDefault,
                    'default' => $default,
                    'file' => $call['file'],
                    'line' => $call['node']->getStartLine(),
                ];

                continue;
            }

            // Any bare/null-default call wins; the first occurrence keeps the location.
            $usages[$key]['hasDefault'] = $usages[$key]['hasDefault'] && $hasDefault;

            if (! $hasDefault || $usages[$key]['default'] !== $default) {
                $usages[$key]['default'] = null;
            }
        }

        return $usages;
    }

    /**
     * Classify the default argument of an env() call.
     *
     * Works from the raw AST node because InspectsCode extracts both a
     * ConstFetch null and the string literal 'null' to the same value, and
     * those must grade differently (no default vs. a real string default).
     *
     * @param  array<int, mixed>  $args
     * @return array{0: bool, 1: string|null}
     */
    private function classifyEnvDefault(FuncCall $node, array $args): array
    {
        if (! array_key_exists(1, $args)) {
            return [false, null]; // bare env('KEY')
        }

        $rawArg = $node->args[1] ?? null;

        if ($rawArg instanceof Node\Arg && $rawArg->value instanceof Node\Expr\ConstFetch) {
            $name = strtolower($rawArg->value->name->toString());

            if ($name === 'null') {
                return [false, null]; // env('KEY', null) behaves like a bare call
            }

            // true/false match their .env textual form; other constants are unknown values.
            return [true, in_array($name, ['true', 'false'], true) ? $name : null];
        }

        $value = $args[1];

        if (is_string($value)) {
            return [true, $value];
        }

        if (is_int($value) || is_float($value)) {
            return [true, (string) $value];
        }

        return [true, null]; // complex expression: a default exists, its value is unknown
    }

    /**
     * Extract the value portion of a KEY=VALUE line, trimmed and with
     * matching surrounding quotes stripped.
     */
    private function extractEnvValue(string $line): string
    {
        $value = trim(substr($line, (int) strpos($line, '=') + 1));

        if (strlen($value) >= 2) {
            $first = $value[0];

            if (($first === '"' || $first === "'") && str_ends_with($value, $first)) {
                $value = substr($value, 1, -1);
            }
        }

        return $value;
    }
}
