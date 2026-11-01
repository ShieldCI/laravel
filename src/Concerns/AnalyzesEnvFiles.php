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

    abstract protected function getBasePath(): string;

    /**
     * Parse environment file and return key-value pairs with error tracking.
     *
     * `variables` maps each key to its raw line; `values` maps each key to
     * its value as dotenv reads it, without quotes or inline comment.
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

        foreach ($this->envEntries($lines) as $line) {
            $line = trim($line);

            // Skip empty lines and comments
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            $key = $this->envEntryName($line);

            if ($key !== null) {
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

        foreach ($this->envEntries($lines) as $line) {
            $line = trim($line);

            // Look for commented variable definitions: # KEY=VALUE or #KEY=VALUE
            if (! str_starts_with($line, '#')) {
                continue;
            }

            $key = $this->envEntryName(ltrim(substr($line, 1)));

            if ($key !== null) {
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
     * Harvest the env() key names read by installed packages' own config
     * files (vendor/{vendor}/{package}/config/*.php, which on Laravel 11+
     * also covers vendor/laravel/framework/config).
     *
     * A published vendor config's keys are vendor-owned: they are not the
     * application's documentation debt, so completeness checks should never
     * flag them. Keys the app ADDS to a published copy are absent from the
     * vendor original and stay visible.
     *
     * Uses a regex rather than the AST: only key names are needed here, and
     * PCRE \s spans newlines so multi-line env() calls are matched.
     *
     * @return array<string, true>
     */
    protected function collectVendorConfigEnvKeys(): array
    {
        $basePath = $this->getBasePath();

        if ($basePath === '') {
            return [];
        }

        $keys = [];
        $files = glob($basePath.'/vendor/*/*/config/*.php') ?: [];

        foreach ($files as $file) {
            $contents = @file_get_contents($file);

            if ($contents === false) {
                continue;
            }

            if (preg_match_all("/env\\(\\s*'([A-Za-z0-9_]+)'/", $contents, $matches) > 0) {
                foreach ($matches[1] as $key) {
                    $keys[$key] = true;
                }
            }
        }

        return $keys;
    }

    /**
     * Collect the basenames of installed packages' config files
     * (vendor/{vendor}/{package}/config/*.php, framework stubs included).
     *
     * A key read in an app config file sharing a vendor config's basename
     * lives in stock-file territory, where skeleton and vendor stubs drift
     * apart key by key (a skeleton services.php reads keys no framework
     * stub does), so name-level provenance is the drift-proof signal.
     *
     * @return array<string, true>
     */
    protected function collectVendorConfigFileNames(): array
    {
        $basePath = $this->getBasePath();

        if ($basePath === '') {
            return [];
        }

        $names = [];

        foreach (glob($basePath.'/vendor/*/*/config/*.php') ?: [] as $file) {
            $names[basename($file)] = true;
        }

        return $names;
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
     * Group raw .env lines into entries as dotenv's Lines::process does: a line that
     * opens a double-quoted value without closing it runs on until a line holding an
     * unescaped quote, so lines inside a multi-line value are never read as definitions.
     * A value still open at the end of the file is dropped, as dotenv drops it.
     *
     * @param  array<int, string>  $lines
     * @return list<string>
     */
    private function envEntries(array $lines): array
    {
        $entries = [];
        $buffer = null;

        foreach ($lines as $line) {
            $line = rtrim($line, "\r\n");

            if ($buffer !== null) {
                $buffer .= "\n".$line;

                if ($line === '"' || $this->unescapedQuotes($line) >= 1) {
                    $entries[] = $buffer;
                    $buffer = null;
                }

                continue;
            }

            $open = strpos($line, '="');
            $hash = strpos($line, '#');

            if ($open !== false && ($hash === false || $hash > $open) && $this->unescapedQuotes($line) <= 1) {
                $buffer = $line;

                continue;
            }

            $entries[] = $line;
        }

        return $entries;
    }

    /**
     * Count the quotes dotenv treats as unescaped when finding where a multi-line value ends.
     */
    private function unescapedQuotes(string $line): int
    {
        return (int) preg_match_all('/(?=([^\\\\]"))/', str_replace('\\\\', '', $line));
    }

    /**
     * The variable name a KEY=VALUE entry assigns, or null when dotenv would reject it.
     *
     * Mirrors dotenv's EntryParser: the name before the first `=`, with an optional
     * export prefix and optional matching quotes, made of letters, digits, `_` and `.`.
     */
    private function envEntryName(string $line): ?string
    {
        $equals = strpos($line, '=');

        if ($equals === false) {
            return null;
        }

        $name = trim(substr($line, 0, $equals));

        return preg_match('/\A(?:export\s+)?(["\']?)([\p{Ll}\p{Lu}\p{M}\p{N}_.]+)\1\z/u', $name, $matches) === 1 ? $matches[2] : null;
    }

    /**
     * The value a KEY=VALUE entry assigns, read as dotenv's EntryParser reads it.
     *
     * An unquoted value ends at the first `#`, and whitespace may only precede that `#`.
     * A quoted value ends at its closing quote,
     * and only whitespace or a comment may follow it; double-quoted escapes are decoded,
     * single-quoted values are literal. ${VAR} references are left unresolved. A value
     * dotenv rejects is returned trimmed but otherwise as written.
     */
    private function extractEnvValue(string $line): string
    {
        $value = trim(substr($line, (int) strpos($line, '=') + 1));
        $quote = $value[0] ?? '';

        if ($quote !== '"' && $quote !== "'") {
            $hash = strpos($value, '#');
            $parsed = $hash === false ? $value : rtrim(substr($value, 0, $hash));

            return preg_match('/\s/', $parsed) === 1 ? $value : $parsed;
        }

        $parsed = '';
        $length = strlen($value);

        for ($i = 1; $i < $length; $i++) {
            $char = $value[$i];

            if ($char === $quote) {
                $rest = ltrim(substr($value, $i + 1));

                return $rest === '' || $rest[0] === '#' ? $parsed : $value;
            }

            if ($quote === '"' && $char === '\\') {
                $escaped = match ($value[++$i] ?? '') {
                    '"', '\\', '$' => $value[$i],
                    'f' => "\f",
                    'n' => "\n",
                    'r' => "\r",
                    't' => "\t",
                    'v' => "\v",
                    default => null,
                };

                if ($escaped === null) {
                    return $value;
                }

                $char = $escaped;
            }

            $parsed .= $char;
        }

        return $value;
    }
}
