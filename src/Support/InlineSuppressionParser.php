<?php

declare(strict_types=1);

namespace ShieldCI\Support;

/**
 * Parses @shieldci-ignore inline comments from source files.
 *
 * Supports three placement styles (matching PHPStan conventions):
 *   - Previous line: `// @shieldci-ignore [analyzer-id,...]`
 *   - Same line:     `$code; // @shieldci-ignore [analyzer-id,...]`
 *   - Docblock:      Multi-line block comment with @shieldci-ignore anywhere inside it
 *
 * When no analyzer IDs are specified, the suppression applies to all analyzers.
 * Multiple IDs can be comma-separated: `@shieldci-ignore sql-injection,xss-detection`
 */
class InlineSuppressionParser
{
    /**
     * Cached file lines keyed by absolute file path.
     *
     * @var array<string, array<int, string>>
     */
    private array $fileCache = [];

    /**
     * Determine if an issue at the given file and line is suppressed for an analyzer.
     *
     * Checks the issue line itself and the line immediately above it for
     * a @shieldci-ignore comment that either targets all analyzers (bare)
     * or specifically names the given analyzer ID.
     *
     * Also handles multi-line docblocks: when the line immediately above ends
     * with the block-comment closing marker, scans backward for @shieldci-ignore.
     */
    public function isLineSuppressed(string $filePath, int $line, string $analyzerId): bool
    {
        if ($line < 1) {
            return false;
        }

        $lines = $this->getFileLines($filePath);

        if ($lines === []) {
            return false;
        }

        // Check same line and previous line (1-based to 0-based index)
        foreach ([$line - 1, $line - 2] as $index) {
            if ($index < 0 || ! isset($lines[$index])) {
                continue;
            }

            if ($this->lineHasSuppression($lines[$index], $analyzerId)) {
                return true;
            }
        }

        // If the line immediately above ends with */, scan backward through the block comment
        $prevIdx = $line - 2; // 0-based index of the line immediately above the issue
        if ($prevIdx >= 0 && isset($lines[$prevIdx]) && str_ends_with(rtrim($lines[$prevIdx]), '*/')) {
            for ($i = $prevIdx - 1; $i >= 0 && $i >= $prevIdx - 50; $i--) {
                if ($this->lineHasSuppression($lines[$i], $analyzerId)) {
                    return true;
                }
                if (str_contains($lines[$i], '/*')) {
                    break;
                }
            }
        }

        return false;
    }

    /**
     * Check if a single line of text contains a matching @shieldci-ignore comment.
     */
    private function lineHasSuppression(string $lineContent, string $analyzerId): bool
    {
        // Match @shieldci-ignore optionally followed by comma-separated analyzer IDs
        if (! preg_match('/@shieldci-ignore(?:\s+([\w,-]+))?/i', $lineContent, $matches)) {
            return false;
        }

        // Bare @shieldci-ignore — suppresses all analyzers
        if (! isset($matches[1])) {
            return true;
        }

        // Specific analyzer IDs — check if our analyzer is listed
        $ids = array_map('trim', explode(',', $matches[1]));

        return in_array($analyzerId, $ids, true);
    }

    /**
     * Read and cache file lines for a given path.
     *
     * @return array<int, string>
     */
    private function getFileLines(string $filePath): array
    {
        if (isset($this->fileCache[$filePath])) {
            return $this->fileCache[$filePath];
        }

        if (! is_file($filePath) || ! is_readable($filePath)) {
            $this->fileCache[$filePath] = [];

            return [];
        }

        $content = file_get_contents($filePath);

        if ($content === false) {
            $this->fileCache[$filePath] = [];

            return [];
        }

        $this->fileCache[$filePath] = explode("\n", $content);

        return $this->fileCache[$filePath];
    }
}
