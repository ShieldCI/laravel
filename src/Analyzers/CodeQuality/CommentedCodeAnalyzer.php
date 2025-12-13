<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\CodeQuality;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

/**
 * Detects commented-out code that should be removed.
 *
 * Checks for:
 * - Code-like patterns in comments
 * - Multiple consecutive commented lines
 * - Common code indicators (function calls, assignments, etc.)
 * - Excludes genuine documentation comments
 */
class CommentedCodeAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Minimum consecutive commented lines to flag.
     */
    private int $minConsecutiveLines = 3;

    /**
     * Code pattern indicators.
     *
     * @var array<string>
     */
    private array $codePatterns = [
        '/\$[a-zA-Z_]/',                    // Variables
        '/function\s+[a-zA-Z_]/',           // Functions
        '/public|private|protected/',       // Visibility
        '/class\s+[A-Z]/',                  // Classes
        '/if\s*\(/',                        // If statements
        '/foreach\s*\(/',                   // Foreach loops
        '/while\s*\(/',                     // While loops
        '/return\s+/',                      // Return statements
        '/new\s+[A-Z]/',                    // Object instantiation
        '/\-\>/',                           // Method calls
        '/\:\:/',                           // Static calls
        '/\=\>/',                           // Array arrows
        '/use\s+[A-Z]/',                    // Use statements
        '/namespace\s+/',                   // Namespace
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'commented-code',
            name: 'Commented Code Analyzer',
            description: 'Detects commented-out code that should be removed in favor of version control',
            category: Category::CodeQuality,
            severity: Severity::Low,
            tags: ['maintainability', 'code-quality', 'comments', 'dead-code', 'version-control'],
            docsUrl: 'https://docs.shieldci.com/analyzers/code-quality/commented-code',
            timeToFix: 5
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $minLines = $this->minConsecutiveLines;

        foreach ($this->getPhpFiles() as $file) {
            $content = FileParser::readFile($file);

            if ($content === null) {
                continue;
            }

            $commentedBlocks = $this->findCommentedCodeBlocks($content, $minLines);

            foreach ($commentedBlocks as $block) {
                $issues[] = $this->createIssueWithSnippet(
                    message: "Found {$block['lineCount']} consecutive lines of commented-out code",
                    filePath: $file,
                    lineNumber: $block['startLine'],
                    severity: $this->getSeverityForBlock($block['lineCount']),
                    recommendation: $this->getRecommendation($block['lineCount']),
                    column: null,
                    contextLines: null,
                    code: 'commented-code',
                    metadata: [
                        'startLine' => $block['startLine'],
                        'endLine' => $block['endLine'],
                        'lineCount' => $block['lineCount'],
                        'preview' => $block['preview'],
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('No commented-out code blocks detected');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} block(s) of commented-out code",
            $issues
        );
    }

    /**
     * Find blocks of commented code.
     *
     * @return array<int, array{startLine: int, endLine: int, lineCount: int, preview: string}>
     */
    private function findCommentedCodeBlocks(string $content, int $minLines): array
    {
        $lines = explode("\n", $content);
        $blocks = [];
        $currentBlock = null;

        foreach ($lines as $lineNumber => $line) {
            $trimmed = trim($line);

            // Check if line is a single-line comment
            if ($this->isSingleLineComment($trimmed)) {
                $commentContent = $this->extractCommentContent($trimmed);

                // Check if comment content looks like code
                if ($this->looksLikeCode($commentContent)) {
                    if ($currentBlock === null) {
                        // Start new block
                        $currentBlock = [
                            'startLine' => $lineNumber + 1,
                            'endLine' => $lineNumber + 1,
                            'lineCount' => 1,
                            'lines' => [$commentContent],
                        ];
                    } else {
                        // Continue current block
                        $currentBlock['endLine'] = $lineNumber + 1;
                        $currentBlock['lineCount']++;
                        $currentBlock['lines'][] = $commentContent;
                    }
                } else {
                    // Non-code comment, end current block if any
                    if ($currentBlock !== null && $currentBlock['lineCount'] >= $minLines) {
                        $currentBlock['preview'] = $this->getPreview($currentBlock['lines']);
                        $blocks[] = $currentBlock;
                    }
                    $currentBlock = null;
                }
            } else {
                // Not a comment, end current block if any
                if ($currentBlock !== null && $currentBlock['lineCount'] >= $minLines) {
                    $currentBlock['preview'] = $this->getPreview($currentBlock['lines']);
                    $blocks[] = $currentBlock;
                }
                $currentBlock = null;
            }
        }

        // Check final block
        if ($currentBlock !== null && $currentBlock['lineCount'] >= $minLines) {
            $currentBlock['preview'] = $this->getPreview($currentBlock['lines']);
            $blocks[] = $currentBlock;
        }

        return $blocks;
    }

    /**
     * Check if line is a single-line comment.
     */
    private function isSingleLineComment(string $line): bool
    {
        return str_starts_with($line, '//') || str_starts_with($line, '#');
    }

    /**
     * Extract comment content without comment markers.
     */
    private function extractCommentContent(string $line): string
    {
        // Remove leading comment markers
        $content = preg_replace('/^(\/\/|#)\s*/', '', $line);

        return trim($content ?? '');
    }

    /**
     * Check if comment content looks like code.
     */
    private function looksLikeCode(string $content): bool
    {
        // Empty content
        if (strlen($content) === 0) {
            return false;
        }

        // Short structural code elements (braces, semicolons, etc.)
        if (strlen($content) < 5) {
            // Allow structural characters that indicate code
            return preg_match('/^[{};\[\]\(\)]$/', trim($content)) === 1;
        }

        // Exclude common documentation patterns
        if ($this->isDocumentation($content)) {
            return false;
        }

        // Check for code patterns
        $matches = 0;
        foreach ($this->codePatterns as $pattern) {
            if (preg_match($pattern, $content)) {
                $matches++;
            }
        }

        // If code patterns match, likely code
        return $matches >= 1;
    }

    /**
     * Check if content is documentation.
     */
    private function isDocumentation(string $content): bool
    {
        // Common documentation patterns
        $docPatterns = [
            '/^TODO/',
            '/^FIXME/',
            '/^NOTE/',
            '/^XXX/',
            '/^HACK/',
            '/^BUG/',
            '/^@param/',
            '/^@return/',
            '/^@throws/',
            '/^\*/',
            '/^Description:/',
            '/^Example:/',
            '/^Usage:/',
        ];

        foreach ($docPatterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        // Check if it's prose (contains common English words)
        $proseWords = ['the', 'this', 'that', 'with', 'from', 'should', 'will', 'can', 'may'];
        foreach ($proseWords as $word) {
            // Use word boundaries to match at sentence boundaries too
            if (preg_match('/\b'.preg_quote($word, '/').'\b/i', $content)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get preview of commented code.
     *
     * @param  array<string>  $lines
     */
    private function getPreview(array $lines): string
    {
        $preview = implode("\n", array_slice($lines, 0, 3));

        if (count($lines) > 3) {
            $preview .= "\n... (".(count($lines) - 3).' more lines)';
        }

        return $preview;
    }

    /**
     * Get severity based on block size.
     */
    private function getSeverityForBlock(int $lineCount): Severity
    {
        if ($lineCount >= 20) {
            return Severity::Medium;
        }

        return Severity::Low;
    }

    /**
     * Get recommendation for commented code.
     */
    private function getRecommendation(int $lineCount): string
    {
        return "Found {$lineCount} consecutive lines of commented-out code. Commented code clutters the codebase and creates maintenance confusion. Delete the commented code - version control (Git) preserves history.";
    }
}
