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
     * Maximum number of neutral lines (blank comments) allowed within a block.
     * Allows blocks to continue even with spacing like:
     * // $foo = 1;
     * //
     * // $bar = 2;
     */
    private int $maxNeutralLines = 2;

    /**
     * Code pattern indicators with weights.
     * Higher weights = stronger indicators of code vs documentation.
     *
     * @var array<string, int>
     */
    private array $codePatterns = [
        // Strong indicators (weight: 4) - Structural declarations
        '/function\s+[a-zA-Z_]/' => 4,      // Function definitions
        '/public|private|protected/' => 4,  // Visibility modifiers
        '/class\s+[A-Z]/' => 4,             // Class declarations
        '/namespace\s+/' => 4,              // Namespace declarations
        '/use\s+[A-Z]/' => 4,               // Use statements

        // Medium indicators (weight: 2) - Control flow and operations
        '/if\s*\(/' => 2,                   // If statements
        '/foreach\s*\(/' => 2,              // Foreach loops
        '/while\s*\(/' => 2,                // While loops
        '/return\s+/' => 2,                 // Return statements
        '/new\s+[A-Z]/' => 2,               // Object instantiation
        '/[A-Z][a-zA-Z]*\:\:[a-zA-Z_]/' => 2, // Static method calls (User::find)

        // Weak indicators (weight: 1) - Common in documentation examples
        '/\$[a-zA-Z_]/' => 1,               // Variables (often mentioned in docs)
        '/\-\>/' => 1,                      // Method calls (common in inline examples)
        '/\=\>/' => 1,                      // Array arrows
        '/\s=\s/' => 1,                     // Assignment operator (distinguishes code from prose)
        '/;/' => 1,                         // Semicolons (code terminator)
    ];

    /**
     * Minimum score threshold to classify content as code.
     * Prevents single weak indicators from triggering false positives.
     *
     * Threshold of 2 allows:
     * - Medium indicators: return, if, foreach, User::find() (score 2)
     * - Combined weak: $var = value; (score 1+1+1=3), $obj->method() (score 1+1=2)
     * - Strong indicators: function, class, visibility (score 4+)
     *
     * But rejects false positives:
     * - Single weak: just "$variable" mentioned in docs (score 1)
     * - Prose: "Set the $variable" (score 1)
     * - Examples: "Use User::class" (score 1, no method call)
     */
    private int $codeScoreThreshold = 2;

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
        $singleLineBlocks = $this->findSingleLineCommentBlocks($content, $minLines);
        $blockCommentBlocks = $this->findBlockCommentBlocks($content, $minLines);

        // Merge and sort by line number
        $allBlocks = array_merge($singleLineBlocks, $blockCommentBlocks);
        usort($allBlocks, fn ($a, $b) => $a['startLine'] <=> $b['startLine']);

        return $allBlocks;
    }

    /**
     * Find single-line comment blocks.
     *
     * @return array<int, array{startLine: int, endLine: int, lineCount: int, preview: string}>
     */
    private function findSingleLineCommentBlocks(string $content, int $minLines): array
    {
        $lines = explode("\n", $content);
        $blocks = [];
        $currentBlock = null;
        $neutralLineCount = 0;

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
                        $neutralLineCount = 0;
                    } else {
                        // Continue current block (reset neutral line counter)
                        $currentBlock['endLine'] = $lineNumber + 1;
                        $currentBlock['lineCount']++;
                        $currentBlock['lines'][] = $commentContent;
                        $neutralLineCount = 0;
                    }
                } else {
                    // Neutral comment line (e.g., blank comment //)
                    if ($currentBlock !== null) {
                        $neutralLineCount++;

                        // Allow a few neutral lines within a block
                        if ($neutralLineCount <= $this->maxNeutralLines) {
                            // Continue block, but don't add neutral line to preview
                            $currentBlock['endLine'] = $lineNumber + 1;
                            // Don't increment lineCount for neutral lines
                        } else {
                            // Too many neutral lines, end the block
                            if ($currentBlock['lineCount'] >= $minLines) {
                                $currentBlock['preview'] = $this->getPreview($currentBlock['lines']);
                                $blocks[] = $currentBlock;
                            }
                            $currentBlock = null;
                            $neutralLineCount = 0;
                        }
                    }
                }
            } else {
                // Not a comment, end current block if any
                if ($currentBlock !== null && $currentBlock['lineCount'] >= $minLines) {
                    $currentBlock['preview'] = $this->getPreview($currentBlock['lines']);
                    $blocks[] = $currentBlock;
                }
                $currentBlock = null;
                $neutralLineCount = 0;
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
     * Find block comment blocks using tokenization.
     *
     * @return array<int, array{startLine: int, endLine: int, lineCount: int, preview: string}>
     */
    private function findBlockCommentBlocks(string $content, int $minLines): array
    {
        $blocks = [];

        // Tokenize the content
        $tokens = @token_get_all($content);

        foreach ($tokens as $token) {
            if (! is_array($token)) {
                continue;
            }

            [$tokenType, $tokenContent, $tokenLine] = $token;

            // Only process T_COMMENT tokens (block comments /* */)
            // Exclude T_DOC_COMMENT (/** */) - those are documentation
            if ($tokenType !== T_COMMENT) {
                continue;
            }

            // Only process block comments (/* ... */)
            // Skip single-line // and # comments (already handled)
            if (! str_starts_with($tokenContent, '/*')) {
                continue;
            }

            // Skip PHPDoc comments (/** ... */)
            if (str_starts_with($tokenContent, '/**')) {
                continue;
            }

            // Extract comment content (remove /* and */)
            $commentContent = $this->extractBlockCommentContent($tokenContent);

            // Count lines in the comment
            $commentLines = explode("\n", $commentContent);
            $lineCount = count($commentLines);

            // Only process multi-line blocks
            if ($lineCount < $minLines) {
                continue;
            }

            // Check if the comment content looks like code
            $codeLineCount = 0;
            $codeLines = [];

            foreach ($commentLines as $line) {
                $trimmed = trim($line);
                // Remove leading * if present (common in block comments)
                $trimmed = ltrim($trimmed, '* ');

                if ($this->looksLikeCode($trimmed)) {
                    $codeLineCount++;
                    $codeLines[] = $trimmed;
                }
            }

            // If majority of lines look like code, flag it
            if ($codeLineCount >= max(1, (int) ($lineCount * 0.5))) {
                $endLine = $tokenLine + $lineCount - 1;

                $blocks[] = [
                    'startLine' => $tokenLine,
                    'endLine' => $endLine,
                    'lineCount' => $lineCount,
                    'preview' => $this->getPreview($codeLines),
                ];
            }
        }

        return $blocks;
    }

    /**
     * Extract content from block comment (remove opening and closing markers).
     */
    private function extractBlockCommentContent(string $comment): string
    {
        // Remove opening /* and closing */
        $content = preg_replace('/^\/\*+/', '', $comment);
        $content = preg_replace('/\*+\/$/', '', $content ?? '');

        return trim($content ?? '');
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

        // Calculate weighted score for code patterns
        $score = 0;
        foreach ($this->codePatterns as $pattern => $weight) {
            if (preg_match($pattern, $content)) {
                $score += $weight;
            }
        }

        // Require minimum threshold score to classify as code
        // This prevents single weak indicators (like $variable mentions) from triggering
        return $score >= $this->codeScoreThreshold;
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
