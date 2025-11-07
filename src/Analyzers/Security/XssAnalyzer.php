<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects potential Cross-Site Scripting (XSS) vulnerabilities.
 *
 * Checks for:
 * - Unescaped output in Blade templates ({!! $var !!})
 * - Direct echo of user input without escaping
 * - Response::make() with unescaped content
 * - HTML rendering without sanitization
 */
class XssAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'xss-detection',
            name: 'XSS Vulnerability Detector',
            description: 'Detects potential Cross-Site Scripting (XSS) vulnerabilities in views and responses',
            category: Category::Security,
            severity: Severity::High,
            tags: ['xss', 'cross-site-scripting', 'security', 'blade'],
            docsUrl: 'https://laravel.com/docs/blade#displaying-data'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Get all PHP and Blade files
        $files = $this->getPhpFiles();

        // Also scan blade files
        $bladeFiles = $this->getBladeFiles();

        foreach (array_merge($files, $bladeFiles) as $file) {
            $content = FileParser::readFile($file);
            if ($content === null) {
                continue;
            }

            $lines = FileParser::getLines($file);
            $inScriptTag = false;

            foreach ($lines as $lineNumber => $line) {
                // Track if we're inside a script tag
                if (preg_match('/<script[^>]*>/', $line)) {
                    $inScriptTag = true;
                }
                if (str_contains($line, '</script>')) {
                    $inScriptTag = false;
                }
                // Check for unescaped blade output {!! !!}
                if (preg_match('/\{!!.*?!!\}/', $line)) {
                    // Check if the variable might contain user input
                    if ($this->mightContainUserInput($line)) {
                        $issues[] = $this->createIssue(
                            message: 'Potential XSS: Unescaped blade output with possible user input',
                            location: new Location(
                                $this->getRelativePath($file),
                                $lineNumber + 1
                            ),
                            severity: Severity::High,
                            recommendation: 'Use {{ $var }} instead of {!! $var !!} or sanitize with e() helper or Purifier',
                            code: trim($line)
                        );
                    }
                }

                // Check for echo with superglobals
                if (preg_match('/echo\s+\$_(GET|POST|REQUEST|COOKIE)/', $line)) {
                    $issues[] = $this->createIssue(
                        message: 'Critical XSS: Direct echo of superglobal without escaping',
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::Critical,
                        recommendation: 'Always escape output: echo htmlspecialchars($_GET["var"], ENT_QUOTES, "UTF-8")',
                        code: trim($line)
                    );
                }

                // Check for echo with request() helper
                if (preg_match('/echo\s+.*?request\(/', $line) && ! str_contains($line, 'htmlspecialchars') && ! str_contains($line, 'e(')) {
                    $issues[] = $this->createIssue(
                        message: 'Potential XSS: Echo of request data without escaping',
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::High,
                        recommendation: 'Use e() helper or htmlspecialchars() to escape output',
                        code: trim($line)
                    );
                }

                // Check for Response::make with unescaped content
                // Use regex to match e() as a function call, not just the pattern "e("
                if (str_contains($line, 'Response::make') &&
                    ! preg_match('/\be\s*\(/', $line) &&
                    ! str_contains($line, 'htmlspecialchars')) {
                    if ($this->mightContainUserInput($line)) {
                        $issues[] = $this->createIssue(
                            message: 'Potential XSS: Response::make() with possible unescaped user input',
                            location: new Location(
                                $this->getRelativePath($file),
                                $lineNumber + 1
                            ),
                            severity: Severity::High,
                            recommendation: 'Escape user input before rendering or use response()->json() for JSON responses',
                            code: trim($line)
                        );
                    }
                }

                // Check for dangerous JavaScript output when inside script tags
                if ($inScriptTag) {
                    // Check for unescaped Blade output or superglobals in JavaScript
                    if (preg_match('/\{\{[^@].*?(\$_(GET|POST|REQUEST|COOKIE)|request\(|->get\(|->post\()/', $line) ||
                        preg_match('/@json\(\$_(GET|POST|REQUEST|COOKIE)/', $line)) {
                        $issues[] = $this->createIssue(
                            message: 'Potential XSS: User data in JavaScript without proper encoding',
                            location: new Location(
                                $this->getRelativePath($file),
                                $lineNumber + 1
                            ),
                            severity: Severity::High,
                            recommendation: 'Use @json() directive for variables or json_encode() with JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP flags',
                            code: trim($line)
                        );
                    }
                }
            }
        }

        if (empty($issues)) {
            return $this->passed('No XSS vulnerabilities detected');
        }

        return $this->failed(
            sprintf('Found %d potential XSS vulnerabilities', count($issues)),
            $issues
        );
    }

    /**
     * Get all Blade template files.
     */
    private function getBladeFiles(): array
    {
        $files = [];

        foreach ($this->getFilesToAnalyze() as $file) {
            if ($file->getExtension() === 'blade' || str_ends_with($file->getFilename(), '.blade.php')) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    /**
     * Override to include blade files.
     */
    protected function shouldAnalyzeFile(\SplFileInfo $file): bool
    {
        // Include PHP files
        if ($file->getExtension() === 'php') {
            return parent::shouldAnalyzeFile($file);
        }

        // Include blade files
        if (str_ends_with($file->getFilename(), '.blade.php')) {
            $path = $file->getPathname();

            // Check against exclude patterns
            foreach ($this->excludePatterns as $pattern) {
                if ($this->matchesPattern($path, $pattern)) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }

    /**
     * Check if the line might contain user input.
     */
    private function mightContainUserInput(string $line): bool
    {
        $userInputIndicators = [
            'request',
            '$_GET',
            '$_POST',
            '$_REQUEST',
            '$_COOKIE',
            'Input::',
            'Request::',
            '->input(',
            '->get(',
            '->post(',
            '->query(',
        ];

        foreach ($userInputIndicators as $indicator) {
            if (str_contains($line, $indicator)) {
                return true;
            }
        }

        return false;
    }
}
