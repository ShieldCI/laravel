<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use GuzzleHttp\Client;
use Illuminate\Routing\Router;
use Illuminate\Support\Str;
use Psr\Http\Message\ResponseInterface;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\AnalyzesHeaders;
use ShieldCI\Concerns\FindsLoginRoute;
use SplFileInfo;
use Throwable;

/**
 * Detects XSS vulnerabilities through dual analysis:
 * 1. Static code analysis (always runs) - finds code-level vulnerabilities
 * 2. HTTP header verification (production only) - validates CSP headers
 *
 * Static analysis includes:
 * - Unescaped Blade output ({!! $var !!})
 * - JavaScript context injection
 * - HTML attribute context (href, src, event handlers, data-*)
 * - Direct echo of superglobals
 * - Request data without escaping
 *
 * Provides defense-in-depth protection against XSS attacks.
 */
class XssAnalyzer extends AbstractFileAnalyzer
{
    use AnalyzesHeaders;
    use FindsLoginRoute;

    /**
     * Skip HTTP checks in CI (requires live server).
     */
    private bool $skipHttpChecks = false;

    /**
     * Safe JavaScript no-op patterns that don't execute code.
     *
     * @var array<string>
     */
    private const SAFE_JAVASCRIPT_PATTERNS = [
        'javascript:;',
        'javascript:void(0)',
        'javascript:void(0);',
    ];

    /**
     * Functions that URL-encode user input, making it safe in URL context.
     *
     * @var array<string>
     */
    private const URL_SAFE_FUNCTIONS = [
        'http_build_query',
        'urlencode',
        'rawurlencode',
    ];

    public function __construct(Router $router)
    {
        $this->router = $router;
        $this->client = new Client;

        // Skip HTTP checks in CI mode
        $this->skipHttpChecks = config('shieldci.ci_mode', false);
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'xss-vulnerabilities',
            name: 'XSS Vulnerabilities Analyzer',
            description: 'Detects XSS vulnerabilities via code analysis and HTTP header verification (dual protection)',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['xss', 'cross-site-scripting', 'security', 'blade', 'csp', 'headers'],
            timeToFix: 30
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // PART 1: Static Code Analysis (always runs)
        $staticIssues = $this->analyzeCodePatterns();
        $issues = array_merge($issues, $staticIssues);

        // PART 2: HTTP Header Analysis (production only)
        if (! $this->skipHttpChecks) {
            $headerIssues = $this->analyzeHttpHeaders();
            $issues = array_merge($issues, $headerIssues);
        }

        if (empty($issues)) {
            return $this->passed(
                $this->skipHttpChecks
                    ? 'No XSS vulnerabilities detected in code'
                    : 'No XSS vulnerabilities detected (code and headers verified)'
            );
        }

        return $this->resultBySeverity(
            sprintf('Found %d XSS issue(s)', count($issues)),
            $issues
        );
    }

    /**
     * PART 1: Static Code Analysis.
     *
     * Analyzes PHP and Blade files for XSS vulnerabilities:
     * - Unescaped blade output ({!! $var !!})
     * - Direct echo of superglobals
     * - Request data without escaping
     * - Response::make() with user input
     * - Unsafe JavaScript injection
     *
     * @return array<\ShieldCI\AnalyzersCore\ValueObjects\Issue>
     */
    private function analyzeCodePatterns(): array
    {
        $issues = [];

        foreach ($this->getAnalyzableFiles() as $file) {
            $content = FileParser::readFile($file);
            if ($content === null) {
                continue;
            }

            $lines = FileParser::getLines($file);
            $inScriptTag = false;

            foreach ($lines as $lineNumber => $line) {
                if (! is_string($line)) {
                    continue;
                }

                // Track if we're inside a script tag (handle single-line and multiline)
                $hasOpeningTag = preg_match('/<script[^>]*>/', $line);
                $hasClosingTag = str_contains($line, '</script>');

                $exitScriptAfterLine = false;
                if ($hasOpeningTag && $hasClosingTag) {
                    // Single-line <script>...</script> - treat content as inside script
                    // (will be checked in the inScriptTag section)
                    $inScriptTag = true;
                    $exitScriptAfterLine = true;
                } elseif ($hasOpeningTag) {
                    // Opening tag without closing - enter script block
                    $inScriptTag = true;

                    continue; // Skip the opening tag line itself
                } elseif ($hasClosingTag) {
                    // Closing tag - exit script block AFTER processing this line
                    // (set flag to exit after checks)
                    $exitScriptAfterLine = true;
                } else {
                    $exitScriptAfterLine = false;
                }

                $rawBladeMatched = false;

                // Check for unescaped blade output {!! !!}
                if (preg_match('/\{!!\s*(__|trans|csrf_field)\(/', $line)) {
                    continue;
                }

                if (preg_match('/\{!!.*?!!\}/', $line) && $this->mightContainUserInput($line)) {
                    $rawBladeMatched = true;

                    $issues[] = $this->createIssueWithSnippet(
                        message: 'Critical XSS: Unescaped blade output with possible user input',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::Critical,
                        recommendation: 'Use {{ $var }} instead of {!! $var !!} or sanitize with e() helper or Purifier'
                    );
                }

                // Check for echo with superglobals
                if (preg_match('/echo\s+\$_(GET|POST|REQUEST|COOKIE)/', $line)) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'Critical XSS: Direct echo of superglobal without escaping',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::Critical,
                        recommendation: 'Always escape output: echo htmlspecialchars($_GET["var"], ENT_QUOTES, "UTF-8")'
                    );
                }

                // Check for echo with request() helper
                if (preg_match('/echo\s+.*?request\(/', $line) && ! str_contains($line, 'htmlspecialchars') && ! str_contains($line, 'e(')) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'Potential XSS: Echo of request data without escaping',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::High,
                        recommendation: 'Use e() helper or htmlspecialchars() to escape output'
                    );
                }

                // Detect unescaped response bodies containing user input
                $isResponseConstructor =
                    preg_match('/\bResponse::make\s*\(/', $line) ||
                    preg_match('/\bresponse\s*\(\s*.*(request\(|\$_(GET|POST|REQUEST|COOKIE)|\$request)/', $line) ||
                    preg_match('/\bresponse\s*\(\s*\)\s*->\s*make\s*\(/', $line) ||
                    preg_match('/\bresponse\s*\(\s*\)\s*->\s*view\s*\(/', $line);

                $isSafeResponse =
                    preg_match('/\be\s*\(/', $line) ||
                    str_contains($line, 'htmlspecialchars') ||
                    preg_match('/response\s*\(\s*\)\s*->\s*json\s*\(/', $line) ||
                    str_contains($line, 'JsonResponse');

                if ($isResponseConstructor && ! $isSafeResponse && $this->mightContainUserInput($line)) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'Potential XSS: HTTP response body contains unescaped user input',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::High,
                        recommendation: 'Escape output using e() or htmlspecialchars(), or return JSON responses with response()->json()'
                    );
                }

                // Check for HTML attribute context XSS vulnerabilities
                $attributeIssues = $this->checkHtmlAttributeContext($line, $file, $lineNumber);
                $issues = array_merge($issues, $attributeIssues);

                // Check for dangerous JavaScript output when inside script tags
                $isBladeOutput = preg_match('/\{\{.*?\}\}|\{!!.*?!!\}/', $line);
                $isRawBlade = preg_match('/\{!!.*?!!\}/', $line);
                $isTainted = $this->mightContainUserInput($line);
                $isEncoded = preg_match('/@json\s*\(|json_encode\s*\(|Js::from\s*\(/', $line);
                $isJsString = preg_match('/([=\(,]\s*[\'"]\s*\{\{.*?\}\}\s*[\'"])/', $line);
                if ($inScriptTag && ! $rawBladeMatched && $isBladeOutput && $isTainted && ! $isEncoded) {
                    // Check for unescaped Blade output or superglobals in JavaScript
                    $severity = $isRawBlade || $isJsString
                        ? Severity::Critical
                        : Severity::High;

                    $issues[] = $this->createIssueWithSnippet(
                        message: $isJsString ? 'Critical XSS: User input injected into JavaScript string context' : 'Potential XSS: User data injected into JavaScript without proper encoding',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: $severity,
                        recommendation: 'Use @json() directive for variables, Js::from(), or json_encode() with JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP flags'
                    );
                }

                // Exit script tag after processing closing tag line
                if ($exitScriptAfterLine) {
                    $inScriptTag = false;
                }
            }
        }

        return $issues;
    }

    protected function shouldAnalyzeFile(SplFileInfo $file): bool
    {
        if ($file->getExtension() === 'php' && ! $this->isBladeFile($file)) {
            return parent::shouldAnalyzeFile($file);
        }

        if ($this->isBladeFile($file)) {
            return ! $this->isExcludedPath($file->getPathname());
        }

        return false;
    }

    /**
     * Check if the line might contain user input.
     */
    private function mightContainUserInput(string $line): bool
    {
        // Superglobals - always user input
        $superglobals = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES'];
        foreach ($superglobals as $superglobal) {
            if (str_contains($line, $superglobal)) {
                return true;
            }
        }

        // Laravel Request/Input facades
        if (str_contains($line, 'Input::') || str_contains($line, 'Request::')) {
            return true;
        }

        // request() helper function
        if (preg_match('/\brequest\s*\(/', $line)) {
            return true;
        }

        // Request object methods (context-aware)
        // Only flag ->get(), ->post(), etc. if preceded by $request or request context
        if (preg_match('/(\$request|request\(.*?\))\s*->\s*(input|get|post|query|cookie)\s*\(/', $line)) {
            return true;
        }

        // old() helper function
        if (preg_match('/\bold\s*\(/', $line)) {
            return true;
        }

        return false;
    }

    /**
     * Check if JavaScript pattern is a safe no-op (doesn't execute code).
     */
    private function isSafeJavaScriptPattern(string $line): bool
    {
        foreach (self::SAFE_JAVASCRIPT_PATTERNS as $pattern) {
            // Match the pattern as the entire javascript: value in href or src
            $regex = '/(?:href|src)\s*=\s*["\']?'.preg_quote($pattern, '/').'["\']?/i';
            if (preg_match($regex, $line)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if user input is wrapped in URL-encoding functions.
     */
    private function isUrlSafeContext(string $attributeValue): bool
    {
        foreach (self::URL_SAFE_FUNCTIONS as $function) {
            // Check if the user input is inside a URL-safe function call
            if (preg_match('/\b'.preg_quote($function, '/').'\s*\([^)]*(?:request\(|Request::|Input::|\$_)/i', $attributeValue)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract the value of an HTML attribute from a line.
     *
     * @param  string  $attributeName  The attribute name (e.g., 'href', 'src')
     * @param  string  $line  The line of code to search
     * @return string|null The attribute value, or null if not found
     */
    private function extractAttributeValue(string $attributeName, string $line): ?string
    {
        // Match attribute="value" with double quotes
        $patternDouble = '/'.preg_quote($attributeName, '/').'\s*=\s*"([^"]*)"/i';
        if (preg_match($patternDouble, $line, $matches)) {
            return $matches[1];
        }

        // Match attribute='value' with single quotes
        $patternSingle = '/'.preg_quote($attributeName, '/')."\s*=\s*'([^']*)'/i";
        if (preg_match($patternSingle, $line, $matches)) {
            return $matches[1];
        }

        return null;
    }

    /**
     * Check for XSS vulnerabilities in HTML attribute contexts.
     *
     * Detects dangerous patterns in HTML attributes:
     * - javascript: and data: protocols in href/src
     * - User input in event handler attributes (onclick, onerror, etc.)
     * - User input in data-* attributes
     * - Unescaped output in URL attributes
     *
     * @return array<\ShieldCI\AnalyzersCore\ValueObjects\Issue>
     */
    private function checkHtmlAttributeContext(string $line, string $file, int $lineNumber): array
    {
        $issues = [];

        // Check for javascript: protocol (Critical - immediate XSS risk)
        // Skip safe no-op patterns like javascript:; or javascript:void(0)
        if (preg_match('/(?:href|src|action|formaction)\s*=\s*["\']?\s*javascript:/i', $line)) {
            // Skip safe no-op patterns
            if (! $this->isSafeJavaScriptPattern($line)) {
                $hasUserInput = $this->mightContainUserInput($line);
                $issues[] = $this->createIssueWithSnippet(
                    message: $hasUserInput
                        ? 'Critical XSS: javascript: protocol with user input in HTML attribute'
                        : 'High: javascript: protocol with executable code in HTML attribute',
                    filePath: $file,
                    lineNumber: $lineNumber + 1,
                    severity: $hasUserInput ? Severity::Critical : Severity::High,
                    recommendation: 'Avoid executable javascript: URLs. Use javascript:; or javascript:void(0) for no-op links, or data attributes with event listeners for interactive behavior'
                );
            }
        }

        // Check for data: protocol with user input (Critical - can execute JavaScript)
        if (preg_match('/(?:href|src)\s*=\s*["\']?\s*data:/i', $line) && $this->mightContainUserInput($line)) {
            $issues[] = $this->createIssueWithSnippet(
                message: 'Critical XSS: data: protocol with user input in HTML attribute',
                filePath: $file,
                lineNumber: $lineNumber + 1,
                severity: Severity::Critical,
                recommendation: 'Avoid data: URLs with user input. If necessary, validate and whitelist allowed MIME types'
            );
        }

        // Check for event handler attributes with user input or blade output (Critical)
        $eventHandlers = [
            'onclick', 'ondblclick', 'onmousedown', 'onmouseup', 'onmouseover', 'onmousemove', 'onmouseout',
            'onkeydown', 'onkeypress', 'onkeyup', 'onload', 'onunload', 'onerror', 'onabort',
            'onblur', 'onchange', 'onfocus', 'onreset', 'onselect', 'onsubmit',
        ];

        foreach ($eventHandlers as $handler) {
            // Check for event handlers with Blade output or user input
            if (preg_match('/'.$handler.'\s*=\s*["\'][^"\']*(\{\{|\{!!|\$_|request\()/i', $line)) {
                $issues[] = $this->createIssueWithSnippet(
                    message: "Critical XSS: User input in {$handler} event handler attribute",
                    filePath: $file,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::Critical,
                    recommendation: 'Never insert user input into event handlers. Use data attributes and attach event listeners in JavaScript'
                );
                break; // Only report once per line
            }
        }

        // Check for user input in href attribute (High - potential XSS if not validated)
        // Use attribute-level context to avoid false positives when user input is elsewhere on line
        $hrefValue = $this->extractAttributeValue('href', $line);
        if ($hrefValue !== null && preg_match('/(\{\{|\{!!)/', $hrefValue) && $this->mightContainUserInput($hrefValue)) {
            // Skip if it's using javascript: or data: (already caught above)
            if (! preg_match('/^\s*(?:javascript|data):/i', $hrefValue)) {
                // Skip if user input is properly URL-encoded
                if (! $this->isUrlSafeContext($hrefValue)) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'High: User input in href attribute without URL validation',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::High,
                        recommendation: 'Validate URLs to ensure they use safe protocols (http/https). Use url() helper or validate against whitelist'
                    );
                }
            }
        }

        // Check for user input in src attribute (High - can load malicious resources)
        // Use attribute-level context to avoid false positives when user input is elsewhere on line
        $srcValue = $this->extractAttributeValue('src', $line);
        if ($srcValue !== null && preg_match('/(\{\{|\{!!)/', $srcValue) && $this->mightContainUserInput($srcValue)) {
            // Skip if it's using javascript: or data: (already caught above)
            if (! preg_match('/^\s*(?:javascript|data):/i', $srcValue)) {
                // Skip if user input is properly URL-encoded
                if (! $this->isUrlSafeContext($srcValue)) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'High: User input in src attribute without validation',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::High,
                        recommendation: 'Validate resource URLs. Ensure they use safe protocols and come from trusted sources'
                    );
                }
            }
        }

        // Check for user input in data-* attributes (Medium - can be exploited in some contexts)
        if (preg_match('/data-[a-z0-9_-]+\s*=\s*["\'][^"\']*(\{!!)/i', $line)) {
            $issues[] = $this->createIssueWithSnippet(
                message: 'Medium: Unescaped user input in data-* attribute',
                filePath: $file,
                lineNumber: $lineNumber + 1,
                severity: Severity::Medium,
                recommendation: 'Use {{ $var }} instead of {!! $var !!} for data attributes, or sanitize the value'
            );
        }

        return $issues;
    }

    /**
     * PART 2: HTTP Header Analysis.
     *
     * Checks Content-Security-Policy (CSP) headers for XSS protection:
     * - Verifies CSP header is present
     * - Ensures script-src or default-src directive exists
     * - Validates no unsafe-inline or unsafe-eval directives
     *
     * @return array<\ShieldCI\AnalyzersCore\ValueObjects\Issue>
     */
    private function analyzeHttpHeaders(): array
    {
        $issues = [];

        // Try to find a guest URL to check
        $url = $this->findLoginRoute();

        if ($url === null) {
            // Can't check headers without a URL (not a failure, just skip)
            return [];
        }

        // Skip localhost URLs
        if (str_contains($url, 'localhost') || str_contains($url, '127.0.0.1')) {
            return [];
        }

        $response = $this->fetchHttpResponse($url);

        if ($response === null) {
            return [];
        }

        $body = (string) $response->getBody();
        $cspHeaders = $response->getHeader('Content-Security-Policy');

        // Check if CSP is set
        if (empty($cspHeaders)) {
            // Try meta tags as fallback
            $metaPolicy = $this->extractCspFromMetaTags($body);

            if (empty($metaPolicy)) {
                $issues[] = $this->createIssue(
                    message: 'HTTP XSS: Content-Security-Policy header not set',
                    location: new Location('HTTP Headers'),
                    severity: Severity::High,
                    recommendation: 'Set Content-Security-Policy header with script-src or default-src directive without unsafe-eval or unsafe-inline. Example: "default-src \'self\'; script-src \'self\'"'
                );

                return $issues;
            }

            $cspHeaders = [$metaPolicy];
        }

        // Validate CSP headers
        $hasValidPolicy = false;
        foreach ($cspHeaders as $policy) {
            if (is_string($policy) && $this->isValidCspPolicy($policy)) {
                $hasValidPolicy = true;
                break;
            }
        }

        if (! $hasValidPolicy) {
            $cspString = implode('; ', array_filter($cspHeaders, 'is_string'));

            $issues[] = $this->createIssue(
                message: 'HTTP XSS: Content-Security-Policy header is inadequate for XSS protection',
                location: new Location('HTTP Headers'),
                severity: Severity::High,
                recommendation: 'Set a "script-src" or "default-src" policy directive without "unsafe-eval" or "unsafe-inline". Current policy weakens script execution protections or lacks a strict script-src directive.',
                metadata: ['current_csp' => $cspString]
            );
        }

        return $issues;
    }

    /**
     * Check if CSP policy is valid (has script-src/default-src without unsafe).
     */
    private function isValidCspPolicy(string $policy): bool
    {
        // Must contain script-src or default-src
        if (! Str::contains($policy, ['default-src', 'script-src'])) {
            return false;
        }

        // Must not contain unsafe-eval or unsafe-inline
        if (Str::contains($policy, ['unsafe-eval', 'unsafe-inline'])) {
            return false;
        }

        return true;
    }

    /**
     * Get CSP from meta tags (fallback).
     */
    private function extractCspFromMetaTags(string $html): string
    {
        // Try double quotes first (most common)
        if (preg_match('/<meta[^>]+http-equiv="Content-Security-Policy"[^>]+content="([^"]+)"/', $html, $matches)) {
            return $matches[1];
        }

        // Try single quotes
        if (preg_match('/<meta[^>]+http-equiv=\'Content-Security-Policy\'[^>]+content=\'([^\']+)\'/', $html, $matches)) {
            return $matches[1];
        }

        return '';
    }

    /**
     * @return array<int, string>
     */
    private function getAnalyzableFiles(): array
    {
        $files = [];

        foreach ($this->getFilesToAnalyze() as $file) {
            if ($this->shouldAnalyzeFile($file)) {
                $files[$file->getPathname()] = $file->getPathname();
            }
        }

        return array_values($files);
    }

    private function isBladeFile(SplFileInfo $file): bool
    {
        return str_ends_with($file->getFilename(), '.blade.php');
    }

    private function isExcludedPath(string $path): bool
    {
        foreach ($this->excludePatterns as $pattern) {
            if ($this->matchesPattern($path, $pattern)) {
                return true;
            }
        }

        return false;
    }

    private function fetchHttpResponse(string $url): ?ResponseInterface
    {
        try {
            return $this->getClient()->get($url, [
                'timeout' => 5,
                'http_errors' => false,
                'verify' => false,
            ]);
        } catch (Throwable) {
            return null;
        }
    }
}
