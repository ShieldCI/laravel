<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use PhpParser\Node;
use PhpParser\Node\ArrayItem;
use PhpParser\Node\Expr;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\Concerns\DetectsLaravelVersion;
use ShieldCI\Concerns\ReadsMiddlewareConfigurator;
use ShieldCI\Concerns\ResolvesClassNames;
use ShieldCI\Support\BootstrapRouteParser;

/**
 * Detects missing CSRF protection vulnerabilities.
 *
 * Checks for:
 * - Forms without @csrf directive
 * - AJAX requests without CSRF token
 * - Routes without CSRF middleware (VerifyCsrfToken in Laravel 9/10, ValidateCsrfToken in Laravel 11/12,
 *   PreventRequestForgery in Laravel 13+)
 * - Overly broad CSRF exceptions in middleware $except array (Laravel 9/10)
 * - Overly broad CSRF exceptions in validateCsrfTokens() / preventRequestForgery() (Laravel 11+)
 * - Explicitly disabled CSRF protection in bootstrap/app.php (Laravel 11+), read through the AST:
 *   - $middleware->web(remove: [...]) or removeFromGroup('web', ...) naming the CSRF middleware
 *     the web group holds for the installed Laravel version
 *   - $middleware->group('web', [...]) without CSRF middleware
 *   - $middleware->web(replace: [...]) or replaceInGroup('web', ...) swapping CSRF middleware out
 *   - validateCsrfTokens(except: ['*']) / preventRequestForgery(except: ['*'])
 */
class CsrfAnalyzer extends AbstractFileAnalyzer
{
    use DetectsLaravelVersion;
    use ReadsMiddlewareConfigurator;
    use ResolvesClassNames;

    /**
     * Middleware methods that take CSRF exceptions, lowercased. Laravel 13 deprecated
     * validateCsrfTokens() in favour of preventRequestForgery().
     *
     * @var array<int, string>
     */
    private const CSRF_EXCEPT_METHODS = ['validatecsrftokens', 'preventrequestforgery'];

    /**
     * CSRF middleware names an application may register. Laravel 13 renamed ValidateCsrfToken to
     * PreventRequestForgery and keeps the old names as subclasses, so any of them may appear.
     *
     * @var array<int, string>
     */
    private const CSRF_MIDDLEWARE = ['VerifyCsrfToken', 'ValidateCsrfToken', 'PreventRequestForgery'];

    public function __construct(
        private AstParser $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'csrf-protection',
            name: 'CSRF Protection Analyzer',
            description: 'Detects missing CSRF (Cross-Site Request Forgery) protection',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['csrf', 'cross-site-request-forgery', 'security', 'forms'],
            timeToFix: 20
        );
    }

    public function shouldRun(): bool
    {
        // Check if there are any files to analyze
        $hasBladeFiles = ! empty($this->getBladeFiles());
        $hasJsFiles = ! empty($this->getJavaScriptFiles());
        $hasRoutes = ! empty($this->getRouteFiles());

        $hasMiddleware = $this->csrfMiddlewareFile() !== null;

        $kernelFile = $this->buildPath('app', 'Http', 'Kernel.php');
        $bootstrapApp = $this->buildPath('bootstrap', 'app.php');
        $hasKernelOrBootstrap = file_exists($kernelFile) || file_exists($bootstrapApp);

        return $hasBladeFiles || $hasJsFiles || $hasRoutes || $hasMiddleware || $hasKernelOrBootstrap;
    }

    public function getSkipReason(): string
    {
        return 'No Blade templates, JavaScript files, routes, or CSRF middleware found to analyze';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check Blade templates for forms without @csrf
        $bladeFiles = $this->getBladeFiles();
        foreach ($bladeFiles as $file) {
            $this->checkBladeFormsForCsrf($file, $issues);
            $this->checkAjaxRequestsForCsrf($file, $issues);
        }

        // Check JavaScript files for AJAX without CSRF token
        $jsFiles = $this->getJavaScriptFiles();
        foreach ($jsFiles as $file) {
            $this->checkJavaScriptAjaxForCsrf($file, $issues);
        }

        // Check VerifyCsrfToken middleware for overly broad exceptions
        $this->checkCsrfMiddlewareExceptions($issues);

        // Check VerifyCsrfToken middleware registration
        $this->checkCsrfMiddlewareRegistration($issues);

        // Compute route files covered by web/API middleware via external registration
        // (require from web.php/api.php, or Route::middleware()->group() in bootstrap/app.php)
        $bootstrapParser = new BootstrapRouteParser($this->getBasePath(), $this->parser);
        $webProtectedFiles = $bootstrapParser->getWebProtectedRouteFiles();
        $apiRegisteredFiles = $bootstrapParser->getApiRegisteredRouteFiles();

        // Check route files for routes that should have CSRF protection
        $routeFiles = $this->getRouteFiles();
        foreach ($routeFiles as $file) {
            $this->checkRoutesForCsrfMiddleware($file, $issues, $bootstrapParser, $webProtectedFiles, $apiRegisteredFiles);
        }

        $summary = empty($issues)
            ? 'No CSRF protection issues detected'
            : sprintf('Found %d potential CSRF protection issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Check Blade templates for forms without @csrf directive.
     *
     * ALL forms in Blade templates require CSRF protection - no exceptions.
     * Blade templates are web views; if building an API, use JSON responses instead of forms.
     *
     * Accepts multiple CSRF protection patterns:
     * - @csrf or @csrf() - Blade directive
     * - <x-csrf /> or <x-csrf/> - Blade component
     * - csrf_field() - Helper function
     * - <input name="_token" ... /> - Manual token input
     *
     * Scans until </form> is found (no hardcoded line limit).
     *
     * @param  array<int, Issue>  &$issues
     */
    private function checkBladeFormsForCsrf(string $file, array &$issues): void
    {
        $content = FileParser::readFile($file);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($file);

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Check for form opening tags (POST, PUT, PATCH, DELETE)
            if (preg_match('/<form[^>]*method\s*=\s*["\'](?:POST|PUT|PATCH|DELETE)["\'][^>]*>/i', $line, $matches)) {
                $hasCsrf = false;
                $method = preg_match('/method\s*=\s*["\']([^"\']+)["\']/', $matches[0], $methodMatch) ? strtoupper($methodMatch[1]) : 'POST';

                // Scan from form opening until </form> is found
                for ($i = $lineNumber; $i < count($lines); $i++) {
                    if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                        continue;
                    }

                    // Check for CSRF token patterns:
                    // - @csrf or @csrf() - Blade directive (with or without parentheses)
                    // - <x-csrf /> or <x-csrf/> - Blade component
                    // - csrf_field() - Helper function
                    // - <input name="_token" ... /> - Manual token input
                    if (preg_match('/@csrf(\(\))?|<x-csrf\s*\/?>|csrf_field\(\)|<input[^>]*name\s*=\s*["\']_token["\']/', $lines[$i])) {
                        $hasCsrf = true;
                        break;
                    }

                    // Stop if we hit the closing form tag
                    if (str_contains($lines[$i], '</form>')) {
                        break;
                    }
                }

                if (! $hasCsrf) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'Form without CSRF protection - missing @csrf directive',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::High,
                        recommendation: 'Add the @csrf Blade directive inside the form tag to include a hidden CSRF token field.',
                        metadata: [
                            'file' => basename($file),
                            'form_method' => $method,
                            'line' => $lineNumber + 1,
                        ]
                    );
                }
            }
        }
    }

    /**
     * Check for AJAX requests without CSRF token in Blade files.
     *
     * Scans until natural boundary (closing parenthesis + semicolon) instead of hardcoded line limit.
     * Uses parenthesis depth tracking to find the end of AJAX call.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function checkAjaxRequestsForCsrf(string $file, array &$issues): void
    {
        $content = FileParser::readFile($file);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($file);

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Check for jQuery AJAX with POST/PUT/PATCH/DELETE
            if (preg_match('/\$\.ajax\s*\(|fetch\s*\(/i', $line, $ajaxMatch)) {
                $hasPostMethod = false;
                $hasCsrfToken = false;
                $ajaxType = str_contains($ajaxMatch[0], 'fetch') ? 'fetch' : 'jQuery';
                $parenDepth = 0;
                $foundOpeningParen = false;

                // Scan until we find the closing statement (closing paren + semicolon, or just semicolon)
                for ($i = $lineNumber; $i < count($lines); $i++) {
                    if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                        continue;
                    }

                    $currentLine = $lines[$i];

                    // Track parenthesis depth to find end of AJAX call
                    $parenDepth += substr_count($currentLine, '(') - substr_count($currentLine, ')');
                    if (substr_count($currentLine, '(') > 0) {
                        $foundOpeningParen = true;
                    }

                    // Check for method: POST/PUT/PATCH/DELETE
                    if (preg_match('/method\s*:\s*["\']?\s*(?:POST|PUT|PATCH|DELETE)\s*["\']?/i', $currentLine)) {
                        $hasPostMethod = true;
                    }

                    // Check for CSRF token
                    if (preg_match('/X-CSRF-TOKEN|_token|csrf|@csrf/i', $currentLine)) {
                        $hasCsrfToken = true;
                    }

                    // Stop if we've closed all parentheses and hit a semicolon, or exceeded reasonable search range
                    if ($foundOpeningParen && $parenDepth <= 0 && str_contains($currentLine, ';')) {
                        break;
                    }

                    // Safety limit: don't scan more than 30 lines for a single AJAX call
                    if ($i - $lineNumber > 30) {
                        break;
                    }
                }

                if ($hasPostMethod && ! $hasCsrfToken) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'AJAX request without CSRF token',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::High,
                        recommendation: 'Add the X-CSRF-TOKEN request header using the token value stored in the csrf-token meta tag.',
                        metadata: [
                            'file' => basename($file),
                            'ajax_type' => $ajaxType,
                            'line' => $lineNumber + 1,
                        ]
                    );
                }
            }
        }
    }

    /**
     * Check JavaScript files for AJAX without CSRF token.
     *
     * Only flags POST/PUT/PATCH/DELETE requests:
     * - axios.post/put/patch/delete - method explicit in function name
     * - fetch(url, {method: 'POST'}) - checks for method property
     * - $.ajax({method: 'POST'}) - checks for method property
     *
     * GET requests (fetch(url) without method, or method: 'GET') are not flagged.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function checkJavaScriptAjaxForCsrf(string $file, array &$issues): void
    {
        $content = FileParser::readFile($file);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($file);

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Check for fetch API or axios with POST methods
            if (preg_match('/fetch\s*\(|axios\.(post|put|patch|delete)|\.ajax\s*\(/i', $line, $jsMatch)) {
                $searchRange = min($lineNumber + 10, count($lines));
                $hasCsrfToken = false;
                $hasPostMethod = false;
                $ajaxLibrary = str_contains($jsMatch[0], 'axios') ? 'axios' : (str_contains($jsMatch[0], 'fetch') ? 'fetch' : 'jQuery');

                // For axios.post/put/patch/delete, the method is explicit in the function name
                if (preg_match('/axios\.(post|put|patch|delete)/i', $jsMatch[0])) {
                    $hasPostMethod = true;
                }

                // For fetch() and $.ajax(), check if method is POST/PUT/PATCH/DELETE
                for ($i = $lineNumber; $i < $searchRange; $i++) {
                    // Check for method: 'POST' or method:'POST' (with or without quotes)
                    if (preg_match('/method\s*:\s*["\']?\s*(POST|PUT|PATCH|DELETE)\s*["\']?/i', $lines[$i])) {
                        $hasPostMethod = true;
                    }

                    if (preg_match('/X-CSRF-TOKEN|csrf[-_]?token|_token/i', $lines[$i])) {
                        $hasCsrfToken = true;
                    }

                    // Stop searching if we hit a semicolon or closing brace at statement level
                    if (preg_match('/^\s*[;}]\s*$/', $lines[$i])) {
                        break;
                    }
                }

                // Only flag if it's a POST/PUT/PATCH/DELETE request without CSRF token
                if ($hasPostMethod && ! $hasCsrfToken) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'JavaScript AJAX request may be missing CSRF token',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::Medium,
                        recommendation: 'Add CSRF token to headers or ensure Laravel\'s default CSRF setup is configured',
                        metadata: [
                            'file' => basename($file),
                            'ajax_library' => $ajaxLibrary,
                            'line' => $lineNumber + 1,
                            'severity_reason' => 'Medium severity because JS files may use global CSRF configuration',
                        ]
                    );
                }
            }
        }
    }

    /**
     * The application's CSRF middleware subclass in app/Http/Middleware, or null when it has none.
     */
    private function csrfMiddlewareFile(): ?string
    {
        foreach (self::CSRF_MIDDLEWARE as $name) {
            $path = $this->buildPath('app', 'Http', 'Middleware', $name.'.php');

            if (file_exists($path)) {
                return $path;
            }
        }

        return null;
    }

    /**
     * Check the application's CSRF middleware subclass for overly broad exceptions.
     *
     * The $except property is read through the AST, so every entry counts however the array
     * is laid out across lines.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function checkCsrfMiddlewareExceptions(array &$issues): void
    {
        $middlewarePath = $this->csrfMiddlewareFile();

        if ($middlewarePath === null) {
            return;
        }

        foreach ($this->parser->findNodes($this->parser->parseFile($middlewarePath), Stmt\Property::class) as $property) {
            if (! $property instanceof Stmt\Property) {
                continue;
            }

            foreach ($property->props as $item) {
                if ($item->name->toString() !== 'except' || ! $item->default instanceof Expr\Array_) {
                    continue;
                }

                $line = $item->getStartLine();

                foreach ($item->default->items as $entry) {
                    if (! $entry instanceof ArrayItem || ! $entry->value instanceof String_) {
                        continue;
                    }

                    $exception = $entry->value->value;

                    if ($exception === '*' || $exception === '/*') {
                        $issues[] = $this->createIssueWithSnippet(
                            message: 'All routes excluded from CSRF protection with wildcard',
                            filePath: $middlewarePath,
                            lineNumber: $line,
                            severity: Severity::Critical,
                            recommendation: 'Remove wildcard CSRF exceptions and specify exact routes that need exclusion',
                            metadata: [
                                'exception' => $exception,
                                'file' => basename($middlewarePath),
                                'line' => $line,
                            ]
                        );
                    } elseif (str_contains($exception, '*') && $this->isBroadCsrfException($exception)) {
                        $issues[] = $this->createIssueWithSnippet(
                            message: sprintf('Broad CSRF exception pattern: %s', $exception),
                            filePath: $middlewarePath,
                            lineNumber: $line,
                            severity: Severity::High,
                            recommendation: 'Use more specific route patterns for CSRF exceptions (e.g., "service/webhooks/*" instead of "webhooks/*")',
                            metadata: [
                                'exception' => $exception,
                                'file' => basename($middlewarePath),
                                'line' => $line,
                            ]
                        );
                    }
                }
            }
        }
    }

    /**
     * Determine if a CSRF exception pattern is overly broad.
     *
     * Patterns are considered broad if they:
     * - Have only one path segment before wildcard (e.g., 'admin/*', 'webhook/*')
     * - Exception: 'api/*' patterns are allowed as APIs typically use token auth
     *
     * Patterns are considered specific if they:
     * - Have 2+ path segments (e.g., 'service/webhooks/*', '/clock/switch/*')
     * - Are for known webhook/integration services (e.g., 'stripe/*', 'mailgun/*')
     */
    private function isBroadCsrfException(string $exception): bool
    {
        // Allow API routes - they typically use token authentication
        if (str_starts_with(trim($exception, '/'), 'api/')) {
            return false;
        }

        // Allow known webhook/integration services (single segment is OK for these)
        $allowedServices = [
            'stripe', 'mailgun', 'mailslurp', 'twilio', 'slack',
            'github', 'gitlab', 'bitbucket', 'webhooks',
            'paddle', 'paypal', 'braintree', 'plaid',
        ];

        $cleanException = trim($exception, '/');
        foreach ($allowedServices as $service) {
            if (str_starts_with($cleanException, $service.'/')) {
                return false;
            }
        }

        // Count path segments (excluding wildcard)
        $pathWithoutWildcard = str_replace('*', '', $exception);
        $segments = array_filter(explode('/', $pathWithoutWildcard), fn ($seg) => $seg !== '');

        // If 2+ segments before wildcard, it's specific enough (e.g., '/clock/switch/*')
        if (count($segments) >= 2) {
            return false;
        }

        // Single segment patterns are broad (e.g., 'admin/*', 'dashboard/*')
        return true;
    }

    /**
     * Check if CSRF middleware is registered in Kernel.php.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function checkCsrfMiddlewareRegistration(array &$issues): void
    {
        $kernelFile = $this->buildPath('app', 'Http', 'Kernel.php');

        if (! file_exists($kernelFile)) {
            // Check bootstrap/app.php for Laravel 11+
            $bootstrapApp = $this->buildPath('bootstrap', 'app.php');
            if (file_exists($bootstrapApp)) {
                $this->checkBootstrapApp($bootstrapApp, $issues);
            }

            return;
        }

        $content = FileParser::readFile($kernelFile);
        if ($content === null) {
            return;
        }

        // Only a comment that is itself a middleware entry counts, not prose that names the class
        $commentedEntry = '/^\s*\/\/\s*[\'"]?\\\\?(?:\w+\\\\)*('.implode('|', self::CSRF_MIDDLEWARE).')(?:::class|[\'"])/';
        $commentedOut = [];

        foreach (FileParser::getLines($kernelFile) as $lineNumber => $line) {
            if (! is_string($line) || preg_match($commentedEntry, $line, $matches) !== 1) {
                continue;
            }

            $middlewareName = $matches[1];

            $commentedOut[] = $this->createIssueWithSnippet(
                message: sprintf('%s middleware is commented out', $middlewareName),
                filePath: $kernelFile,
                lineNumber: $lineNumber + 1,
                severity: Severity::Critical,
                recommendation: sprintf('Uncomment the %s middleware to enable CSRF protection', $middlewareName),
                metadata: [
                    'file' => 'Kernel.php',
                    'middleware' => $middlewareName,
                    'status' => 'commented',
                    'line' => $lineNumber + 1,
                ]
            );
        }

        // A commented-out entry is the more specific finding for a Kernel that registers none
        if ($commentedOut === [] && $this->csrfMiddlewareIn(FileParser::stripAllComments($content)) === null) {
            $issues[] = $this->createIssueWithSnippet(
                message: 'CSRF middleware is not registered in HTTP Kernel',
                filePath: $kernelFile,
                lineNumber: null,
                severity: Severity::Critical,
                recommendation: 'Register the CSRF validation middleware in the web middleware group in app/Http/Kernel.php to protect all web routes.',
                metadata: [
                    'file' => 'Kernel.php',
                    'middleware' => 'CSRF',
                    'status' => 'missing',
                ]
            );
        }

        array_push($issues, ...$commentedOut);
    }

    /**
     * Return the CSRF middleware name the text mentions, or null when it mentions none.
     */
    private function csrfMiddlewareIn(string $text): ?string
    {
        foreach (self::CSRF_MIDDLEWARE as $name) {
            if (str_contains($text, $name)) {
                return $name;
            }
        }

        return null;
    }

    /**
     * Check bootstrap/app.php for Laravel 11+ applications.
     *
     * Laravel 11+ includes CSRF middleware in the web group by default. The withMiddleware()
     * configurator can take it out of the group or exclude URIs from it, and each call is read
     * through the AST, so an argument's position, order or line break does not matter.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function checkBootstrapApp(string $file, array &$issues): void
    {
        $calls = $this->configuratorCalls($this->parser, $this->resolveNamesForMatching($this->parser->parseFile($file)));

        $this->checkBootstrapCsrfExceptions($calls, $file, $issues);
        $this->checkWebGroupInBootstrap($calls, $file, $issues);
    }

    /**
     * Check validateCsrfTokens() / preventRequestForgery() calls for wildcard and overly broad
     * exceptions.
     *
     * @param  list<Expr\MethodCall>  $calls
     * @param  array<int, Issue>  &$issues
     */
    private function checkBootstrapCsrfExceptions(array $calls, string $file, array &$issues): void
    {
        foreach ($calls as $call) {
            if (! $call->name instanceof Identifier
                || ! in_array($call->name->toLowerString(), self::CSRF_EXCEPT_METHODS, true)) {
                continue;
            }

            $except = $this->callArgument($call, 0, 'except');
            if (! $except instanceof Expr\Array_) {
                continue;
            }

            $method = $call->name->toString();
            $line = $call->name->getStartLine();
            $exceptions = [];

            foreach ($except->items as $item) {
                if ($item instanceof ArrayItem && $item->value instanceof String_) {
                    $exceptions[] = $item->value->value;
                }
            }

            // The middleware trims slashes before matching, so '/*' excludes every route too
            $wildcards = array_values(array_intersect($exceptions, ['*', '/*']));

            if ($wildcards !== []) {
                $issues[] = $this->createIssueWithSnippet(
                    message: 'All routes excluded from CSRF protection in bootstrap/app.php',
                    filePath: $file,
                    lineNumber: $line,
                    severity: Severity::Critical,
                    recommendation: 'Remove wildcard CSRF exception. In Laravel 11+, CSRF protection is on for the web group by default - only exclude specific URIs that need it.',
                    metadata: [
                        'file' => 'bootstrap/app.php',
                        'laravel_version' => $this->bootstrapLaravelVersion($method),
                        'exception' => $wildcards[0],
                        'line' => $line,
                    ]
                );
            }

            foreach (array_diff($exceptions, $wildcards) as $exception) {
                if (str_contains($exception, '*') && $this->isBroadCsrfException($exception)) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: sprintf('Broad CSRF exception pattern in bootstrap/app.php: %s', $exception),
                        filePath: $file,
                        lineNumber: $line,
                        severity: Severity::High,
                        recommendation: 'Use more specific route patterns for CSRF exceptions (e.g., "service/webhooks/*" instead of "webhooks/*")',
                        metadata: [
                            'exception' => $exception,
                            'file' => 'bootstrap/app.php',
                            'laravel_version' => $this->bootstrapLaravelVersion($method),
                            'risk_level' => 'high',
                            'line' => $line,
                        ]
                    );
                }
            }
        }
    }

    /**
     * Check bootstrap/app.php for a web group configured so it loses CSRF middleware.
     *
     * Mirrors Middleware::getMiddlewareGroups(): group('web', [...]) replaces the default group,
     * then replacements apply, then removals, then prepends and appends. Replacements and
     * removals match the exact class string in the group, so naming a class the group does not
     * hold, such as ValidateCsrfToken on Laravel 13 where the default group lists
     * PreventRequestForgery, changes nothing. CSRF middleware added back by a prepend or append
     * keeps the group protected.
     *
     * @param  list<Expr\MethodCall>  $calls
     * @param  array<int, Issue>  &$issues
     */
    private function checkWebGroupInBootstrap(array $calls, string $file, array &$issues): void
    {
        /** @var array{entries: list<string|null>, line: int}|null $group */
        $group = null;
        /** @var array<string, array{0: string|null, 1: int}> $replacements */
        $replacements = [];
        /** @var array<string, int> $removals */
        $removals = [];
        /** @var list<string|null> $additions */
        $additions = [];

        foreach ($calls as $call) {
            if (! $call->name instanceof Identifier) {
                continue;
            }

            $line = $call->name->getStartLine();
            $method = $call->name->toLowerString();
            $removing = [];

            if ($method === 'web') {
                $removing = $this->middlewareList($this->callArgument($call, 2, 'remove')) ?? [];
                $additions = array_merge(
                    $additions,
                    $this->middlewareList($this->callArgument($call, 0, 'append')) ?? [],
                    $this->middlewareList($this->callArgument($call, 1, 'prepend')) ?? [],
                );

                $replace = $this->callArgument($call, 3, 'replace');
                foreach ($replace instanceof Expr\Array_ ? $replace->items : [] as $item) {
                    $search = $item instanceof ArrayItem && $item->key !== null ? $this->middlewareName($item->key) : null;

                    if ($item instanceof ArrayItem && $search !== null) {
                        $replacements[$search] = [$this->middlewareName($item->value), $line];
                    }
                }
            } elseif ($this->isWebGroupName($this->callArgument($call, 0, 'group'))) {
                $middleware = $this->middlewareList($this->callArgument($call, 1, 'middleware'));

                switch ($method) {
                    case 'group':
                        // The last group() call wins; a list that cannot be read holds unknown entries
                        $group = ['entries' => $middleware ?? [null], 'line' => $line];
                        break;

                    case 'appendtogroup':
                    case 'prependtogroup':
                        $additions = array_merge($additions, $middleware ?? []);
                        break;

                    case 'removefromgroup':
                        $removing = $middleware ?? [];
                        break;

                    case 'replaceingroup':
                        $search = $this->middlewareName($this->callArgument($call, 1, 'search'));

                        if ($search !== null) {
                            $replacements[$search] = [$this->middlewareName($this->callArgument($call, 2, 'replace')), $line];
                        }
                        break;
                }
            }

            foreach ($removing as $name) {
                if ($name !== null && ! isset($removals[$name])) {
                    $removals[$name] = $line;
                }
            }
        }

        $found = [];
        $entries = $group['entries'] ?? [$this->defaultWebCsrfMiddleware()];
        // An entry that cannot be read may be CSRF middleware, so a CSRF name may match it
        $unknown = in_array(null, $entries, true);

        if ($group !== null && ! $unknown && $this->csrfMiddlewareInList($entries) === null) {
            $found[] = $this->createIssueWithSnippet(
                message: 'web middleware group redefined without CSRF middleware',
                filePath: $file,
                lineNumber: $group['line'],
                severity: Severity::High,
                recommendation: 'Include PreventRequestForgery (ValidateCsrfToken before Laravel 13) in the web group passed to group(). Without it, every web route accepts forged requests.',
                metadata: [
                    'file' => 'bootstrap/app.php',
                    'laravel_version' => '11+',
                    'status' => 'missing_from_web',
                    'line' => $group['line'],
                    'severity_reason' => 'High rather than Critical because a CSRF subclass with a custom name is not recognised',
                ]
            );
        }

        foreach ($replacements as $search => [$replacement, $line]) {
            $replaced = $this->csrfMiddlewareIn($search);

            // Swapping in an application subclass such as App\Http\Middleware\VerifyCsrfToken keeps protection
            if ($replaced === null
                || (! $unknown && ! in_array($search, $entries, true))
                || ($replacement !== null && $this->csrfMiddlewareIn($replacement) !== null)) {
                continue;
            }

            $found[] = $this->webGroupReplacementIssue($replaced, $replacement, $file, $line);
        }

        // Replacements apply in one pass over the group, before removals
        foreach ($entries as $index => $entry) {
            if ($entry !== null && isset($replacements[$entry])) {
                $entries[$index] = $replacements[$entry][0];
            }
        }

        $unknown = in_array(null, $entries, true);

        foreach ($removals as $name => $line) {
            $removed = $this->csrfMiddlewareIn($name);

            if ($removed !== null && ($unknown || in_array($name, $entries, true))) {
                $found[] = $this->webGroupRemovalIssue($removed, $file, $line);
            }
        }

        // Prepends and appends run last, so CSRF middleware added there protects the group
        if ($this->csrfMiddlewareInList($additions) !== null) {
            return;
        }

        array_push($issues, ...$found);
    }

    /**
     * The CSRF middleware the default web group holds: PreventRequestForgery from Laravel 13,
     * ValidateCsrfToken before it.
     */
    private function defaultWebCsrfMiddleware(): string
    {
        return $this->isLaravel13OrNewer()
            ? 'Illuminate\\Foundation\\Http\\Middleware\\PreventRequestForgery'
            : 'Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken';
    }

    /**
     * Whether a group argument names the web group.
     */
    private function isWebGroupName(?Expr $expr): bool
    {
        return $expr instanceof String_ && $expr->value === 'web';
    }

    /**
     * The middleware names an array|string argument lists, with null for an entry that cannot
     * be read. Empty when the argument is absent, and null when the list itself cannot be read.
     *
     * @return list<string|null>|null
     */
    private function middlewareList(?Expr $expr): ?array
    {
        if ($expr === null) {
            return [];
        }

        if (! $expr instanceof Expr\Array_) {
            $name = $this->middlewareName($expr);

            return $name !== null ? [$name] : null;
        }

        $names = [];
        foreach ($expr->items as $item) {
            $names[] = $item instanceof ArrayItem && ! $item->unpack ? $this->middlewareName($item->value) : null;
        }

        return $names;
    }

    /**
     * The string a middleware value puts in the group: a string as written, or the fully
     * qualified name of X::class. Null for anything else.
     */
    private function middlewareName(?Expr $expr): ?string
    {
        if ($expr instanceof String_) {
            return $expr->value;
        }

        if ($expr instanceof Expr\ClassConstFetch
            && $expr->class instanceof Name
            && $expr->name instanceof Identifier
            && $expr->name->toLowerString() === 'class') {
            $resolved = $expr->class->getAttribute('resolvedName');

            return ($resolved instanceof Name ? $resolved : $expr->class)->toString();
        }

        return null;
    }

    /**
     * The first CSRF middleware name a list of middleware names mentions, or null.
     *
     * @param  list<string|null>  $names
     */
    private function csrfMiddlewareInList(array $names): ?string
    {
        foreach ($names as $name) {
            $middleware = $name !== null ? $this->csrfMiddlewareIn($name) : null;

            if ($middleware !== null) {
                return $middleware;
            }
        }

        return null;
    }

    /**
     * The issue for CSRF middleware replaced in the web group, by web(replace:) or replaceInGroup().
     * A replacement that cannot be read may be a CSRF subclass, so it is reported at Medium.
     */
    private function webGroupReplacementIssue(string $replaced, ?string $replacement, string $file, int $line): Issue
    {
        return $this->createIssueWithSnippet(
            message: sprintf('%s replaced in web middleware group', $replaced),
            filePath: $file,
            lineNumber: $line,
            severity: $replacement === null ? Severity::Medium : Severity::High,
            recommendation: sprintf('Replace %s only with a subclass of it. Any other replacement disables CSRF protection for all web routes.', $replaced),
            metadata: [
                'file' => 'bootstrap/app.php',
                'laravel_version' => $this->bootstrapLaravelVersion($replaced),
                'middleware' => $replaced,
                'replacement' => $replacement,
                'status' => 'replaced_in_web',
                'line' => $line,
                'severity_reason' => $replacement === null
                    ? 'Medium because the replacement cannot be read and may be a CSRF subclass'
                    : 'High rather than Critical because a CSRF subclass with a custom name is not recognised',
            ]
        );
    }

    /**
     * The issue for CSRF middleware removed from the web group, by web(remove:) or removeFromGroup().
     */
    private function webGroupRemovalIssue(string $removed, string $file, int $line): Issue
    {
        return $this->createIssueWithSnippet(
            message: sprintf('%s removed from web middleware group', $removed),
            filePath: $file,
            lineNumber: $line,
            severity: Severity::Critical,
            recommendation: sprintf('Do not remove %s from the web middleware group. This disables CSRF protection for all web routes.', $removed),
            metadata: [
                'file' => 'bootstrap/app.php',
                'laravel_version' => $this->bootstrapLaravelVersion($removed),
                'middleware' => $removed,
                'status' => 'removed_from_web',
                'line' => $line,
            ]
        );
    }

    /**
     * The first Laravel version a bootstrap/app.php finding applies to: PreventRequestForgery and
     * preventRequestForgery() exist from Laravel 13, the rest of the configuration API from 11.
     */
    private function bootstrapLaravelVersion(string $text): string
    {
        return stripos($text, 'PreventRequestForgery') !== false ? '13+' : '11+';
    }

    /**
     * Check route files for routes that should have CSRF middleware.
     *
     * IMPORTANT: routes/web.php automatically has 'web' middleware applied globally
     * via RouteServiceProvider (Laravel 10) or bootstrap/app.php (Laravel 11+).
     *
     * This check only flags Route::post/put/patch/delete() routes in custom route files
     * (not web.php or api.php) that the 'web' middleware does not reach. The file is read
     * through the AST, and 'web' counts at any position in:
     * - the route's own ->middleware(...), read as Laravel reads it: a leading array is
     *   the whole list, otherwise every argument is one middleware
     * - a ->middleware(...) on the chain of a group whose closure holds the route
     * - the 'middleware' attribute of a Route::group([...], ...) whose closure holds the route
     *
     * 'auth' and other middleware do not count: they do not include CSRF protection.
     *
     * @param  array<string>  $webProtectedFiles  Files covered by 'web' middleware via external registration
     * @param  array<string>  $apiRegisteredFiles  Files registered under 'api' middleware via external registration
     * @param  array<int, Issue>  $issues
     */
    private function checkRoutesForCsrfMiddleware(
        string $file,
        array &$issues,
        BootstrapRouteParser $routeParser,
        array $webProtectedFiles = [],
        array $apiRegisteredFiles = [],
    ): void {
        $real = realpath($file);
        $normalizedPath = str_replace('\\', '/', $real !== false ? $real : $file);

        // Skip routes/api.php — it uses token authentication, not CSRF cookies
        if (str_ends_with($normalizedPath, '/routes/api.php')) {
            return;
        }

        // Skip web.php - routes in web.php automatically get 'web' middleware applied globally
        // via RouteServiceProvider (Laravel 10) or bootstrap/app.php (Laravel 11+)
        if (str_ends_with($normalizedPath, '/routes/web.php')) {
            return;
        }

        // Skip files registered under 'api' middleware externally — they use token auth, not CSRF
        if (in_array($normalizedPath, $apiRegisteredFiles, true)) {
            return;
        }

        // Skip files registered with 'web' middleware externally (e.g. withRouting(then: ...))
        if (in_array($normalizedPath, $webProtectedFiles, true)) {
            return;
        }

        // A file that does not parse yields no nodes; the report's parse-failure notice covers it
        $ast = $this->parser->parseFile($file);
        $protected = $this->webProtectedRoutes($ast, $routeParser);
        $reportedLines = [];

        foreach ($this->parser->findNodes($ast, Expr\StaticCall::class) as $call) {
            if (! $call instanceof Expr\StaticCall || ! $this->isRouteVerbCall($call) || isset($protected[spl_object_id($call)])) {
                continue;
            }

            $line = $call->getStartLine();
            if (isset($reportedLines[$line])) {
                continue;
            }
            $reportedLines[$line] = true;

            $method = $call->name instanceof Identifier ? strtoupper($call->name->name) : '';
            $issues[] = $this->createIssueWithSnippet(
                message: sprintf('%s route in custom route file missing CSRF protection - no "web" middleware detected', $method),
                filePath: $file,
                lineNumber: $line,
                severity: Severity::High,
                recommendation: 'Apply the web middleware group to this route or move it into a route group that includes the web middleware, which provides CSRF protection.',
                metadata: [
                    'method' => $method,
                    'file' => basename($file),
                    'line' => $line,
                    'severity_reason' => 'High severity for custom route files - web.php is automatically protected',
                ]
            );
        }
    }

    /**
     * The route verb calls of a route file the 'web' middleware reaches, keyed by
     * spl_object_id(): those whose own chain applies it, and those inside the closure of
     * a group that applies it through its chain or its 'middleware' attribute. A nested
     * group sits inside its parent's closure, so its routes are covered with it.
     *
     * @param  array<Node>  $ast
     * @return array<int, true>
     */
    private function webProtectedRoutes(array $ast, BootstrapRouteParser $routeParser): array
    {
        $protected = [];
        $webClosures = [];

        foreach ($this->parser->findNodes($ast, Expr\MethodCall::class) as $call) {
            if (! $call instanceof Expr\MethodCall || ! $call->name instanceof Identifier) {
                continue;
            }

            $method = $call->name->toLowerString();

            // Route::middleware('web')->group(function () { ... })
            if ($method === 'group' && $routeParser->chainContainsMiddleware($call->var, 'web')) {
                $webClosures[] = $routeParser->closureArgument($call->args);
            }

            // Route::post(...)->middleware('web'): the verb is the root of the chain
            if ($method === 'middleware' && $routeParser->chainContainsMiddleware($call, 'web')) {
                $root = $call->var;
                while ($root instanceof Expr\MethodCall) {
                    $root = $root->var;
                }
                if ($root instanceof Expr\StaticCall && $this->isRouteVerbCall($root)) {
                    $protected[spl_object_id($root)] = true;
                }
            }
        }

        // Route::group(['middleware' => [..., 'web']], function () { ... })
        foreach ($this->parser->findNodes($ast, Expr\StaticCall::class) as $call) {
            if ($call instanceof Expr\StaticCall
                && $this->isRouteCall($call, ['group'])
                && $this->groupAttributesListWeb($call->args)) {
                $webClosures[] = $routeParser->closureArgument($call->args);
            }
        }

        foreach (array_filter($webClosures) as $closure) {
            foreach ($this->parser->findNodes([$closure], Expr\StaticCall::class) as $call) {
                if ($call instanceof Expr\StaticCall && $this->isRouteVerbCall($call)) {
                    $protected[spl_object_id($call)] = true;
                }
            }
        }

        return $protected;
    }

    /**
     * Whether a group's attribute array lists 'web' in its 'middleware' entry, at any
     * position: Laravel applies every middleware a group lists.
     *
     * @param  array<Node>  $args
     */
    private function groupAttributesListWeb(array $args): bool
    {
        foreach ($args as $arg) {
            if (! $arg instanceof Node\Arg || ! $arg->value instanceof Expr\Array_) {
                continue;
            }

            foreach ($arg->value->items as $item) {
                if ($item instanceof ArrayItem
                    && $item->key instanceof String_
                    && $item->key->value === 'middleware'
                    && in_array('web', $this->middlewareList($item->value) ?? [], true)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Whether a static call registers a POST/PUT/PATCH/DELETE route: Route::post(...) and the like.
     */
    private function isRouteVerbCall(Expr\StaticCall $call): bool
    {
        return $this->isRouteCall($call, ['post', 'put', 'patch', 'delete']);
    }

    /**
     * Whether a static call is Route::<one of $methods>(...), matched case-insensitively.
     *
     * @param  array<int, string>  $methods  Lowercase method names
     */
    private function isRouteCall(Expr\StaticCall $call, array $methods): bool
    {
        return $call->class instanceof Name
            && $call->class->getLast() === 'Route'
            && $call->name instanceof Identifier
            && in_array($call->name->toLowerString(), $methods, true);
    }

    /**
     * Get all Blade template files.
     *
     * @return list<string>
     */
    private function getBladeFiles(): array
    {
        $files = [];

        foreach ($this->getFilesToAnalyze() as $file) {
            // A .blade.php file reports its extension as php, so the inherited
            // shouldAnalyzeFile() accepts it and applies excluded_paths.
            if (str_ends_with($file->getFilename(), '.blade.php') && $this->shouldAnalyzeFile($file)) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    /**
     * Get all JavaScript files.
     *
     * @return list<string>
     */
    private function getJavaScriptFiles(): array
    {
        $files = [];

        foreach ($this->getFilesToAnalyze() as $file) {
            if ($file->getExtension() === 'js' && ! $this->isExcluded($file->getPathname())) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    /**
     * Whether excluded_paths covers a file the inherited shouldAnalyzeFile() cannot judge.
     *
     * shouldAnalyzeFile() answers false for anything that is not PHP, so a JavaScript
     * file has to be tested against the patterns here. This follows the same rule:
     * patterns are written relative to the base path ('resources/js/vendor/*'), and the
     * absolute pathname is also tried, for patterns written against it.
     *
     * Widening shouldAnalyzeFile() to accept JavaScript instead would leak .js files into
     * getPhpFiles(), and from there into the route file scan.
     */
    private function isExcluded(string $path): bool
    {
        $relativePath = ltrim($this->getRelativePath($path), '/');

        foreach ($this->excludePatterns as $pattern) {
            if ($this->matchesPattern($relativePath, $pattern) || $this->matchesPattern($path, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get route files.
     *
     * @return array<int, string>
     */
    private function getRouteFiles(): array
    {
        return array_filter(
            $this->getPhpFiles(),
            fn (string $f) => str_contains($f, '/routes/')
        );
    }
}
