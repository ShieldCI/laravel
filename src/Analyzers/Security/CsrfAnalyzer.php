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
 *
 * @phpstan-type RouteWalk array{
 *     routes: list<array{line: int, method: string, web: bool, strips: bool, closures: list<int>}>,
 *     groups: array<int, array{web: bool, strips: bool}>,
 *     variables: array<string, int>,
 *     includes: list<array{include: Expr\Include_, closures: list<int>}>,
 * }
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
        $this->checkRoutesForCsrfMiddleware($this->getRouteFiles(), $issues, $bootstrapParser, $webProtectedFiles, $apiRegisteredFiles);

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
     * Check if CSRF middleware is registered in Kernel.php. The Kernel is read through the AST,
     * and the file text is searched for a CSRF class name only when that reading is inconclusive.
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

        $runsCsrf = $this->kernelRunsCsrfOnWebRoutes($kernelFile);

        // A commented-out entry is a leftover, not a gap, while an active entry runs CSRF on web routes
        $lines = $runsCsrf === true ? [] : FileParser::getLines($kernelFile);

        foreach ($lines as $lineNumber => $line) {
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

        // A Kernel that cannot be read conclusively counts as registering CSRF if its code names it
        $registered = $runsCsrf ?? $this->csrfMiddlewareIn(FileParser::stripAllComments($content)) !== null;

        // A commented-out entry is the more specific finding for a Kernel that registers none
        if ($commentedOut === [] && ! $registered) {
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
     * Whether the Kernel's global $middleware or its web group runs CSRF middleware on an active
     * entry, following a web group entry that names an alias or another group as Laravel does.
     * $middlewarePriority only orders middleware, so it never counts.
     *
     * Null when the property defaults cannot settle it: the file has no single Kernel class, a
     * list on that path cannot be read, a parent, trait or method may change the middleware, or
     * an alias or another group may run CSRF on whichever routes apply it.
     */
    private function kernelRunsCsrfOnWebRoutes(string $kernelFile): ?bool
    {
        $ast = $this->resolveNamesForMatching($this->parser->parseFile($kernelFile));

        // Only the Kernel class counts, not an anonymous or helper class elsewhere in the file
        $kernels = array_values(array_filter(
            $this->parser->findNodes($ast, Stmt\Class_::class),
            fn (Node $class): bool => $class instanceof Stmt\Class_ && $class->name?->toString() === 'Kernel',
        ));

        $class = $kernels[0] ?? null;
        if (count($kernels) !== 1 || ! $class instanceof Stmt\Class_) {
            return null;
        }

        // An undeclared property keeps its parent's value: empty in Laravel's Kernel, unknown in a custom base
        $parent = $class->extends?->getAttribute('resolvedName') ?? $class->extends;
        $isCustomParent = $parent instanceof Name && $parent->toString() !== 'Illuminate\\Foundation\\Http\\Kernel';
        $inherited = $isCustomParent ? null : new Expr\Array_;

        $defaults = [];
        foreach ($class->getProperties() as $property) {
            foreach ($property->props as $prop) {
                $defaults[$prop->name->toString()] = $prop->default ?? new Expr\Array_;
            }
        }

        [$groups, $groupsComplete] = $this->keyedEntries($defaults['middlewareGroups'] ?? $inherited);
        [$aliases, $aliasesComplete] = $this->keyedEntries($defaults['middlewareAliases'] ?? $inherited);
        [$routeMiddleware, $routeMiddlewareComplete] = $this->keyedEntries($defaults['routeMiddleware'] ?? $inherited);

        // Laravel 10 registers both alias properties, $middlewareAliases winning a shared key
        $aliases = array_merge($routeMiddleware, $aliases);
        $complete = $groupsComplete && $aliasesComplete && $routeMiddlewareComplete;

        $global = $defaults['middleware'] ?? $inherited;
        $globalRuns = $global !== null ? $this->kernelListRunsCsrf($global, [], [], true) : null;

        $webRuns = isset($groups['web']) || $groupsComplete
            ? $this->kernelListRunsCsrf($groups['web'] ?? null, $groups, $aliases, $complete, ['web' => true])
            : null;

        if ($globalRuns === true || $webRuns === true) {
            return true;
        }

        if ($globalRuns === null || $webRuns === null || $this->kernelMayChangeMiddleware($class)) {
            return null;
        }

        // Routes, providers and controllers may apply such an alias or group, which the Kernel does not show
        return $this->kernelDefinesCsrfOutsideWebGroup($groups, $aliases, $complete) ? null : false;
    }

    /**
     * The string-keyed entries of an array property's default value, and whether they are all of
     * them. Anything other than a literal array, or an entry without a string key, may hold any
     * key, so a key the entries lack is then unknown rather than absent.
     *
     * @return array{array<string, Expr>, bool}
     */
    private function keyedEntries(?Expr $default): array
    {
        if (! $default instanceof Expr\Array_) {
            return [[], false];
        }

        $entries = [];
        $complete = true;

        foreach ($default->items as $item) {
            if ($item instanceof ArrayItem && $item->key instanceof String_) {
                $entries[$item->key->value] = $item->value;
            } else {
                $complete = false;
            }
        }

        return [$entries, $complete];
    }

    /**
     * Whether a Kernel middleware list runs CSRF middleware. As Laravel resolves an entry, a group
     * name comes first, then an alias, and only then a class name; a group is never followed back
     * into itself. Null when none does but an entry, or the list itself, cannot be settled.
     *
     * @param  array<string, Expr>  $groups
     * @param  array<string, Expr>  $aliases
     * @param  bool  $complete  Whether $groups and $aliases hold every key the Kernel registers
     * @param  array<string, true>  $seen
     */
    private function kernelListRunsCsrf(?Expr $list, array $groups, array $aliases, bool $complete, array $seen = []): ?bool
    {
        $entries = $this->middlewareList($list);
        $runsCsrf = $entries === null ? null : false;

        foreach ($entries ?? [] as $entry) {
            if ($entry === null) {
                $runsCsrf = null;

                continue;
            }

            $alias = explode(':', $entry, 2)[0];

            if (isset($groups[$entry])) {
                $entryRunsCsrf = isset($seen[$entry])
                    ? false
                    : $this->kernelListRunsCsrf($groups[$entry], $groups, $aliases, $complete, $seen + [$entry => true]);
            } elseif (isset($aliases[$alias])) {
                // An alias names a class, so its target is read without the groups and aliases
                $entryRunsCsrf = $this->kernelListRunsCsrf($aliases[$alias], [], [], true);
            } else {
                $entryRunsCsrf = $this->kernelClassRunsCsrf($alias, $complete);
            }

            if ($entryRunsCsrf === true) {
                return true;
            }

            if ($entryRunsCsrf === null) {
                $runsCsrf = null;
            }
        }

        return $runsCsrf;
    }

    /**
     * Whether a Kernel entry that is not a known group or alias names a CSRF middleware class,
     * matched case-sensitively by its exact basename, as the registration check's text match is.
     * Null when it may be a group or alias the maps do not show, or a class whose name only
     * contains a CSRF middleware name, such as CustomVerifyCsrfToken, which may extend it.
     */
    private function kernelClassRunsCsrf(string $name, bool $complete): ?bool
    {
        $basename = substr((string) strrchr('\\'.$name, '\\'), 1);

        if (in_array($basename, self::CSRF_MIDDLEWARE, true)) {
            return true;
        }

        if (! $complete || $this->csrfMiddlewareIn($basename) !== null) {
            return null;
        }

        return false;
    }

    /**
     * Whether the Kernel may change its middleware beyond the property defaults: it uses a trait,
     * a method touches a middleware property at all, since a reference or a by-reference argument
     * can write it, or a method calls, on any receiver, a Kernel or router method that sets or
     * adds middleware.
     */
    private function kernelMayChangeMiddleware(Stmt\Class_ $class): bool
    {
        $mutators = [
            'appendmiddlewaretogroup', 'prependmiddlewaretogroup', 'pushmiddleware', 'prependmiddleware',
            'pushmiddlewaretogroup', 'middlewaregroup', 'aliasmiddleware',
            'setmiddlewaregroups', 'setglobalmiddleware', 'setmiddlewarealiases',
        ];
        $properties = ['middleware', 'middlewareGroups', 'middlewareAliases', 'routeMiddleware'];

        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Stmt\TraitUse) {
                return true;
            }
        }

        foreach ($this->parser->findNodes($class->getMethods(), Expr::class) as $expr) {
            if (($expr instanceof Expr\PropertyFetch || $expr instanceof Expr\NullsafePropertyFetch)
                && $expr->var instanceof Expr\Variable
                && $expr->var->name === 'this'
                && $expr->name instanceof Identifier
                && in_array($expr->name->toString(), $properties, true)) {
                return true;
            }

            // The router may be reached as $this->router, $this->app['router'] or a local variable
            if (($expr instanceof Expr\MethodCall || $expr instanceof Expr\NullsafeMethodCall || $expr instanceof Expr\StaticCall)
                && $expr->name instanceof Identifier
                && in_array($expr->name->toLowerString(), $mutators, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether an alias, or a group other than web, runs or may run CSRF middleware.
     *
     * @param  array<string, Expr>  $groups
     * @param  array<string, Expr>  $aliases
     */
    private function kernelDefinesCsrfOutsideWebGroup(array $groups, array $aliases, bool $complete): bool
    {
        foreach ($groups as $name => $list) {
            if ($name !== 'web' && $this->kernelListRunsCsrf($list, $groups, $aliases, $complete, [$name => true]) !== false) {
                return true;
            }
        }

        foreach ($aliases as $target) {
            if ($this->kernelListRunsCsrf($target, [], [], true) !== false) {
                return true;
            }
        }

        return false;
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
     * Check custom route files for state-changing routes the 'web' middleware does not reach.
     *
     * IMPORTANT: routes/web.php automatically has 'web' middleware applied globally
     * via RouteServiceProvider (Laravel 10) or bootstrap/app.php (Laravel 11+).
     *
     * routes/web.php, routes/api.php and files registered under 'api' are skipped. A file
     * registered under 'web' externally, or loaded by a group 'web' or the CSRF middleware
     * reaches, is covered, and so is any file a covered file requires outside a group that
     * removes CSRF. A file a bootstrap or provider group strips CSRF from is not, and neither
     * is any file it requires. The rest
     * are read through the AST: see walkRouteNode() for what reaches a route.
     *
     * 'auth' and other middleware do not count: they do not include CSRF protection.
     *
     * @param  array<string>  $routeFiles
     * @param  array<int, Issue>  $issues
     * @param  array<string>  $webProtectedFiles  Files covered by 'web' middleware via external registration
     * @param  array<string>  $apiRegisteredFiles  Files registered under 'api' middleware via external registration
     */
    private function checkRoutesForCsrfMiddleware(
        array $routeFiles,
        array &$issues,
        BootstrapRouteParser $routeParser,
        array $webProtectedFiles = [],
        array $apiRegisteredFiles = [],
    ): void {
        $walks = [];

        foreach ($routeFiles as $file) {
            $real = realpath($file);
            $normalizedPath = str_replace('\\', '/', $real !== false ? $real : $file);

            // routes/api.php and files registered under 'api' use token authentication, not
            // CSRF cookies; routes/web.php gets 'web' applied globally
            if (str_ends_with($normalizedPath, '/routes/api.php')
                || str_ends_with($normalizedPath, '/routes/web.php')
                || in_array($normalizedPath, $apiRegisteredFiles, true)) {
                continue;
            }

            $walks[$normalizedPath] = ['file' => $file, 'walk' => $this->walkRouteFile($file, $routeParser)];
        }

        // A group in bootstrap/app.php or a provider that loads a file covers it when it or an
        // enclosing group applies 'web' or the CSRF middleware, and strips it when one excludes
        // either, however else it loads. Groups inside route files are read by the walk, which
        // only trusts what a file that is itself loaded registers
        $covered = array_fill_keys($webProtectedFiles, true);
        $stripped = [];
        foreach ($routeParser->getGroupRegisteredRouteFiles(routeFiles: false) as $registration) {
            $state = $this->groupsCsrfState($registration['calls'], $routeParser);
            if ($state['strips']) {
                $stripped[$registration['file']] = true;
            } elseif ($state['web']) {
                $covered[$registration['file']] = true;
            }
        }

        // Coverage passes down require chains of any depth, and so does stripping, which
        // Laravel merges into every nested group and which wins over 'web'
        do {
            $changed = false;
            foreach ($walks as $path => $entry) {
                foreach ($entry['walk']['includes'] as $include) {
                    $file = $include['file'];
                    if (isset($stripped[$path])) {
                        $changed = $changed || ! isset($stripped[$file]);
                        $stripped[$file] = true;
                    } elseif (! isset($covered[$file]) && ! $include['strips'] && ($include['web'] || isset($covered[$path]))) {
                        $changed = true;
                        $covered[$file] = true;
                    }
                }
            }
        } while ($changed);

        foreach ($walks as $path => $entry) {
            $fileStripped = isset($stripped[$path]);
            if (isset($covered[$path]) && ! $fileStripped) {
                continue;
            }

            $unprotected = [];
            foreach ($entry['walk']['routes'] as $route) {
                if ($fileStripped || ! $route['web'] || $route['strips']) {
                    $unprotected[] = ['line' => $route['line'], 'method' => $route['method'], 'stripped' => $fileStripped || $route['web']];
                }
            }
            $this->reportUnprotectedRoutes($entry['file'], $unprotected, $issues);
        }
    }

    /**
     * @param  list<array{line: int, method: string, stripped: bool}>  $routes
     * @param  array<int, Issue>  $issues
     */
    private function reportUnprotectedRoutes(string $file, array $routes, array &$issues): void
    {
        $reportedLines = [];

        foreach ($routes as $route) {
            $line = $route['line'];
            if (isset($reportedLines[$line])) {
                continue;
            }
            $reportedLines[$line] = true;

            $issues[] = $this->createIssueWithSnippet(
                message: $route['stripped']
                    ? sprintf('%s route in custom route file missing CSRF protection - the CSRF middleware is excluded from it', $route['method'])
                    : sprintf('%s route in custom route file missing CSRF protection - no "web" middleware detected', $route['method']),
                filePath: $file,
                lineNumber: $line,
                severity: Severity::High,
                recommendation: $route['stripped']
                    ? 'Stop excluding the web group or the CSRF middleware from this route through withoutMiddleware() or excluded_middleware. A route that cannot send a token, such as a webhook, belongs in the CSRF middleware exceptions instead, where the exemption is reviewed with the others.'
                    : 'Apply the web middleware group to this route or move it into a route group that includes the web middleware, which provides CSRF protection.',
                metadata: [
                    'method' => $route['method'],
                    'file' => basename($file),
                    'line' => $line,
                    'severity_reason' => 'High severity for custom route files - web.php is automatically protected',
                ]
            );
        }
    }

    /**
     * Walk a route file once and resolve what reaches each route: its state-changing routes,
     * each with whether 'web' reaches it and whether the CSRF middleware is excluded from it,
     * and the files it requires, each with what reaches its require.
     *
     * @return array{routes: list<array{line: int, method: string, web: bool, strips: bool}>, includes: list<array{file: string, web: bool, strips: bool}>}
     */
    private function walkRouteFile(string $file, BootstrapRouteParser $routeParser): array
    {
        /** @var RouteWalk $walk */
        $walk = ['routes' => [], 'groups' => [], 'variables' => [], 'includes' => []];

        // A file that does not parse yields no nodes; the report's parse-failure notice covers it.
        // Names are resolved here, not left to whichever analyzer last resolved the cached AST,
        // so an aliased CSRF import reads as its class
        foreach ($this->resolveNamesForMatching($this->parser->parseFile($file)) as $node) {
            $this->walkRouteNode($node, [], $walk, $routeParser);
        }
        $groups = $walk['groups'];

        $routes = [];
        foreach ($walk['routes'] as $route) {
            [$web, $strips] = $this->groupsReaching($route['closures'], $groups, $route['web'], $route['strips']);
            $routes[] = ['line' => $route['line'], 'method' => $route['method'], 'web' => $web, 'strips' => $strips];
        }

        $includes = [];
        foreach ($walk['includes'] as $include) {
            $path = $routeParser->includedFile($include['include'], dirname($file));
            if ($path !== null) {
                [$web, $strips] = $this->groupsReaching($include['closures'], $groups, false, false);
                $includes[] = ['file' => $path, 'web' => $web, 'strips' => $strips];
            }
        }

        return ['routes' => $routes, 'includes' => $includes];
    }

    /**
     * Whether 'web' reaches a node, and whether the CSRF middleware is excluded from it,
     * given its own chain's state and the closures enclosing it. Laravel merges a group's
     * middleware and excluded middleware into every route inside it, and excluding wins.
     *
     * @param  list<int>  $closures
     * @param  array<int, array{web: bool, strips: bool}>  $groups
     * @return array{bool, bool}
     */
    private function groupsReaching(array $closures, array $groups, bool $web, bool $strips): array
    {
        foreach ($closures as $closure) {
            $web = $web || ($groups[$closure]['web'] ?? false);
            $strips = $strips || ($groups[$closure]['strips'] ?? false);
        }

        return [$web, $strips];
    }

    /**
     * Walk one node of a route file, recording into $walk its route registrations, the groups
     * that open a closure, closures assigned to variables, and require/include expressions,
     * each route and include with the closures enclosing it.
     *
     * 'web' or the CSRF middleware reaches a route at any position in its own ->middleware(...),
     * read as Laravel reads it (a leading array is the whole list, otherwise every argument is
     * one middleware), and through any enclosing group that applies it on its chain or in its
     * 'middleware' attribute. ->withoutMiddleware(...) or an 'excluded_middleware' attribute
     * naming either excludes it again, at any level. Method names are matched
     * case-insensitively, as PHP calls them.
     *
     * @param  list<int>  $closures  spl_object_id()s of the closures enclosing $node, outermost first
     * @param  RouteWalk  $walk
     */
    private function walkRouteNode(Node $node, array $closures, array &$walk, BootstrapRouteParser $routeParser): void
    {
        if ($node instanceof Expr\MethodCall || $node instanceof Expr\StaticCall) {
            $this->walkCallChain($node, $closures, $walk, $routeParser);

            return;
        }

        if ($node instanceof Expr\Closure || $node instanceof Expr\ArrowFunction) {
            $closures[] = spl_object_id($node);
        } elseif ($node instanceof Expr\Include_) {
            $walk['includes'][] = ['include' => $node, 'closures' => $closures];
        } elseif ($node instanceof Expr\Assign
            && $node->var instanceof Expr\Variable
            && is_string($node->var->name)
            && ($node->expr instanceof Expr\Closure || $node->expr instanceof Expr\ArrowFunction)) {
            $walk['variables'][$node->var->name] = spl_object_id($node->expr);
        }

        foreach ($node->getSubNodeNames() as $name) {
            $sub = $node->$name;
            foreach (is_array($sub) ? $sub : [$sub] as $child) {
                if ($child instanceof Node) {
                    $this->walkRouteNode($child, $closures, $walk, $routeParser);
                }
            }
        }
    }

    /**
     * Walk a method-call chain as one unit: read it as a route registration when its root is
     * the Route facade or a $router variable, then walk its root and each call's arguments,
     * which may hold further routes.
     *
     * @param  list<int>  $closures
     * @param  RouteWalk  $walk
     */
    private function walkCallChain(Expr\MethodCall|Expr\StaticCall $call, array $closures, array &$walk, BootstrapRouteParser $routeParser): void
    {
        [$chain, $base] = $this->unwindChain($call);

        if (($base instanceof Name && $base->getLast() === 'Route')
            || ($base instanceof Expr\Variable && $base->name === 'router')) {
            $this->readRouteChain($chain, $closures, $walk, $routeParser);
        }

        $children = [$base];
        foreach ($chain as $link) {
            $children = [...$children, $link->name, ...$link->args];
        }

        foreach ($children as $child) {
            $this->walkRouteNode($child, $closures, $walk, $routeParser);
        }
    }

    /**
     * Read a route registration chain, root first: the middleware it applies and excludes,
     * then the group it opens or the state-changing route it registers.
     *
     * @param  list<Expr\MethodCall|Expr\StaticCall>  $chain
     * @param  list<int>  $closures
     * @param  RouteWalk  $walk
     */
    private function readRouteChain(array $chain, array $closures, array &$walk, BootstrapRouteParser $routeParser): void
    {
        // Calls after resource() configure its PendingResourceRegistration, which reads them
        // by its own rules (see resourceState()); calls up to it read as on any route
        $resourceAt = null;
        foreach ($chain as $index => $link) {
            if ($link->name instanceof Identifier && $link->name->toLowerString() === 'resource') {
                $resourceAt = $index;

                break;
            }
        }

        $calls = $this->callsByName($resourceAt === null ? $chain : array_slice($chain, 0, $resourceAt + 1));
        ['web' => $web, 'strips' => $strips] = $this->chainCsrfState($calls, $routeParser);

        if (isset($calls['group'])) {
            $args = $calls['group'][0]->args;
            $state = ['web' => $web, 'strips' => $strips];

            // Each callback the group loads, including each item of a list, opens its closure; a
            // variable callback opens the closure assigned to it last before this call, as PHP reads it
            foreach ($routeParser->groupRoutes($args) as $callback) {
                $closureId = match (true) {
                    $callback instanceof Expr\Closure, $callback instanceof Expr\ArrowFunction => spl_object_id($callback),
                    $callback instanceof Expr\Variable && is_string($callback->name) => $walk['variables'][$callback->name] ?? null,
                    default => null,
                };
                if ($closureId !== null) {
                    $walk['groups'][$closureId] = [
                        'web' => $state['web'] || ($walk['groups'][$closureId]['web'] ?? false),
                        'strips' => $state['strips'] || ($walk['groups'][$closureId]['strips'] ?? false),
                    ];
                }
            }

            return;
        }

        $method = $this->stateChangingRouteMethod($calls);
        if ($resourceAt !== null) {
            [$writes, $resourceWeb, $resourceStrips] = $this->resourceState($chain[$resourceAt], array_slice($chain, $resourceAt + 1), $routeParser);
            $method = $writes ? 'RESOURCE' : null;
            $web = $web || $resourceWeb;
            $strips = $strips || $resourceStrips;
        }

        if ($method !== null && $chain !== []) {
            $walk['routes'][] = [
                'line' => $chain[0]->getStartLine(),
                'method' => $method,
                'web' => $web,
                'strips' => $strips,
                'closures' => $closures,
            ];
        }
    }

    /**
     * A method-call chain's calls, root first, and the node it is called on: the class of a
     * static root, such as Route, or the variable or expression of a method root.
     *
     * @return array{0: list<Expr\MethodCall|Expr\StaticCall>, 1: Node}
     */
    private function unwindChain(Expr\MethodCall|Expr\StaticCall $call): array
    {
        $chain = [];
        $base = $call;
        while ($base instanceof Expr\MethodCall) {
            array_unshift($chain, $base);
            $base = $base->var;
        }
        if ($base instanceof Expr\StaticCall) {
            array_unshift($chain, $base);
            $base = $base->class;
        }

        return [$chain, $base];
    }

    /**
     * Whether a chain applies 'web' or the CSRF middleware, and whether it excludes either:
     * through ->middleware(...) and ->withoutMiddleware(...) and, on a group, its
     * 'middleware' and 'excluded_middleware' attributes.
     *
     * @param  array<string, non-empty-list<Expr\MethodCall|Expr\StaticCall>>  $calls  Chain calls by lowercase name
     * @return array{web: bool, strips: bool}
     */
    private function chainCsrfState(array $calls, BootstrapRouteParser $routeParser): array
    {
        $web = false;
        foreach ($calls['middleware'] ?? [] as $link) {
            $web = $web || $this->namesCarryCsrf($this->entryNames($routeParser->middlewareEntries($link)));
        }

        $strips = false;
        foreach ($calls['withoutmiddleware'] ?? [] as $link) {
            $strips = $strips || $this->namesCarryCsrf($this->entryNames($routeParser->middlewareEntries($link)));
        }

        $args = isset($calls['group']) ? $calls['group'][0]->args : [];

        return [
            'web' => $web || $this->namesCarryCsrf($this->entryNames($routeParser->groupAttributeEntries($args, 'middleware'))),
            'strips' => $strips || $this->namesCarryCsrf($this->entryNames($routeParser->groupAttributeEntries($args, 'excluded_middleware'))),
        ];
    }

    /**
     * Whether the groups a route file is loaded through, outermost first, apply 'web' or
     * the CSRF middleware to it, and whether one excludes either.
     *
     * @param  non-empty-list<Expr\MethodCall|Expr\StaticCall>  $groups
     * @return array{web: bool, strips: bool}
     */
    private function groupsCsrfState(array $groups, BootstrapRouteParser $routeParser): array
    {
        $web = false;
        $strips = false;
        foreach ($groups as $group) {
            $state = $this->chainCsrfState($this->callsByName($this->unwindChain($group)[0]), $routeParser);
            $web = $web || $state['web'];
            $strips = $strips || $state['strips'];
        }

        return ['web' => $web, 'strips' => $strips];
    }

    /**
     * The method a route chain registers when it accepts a request CSRF checks, or null:
     * post, put, patch, delete and any, and match() listing such a verb. resource() is
     * judged by resourceState().
     *
     * @param  array<string, non-empty-list<Expr\MethodCall|Expr\StaticCall>>  $calls  Chain calls by lowercase name
     */
    private function stateChangingRouteMethod(array $calls): ?string
    {
        foreach (['post', 'put', 'patch', 'delete', 'any'] as $verb) {
            if (isset($calls[$verb])) {
                return strtoupper($verb);
            }
        }

        if (isset($calls['match'])) {
            $first = $calls['match'][0]->args[0] ?? null;
            $methods = $first instanceof Node\Arg
                ? $this->entryNames($this->wrapped($first->value))
                : [];
            $methods = array_map(strtoupper(...), array_filter($methods, is_string(...)));

            return array_diff($methods, ['GET', 'HEAD', 'OPTIONS']) !== [] ? 'MATCH' : null;
        }

        return null;
    }

    /**
     * What a resource() registration applies, as Laravel's PendingResourceRegistration and
     * ResourceRegistrar read it: whether it keeps any of store, update and destroy, whether
     * its own middleware lists 'web', and whether it excludes 'web' or the CSRF middleware.
     *
     * The options array (the third argument) sets only, except, middleware and
     * excluded_middleware. A later only(), except() or middleware() call replaces that
     * option, and withoutMiddleware() adds to excluded_middleware. middleware() and
     * withoutMiddleware() wrap their first argument and ignore any others; only() and
     * except() take a list or every argument, as a route's middleware() does.
     *
     * @param  list<Expr\MethodCall|Expr\StaticCall>  $pending  The calls chained after resource()
     * @return array{bool, bool, bool}
     */
    private function resourceState(Expr\MethodCall|Expr\StaticCall $resource, array $pending, BootstrapRouteParser $routeParser): array
    {
        $optionsArg = $resource->args[2] ?? null;
        $options = $optionsArg instanceof Node\Arg && $optionsArg->value instanceof Expr\Array_ ? $optionsArg->value : null;
        $calls = $this->callsByName($pending);

        $writes = ['store', 'update', 'destroy'];
        foreach (['only' => true, 'except' => false] as $filter => $keeps) {
            $entries = isset($calls[$filter])
                ? $routeParser->middlewareEntries($calls[$filter][count($calls[$filter]) - 1])
                : $this->resourceOption($options, $filter);
            if ($entries === null) {
                continue;
            }

            $names = $this->entryNames($entries);
            if (in_array(null, $names, true)) {
                return [false, false, false];
            }
            $writes = $keeps ? array_intersect($writes, $names) : array_diff($writes, $names);
        }

        $middleware = isset($calls['middleware'])
            ? $this->wrappedFirstArgument($calls['middleware'][count($calls['middleware']) - 1])
            : ($this->resourceOption($options, 'middleware') ?? []);

        $excluded = $this->resourceOption($options, 'excluded_middleware') ?? [];
        foreach ($calls['withoutmiddleware'] ?? [] as $link) {
            $excluded = [...$excluded, ...$this->wrappedFirstArgument($link)];
        }

        return [
            $writes !== [],
            $this->namesCarryCsrf($this->entryNames($middleware)),
            $this->namesCarryCsrf($this->entryNames($excluded)),
        ];
    }

    /**
     * The entries a resource option lists: each item of an array value, or the value
     * itself. Null when the options array does not set the option.
     *
     * @return list<Expr>|null
     */
    private function resourceOption(?Expr\Array_ $options, string $key): ?array
    {
        foreach ($options->items ?? [] as $item) {
            if ($item instanceof ArrayItem && $item->key instanceof String_ && $item->key->value === $key) {
                return $this->wrapped($item->value);
            }
        }

        return null;
    }

    /**
     * The entries of a call's first argument as Arr::wrap() reads it: each item of an array,
     * or the value itself. Later arguments are ignored.
     *
     * @return list<Expr>
     */
    private function wrappedFirstArgument(Expr\MethodCall|Expr\StaticCall $call): array
    {
        $first = $call->args[0] ?? null;
        if (! $first instanceof Node\Arg) {
            return [];
        }

        return $this->wrapped($first->value);
    }

    /**
     * The calls of a chain grouped by lowercase method name, in chain order.
     *
     * @param  list<Expr\MethodCall|Expr\StaticCall>  $chain
     * @return array<string, non-empty-list<Expr\MethodCall|Expr\StaticCall>>
     */
    private function callsByName(array $chain): array
    {
        $calls = [];
        foreach ($chain as $link) {
            if ($link->name instanceof Identifier) {
                $calls[$link->name->toLowerString()][] = $link;
            }
        }

        return $calls;
    }

    /**
     * The name each middleware or route-method entry reads as, with null for one that cannot be read.
     *
     * @param  array<Expr>  $entries
     * @return list<string|null>
     */
    private function entryNames(array $entries): array
    {
        return array_values(array_map($this->middlewareName(...), $entries));
    }

    /**
     * A value as Arr::wrap() reads it: each item of an array, or the value itself.
     *
     * @return list<Expr>
     */
    private function wrapped(Expr $value): array
    {
        if (! $value instanceof Expr\Array_) {
            return [$value];
        }

        $values = [];
        foreach ($value->items as $item) {
            if ($item instanceof ArrayItem) {
                $values[] = $item->value;
            }
        }

        return $values;
    }

    /**
     * Whether these middleware carry CSRF protection, so that applying them protects a route
     * and excluding them removes it: they name 'web' or a CSRF middleware.
     *
     * @param  list<string|null>  $names
     */
    private function namesCarryCsrf(array $names): bool
    {
        return in_array('web', $names, true) || $this->csrfMiddlewareInList($names) !== null;
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
