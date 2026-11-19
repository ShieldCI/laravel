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
 * @phpstan-type CsrfState array{group: bool, applied: list<string>, excluded: list<string|null>, api: bool, unread: bool}
 * @phpstan-type RouteLoad array{state: CsrfState, known: bool, proven: bool, once: bool, apiFile: bool}
 * @phpstan-type ActionMiddleware array{middleware: list<string|null>|null, excluded: list<string|null>|null, dropsRegistrar: bool}
 * @phpstan-type RouteWalk array{
 *     routes: array<int, array{line: int, method: string, states: non-empty-list<CsrfState>, closures: list<int>}>,
 *     groups: array<int, non-empty-list<array{state: CsrfState, closures: list<int>}>>,
 *     variables: array<string, int>,
 *     resolved: array<int, list<Expr>>,
 *     includes: list<array{include: Expr\Include_, closures: list<int>}>,
 *     paths: list<array{path: Expr, state: CsrfState, closures: list<int>}>,
 *     routers: array<int, array<string, true>>,
 *     callbacks: array<int, true>,
 *     late: bool,
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

    /**
     * The CSRF state of a chain that applies and excludes nothing.
     *
     * @var array{group: false, applied: list<string>, excluded: list<string|null>, api: false, unread: false}
     */
    private const NO_CSRF = ['group' => false, 'applied' => [], 'excluded' => [], 'api' => false, 'unread' => false];

    /**
     * What an action that names no middleware gives a route (see routeActionMiddleware()).
     *
     * @var ActionMiddleware
     */
    private const NO_ACTION_MIDDLEWARE = ['middleware' => null, 'excluded' => null, 'dropsRegistrar' => false];

    /**
     * The most registrations of one route statesReaching() follows, one per group() call that
     * runs each reused group callback around it; the walk stops once it has this many. Also the
     * most loads of one route file addLoad() keeps.
     */
    private const MAX_REGISTRATIONS = 64;

    /**
     * The RouteRegistrar attribute methods, lowercased: calls a chain makes before it registers
     * a route or group. The where*() constraint helpers stay on the registrar too.
     *
     * @var list<string>
     */
    private const REGISTRAR_ATTRIBUTES = [
        'as', 'can', 'controller', 'domain', 'metadata', 'middleware', 'missing', 'name',
        'namespace', 'prefix', 'scopebindings', 'where', 'withoutmiddleware', 'withoutscopedbindings',
    ];

    /**
     * The methods, lowercase, that register a route or open a group on the router or a
     * registrar, besides the resource registrations (see RESOURCE_REGISTRATIONS).
     */
    private const ROUTE_REGISTRATIONS = ['get', 'post', 'put', 'patch', 'delete', 'options', 'any', 'match', 'group'];

    /**
     * The framework's VerifyCsrfToken, which an application's own CSRF middleware extends.
     */
    private const FRAMEWORK_VERIFY_CSRF = 'Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken';

    /**
     * Router methods that register resource routes, lowercased, each with the method label its
     * findings carry and whether it is a plural form that takes a list of resources.
     *
     * @var array<string, array{string, bool}>
     */
    private const RESOURCE_REGISTRATIONS = [
        'resource' => ['RESOURCE', false],
        'apiresource' => ['RESOURCE', false],
        'resources' => ['RESOURCE', true],
        'apiresources' => ['RESOURCE', true],
        'softdeletableresources' => ['RESOURCE', true],
        'singleton' => ['SINGLETON', false],
        'apisingleton' => ['SINGLETON', false],
        'singletons' => ['SINGLETON', true],
        'apisingletons' => ['SINGLETON', true],
    ];

    /**
     * The classes the container resolves the router as, besides its 'router' binding.
     *
     * @var list<string>
     */
    private const ROUTER_CLASSES = ['Illuminate\Routing\Router', 'Illuminate\Contracts\Routing\Registrar'];

    /**
     * The CSRF middleware the web group holds, as modelled from app/Http/Kernel.php (see
     * kernelWebGroupCsrf()) or bootstrap/app.php, or null when it is not modelled: the
     * application has neither file, the Kernel's web group cannot be settled, withMiddleware()
     * is not given a closure, or a group, append, remove or replace list cannot be read.
     *
     * @var list<string>|null
     */
    private ?array $webGroupCsrf = null;

    /**
     * Whether the Kernel's global $middleware runs CSRF middleware, as read from a Kernel the
     * application uses and nothing may change. withoutMiddleware() and excluded_middleware filter
     * route middleware only, so no route exclusion removes that check.
     */
    private bool $globalCsrf = false;

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
        $this->webGroupCsrf = null;
        $this->globalCsrf = false;

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
     * Scans the form body up to its </form>, never past the next <form>, with Blade and
     * HTML comments blanked, so a token or a closing tag that is commented out does not count.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function checkBladeFormsForCsrf(string $file, array &$issues): void
    {
        $content = FileParser::readFile($file);
        if ($content === null) {
            return;
        }

        foreach ($this->mutatingForms($content) as [$lineNumber, $method, $body]) {
            // Check for CSRF token patterns:
            // - @csrf or @csrf() - Blade directive (with or without parentheses)
            // - <x-csrf /> or <x-csrf/> - Blade component
            // - csrf_field() - Helper function
            // - <input name="_token" ... /> - Manual token input
            $hasCsrf = preg_match('/@csrf(\(\))?|<x-csrf\s*\/?>|csrf_field\(\)|<input[^<>]*name\s*=\s*["\']_token["\']/', $body) === 1;

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

    /**
     * Every form whose opening tag names POST, PUT, PATCH or DELETE, as its 0-indexed
     * line, the upper-cased method and its body.
     *
     * One forward pass over the whole template, so a tag whose attributes span several
     * lines is read like a one-line tag. Blade and HTML comments are blanked first,
     * keeping every newline, so a commented-out form, token or closing tag does not
     * count and line numbers stay exact.
     *
     * The tag itself is read with Blade echoes blanked too. Blade replaces an echo before
     * a browser ever parses the tag, so a quote or an arrow inside `{{ __("It's") }}` or
     * `{{ $attributes->merge([...]) }}` is not the tag's own. The body keeps its echoes,
     * since `{{ csrf_field() }}` is one of the tokens looked for there.
     *
     * A tag ends at the first `>` outside a quoted attribute value, so an arrow or a
     * comparison inside `action="..."` or `:class="..."` does not cut it short. Both the
     * tag end and the body are only looked for before the next `<form`: an unbalanced
     * quote then falls back to the first bare `>` rather than swallowing the following
     * form, a tag with no `>` before the next one is skipped, a missing `</form>` does
     * not lend a later form's token to this one, and no stretch of the file is read
     * twice, which keeps the pass linear in the file size.
     *
     * @return list<array{int, string, string}>
     */
    private function mutatingForms(string $content): array
    {
        $masked = $this->blankDelimited($content, ['{{--' => ['--}}'], '<!--' => ['-->', '--!>']]);
        $opaque = $this->blankDelimited($masked, ['{{' => ['}}'], '{!!' => ['!!}']]);
        $length = strlen($opaque);

        $forms = [];
        $lineNumber = 0;
        $countedTo = 0;
        $next = $this->nextFormTagStart($opaque, 0);

        while ($next !== null) {
            $tagStart = $next;
            $next = $this->nextFormTagStart($opaque, $tagStart + 1);
            $windowEnd = $next ?? $length;
            $window = substr($opaque, $tagStart, $windowEnd - $tagStart);

            if (preg_match('/\A<form(?:[^>"\']++|"[^"]*+"|\'[^\']*+\')*+>/i', $window, $close) === 1) {
                $tag = $close[0];
                $method = $this->mutatingFormMethod($tag, true);
            } else {
                $bare = strpos($window, '>');
                if ($bare === false) {
                    continue;
                }

                // The quotes do not pair up, so they cannot be skipped as values either.
                $tag = substr($window, 0, $bare + 1);
                $method = $this->mutatingFormMethod($tag, false);
            }

            if ($method === null) {
                continue;
            }

            $bodyStart = $tagStart + strlen($tag);
            $body = substr($masked, $bodyStart, $windowEnd - $bodyStart);
            if (preg_match('/<\/form\s*>/i', $body, $closing, PREG_OFFSET_CAPTURE) === 1) {
                $body = substr($body, 0, $closing[0][1]);
            }

            $lineNumber += substr_count($opaque, "\n", $countedTo, $tagStart - $countedTo);
            $countedTo = $tagStart;
            $forms[] = [$lineNumber, $method, $body];
        }

        return $forms;
    }

    /**
     * Byte offset of the next `<form` that opens a form element, not a longer tag name
     * such as `<formation` or `<form-wizard`.
     */
    private function nextFormTagStart(string $text, int $offset): ?int
    {
        return preg_match('/<form(?=[\s>\/])/i', $text, $open, PREG_OFFSET_CAPTURE, $offset) === 1
            ? $open[0][1]
            : null;
    }

    /**
     * The text with every span from one of the given openers to its nearest closer
     * replaced by spaces, keeping every newline so byte offsets and line numbers are
     * unchanged. An opener with no closer after it is left as text.
     *
     * HTML also ends a comment at `--!>`, and treats `<!-->` and `<!--->` as complete
     * empty comments, so those never blank the text up to a later `-->`.
     *
     * The next position of each closer is remembered and only searched for again once
     * the scan has passed it, and a closer found missing is never searched for again,
     * so the pass stays linear in the file size.
     *
     * @param  array<string, list<string>>  $closers  Each opener and the closers that end it.
     */
    private function blankDelimited(string $text, array $closers): string
    {
        $openers = '/'.implode('|', array_map(static fn (string $opener): string => preg_quote($opener, '/'), array_keys($closers))).'/';
        $nextAt = [];
        $pieces = [];
        $copiedTo = 0;
        $offset = 0;

        while (preg_match($openers, $text, $open, PREG_OFFSET_CAPTURE, $offset) === 1) {
            [$opener, $start] = $open[0];
            $offset = $start + strlen($opener);
            $end = null;

            if ($opener === '<!--') {
                $probe = substr($text, $offset, 2);
                $end = str_starts_with($probe, '>') ? $offset + 1 : ($probe === '->' ? $offset + 2 : null);
            }

            foreach ($end === null ? $closers[$opener] : [] as $closer) {
                // Remembered as the offset just past the closer, which \K reports directly.
                if (! array_key_exists($closer, $nextAt) || ($nextAt[$closer] !== false && $offset > $nextAt[$closer] - strlen($closer))) {
                    $nextAt[$closer] = preg_match('/'.preg_quote($closer, '/').'\K/', $text, $found, PREG_OFFSET_CAPTURE, $offset) === 1
                        ? $found[0][1]
                        : false;
                }

                $closerEnd = $nextAt[$closer];
                if ($closerEnd !== false && ($end === null || $closerEnd < $end)) {
                    $end = $closerEnd;
                }
            }

            if ($end === null) {
                continue;
            }

            $pieces[] = substr($text, $copiedTo, $start - $copiedTo);
            $pieces[] = (string) preg_replace('/[^\n]/', ' ', substr($text, $start, $end - $start));
            $copiedTo = $end;
            $offset = $end;
        }

        $pieces[] = substr($text, $copiedTo);

        return implode('', $pieces);
    }

    /**
     * The upper-cased value of a form tag's `method` attribute when it is POST, PUT,
     * PATCH or DELETE, quoted or not. Only the first `method` attribute counts, as in
     * a browser.
     *
     * The name has to stand alone, so `data-method`, `formmethod` and a bound
     * `:method` or `x-bind:method` are not read as the form's own. When the tag's quotes
     * pair up, quoted values are consumed whole before `method` is looked for, so a
     * `method=` written inside another attribute's value is not read either.
     */
    private function mutatingFormMethod(string $tag, bool $quotesPair): ?string
    {
        $attribute = '(?<![\w:.@-])method\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'>]+))';
        $pattern = $quotesPair ? '/"[^"]*"|\'[^\']*\'|'.$attribute.'/i' : '/'.$attribute.'/i';

        preg_match_all($pattern, $tag, $matches, PREG_SET_ORDER | PREG_UNMATCHED_AS_NULL);

        foreach ($matches as $match) {
            $value = $match[1] ?? $match[2] ?? $match[3] ?? null;
            if ($value === null) {
                continue;
            }

            $value = strtoupper($value);

            return in_array($value, ['POST', 'PUT', 'PATCH', 'DELETE'], true) ? $value : null;
        }

        return null;
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

                    if ($this->excludesEveryRoute($exception)) {
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
     * Determine if a CSRF exception pattern excludes every route.
     *
     * The middleware trims slashes from a pattern other than '/' and matches it with Str::is()
     * against both the path and the full URL, turning each '*' into '.*'. Every full URL holds
     * '://', so a pattern made only of '*' and '/' with at least one '*' and at most two slashes
     * matches every request, the root URL included; a third slash spares at least the root.
     */
    private function excludesEveryRoute(string $exception): bool
    {
        $pattern = $exception === '/' ? $exception : trim($exception, '/');

        return str_contains($pattern, '*')
            && trim($pattern, '*/') === ''
            && substr_count($pattern, '/') <= 2;
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
     *
     * Also models what the route checks match exclusions against, when the same reading settles
     * it and bootstrap/app.php does not replace the Kernel (see bootstrapConfiguresApplication()):
     * $globalCsrf when the global $middleware runs CSRF, and otherwise the web group's CSRF
     * middleware in $webGroupCsrf (see kernelWebGroupCsrf()).
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
        $globalEntries = $global !== null ? $this->kernelListEntries($global, [], [], true) : null;

        $webEntries = isset($groups['web']) || $groupsComplete
            ? $this->kernelListEntries($groups['web'] ?? null, $groups, $aliases, $complete, ['web' => true])
            : null;
        $webRuns = $webEntries !== null ? $this->kernelEntriesRunCsrf($webEntries) : null;

        // A custom parent or a method may change the middleware, and Application::configure() binds the framework's Kernel
        $mayChange = $this->kernelMayChangeMiddleware($class);
        if (! $isCustomParent && ! $mayChange && ! $this->bootstrapConfiguresApplication()) {
            $globalRunsCsrf = $this->kernelGlobalRunsCsrf($globalEntries);
            $this->globalCsrf = $globalRunsCsrf === true;
            // A literal 'web' key in a map that may hold more keys may be overridden by one of them
            $this->webGroupCsrf = $globalRunsCsrf === false && $groupsComplete ? $this->kernelWebGroupCsrf($webEntries) : null;
        }

        if ($globalRuns === true || $webRuns === true) {
            return true;
        }

        if ($globalRuns === null || $webRuns === null || $mayChange) {
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
     * Whether a Kernel middleware list runs CSRF middleware (see kernelListEntries()). Null when
     * none does but an entry, or the list itself, cannot be settled.
     *
     * @param  array<string, Expr>  $groups
     * @param  array<string, Expr>  $aliases
     * @param  bool  $complete  Whether $groups and $aliases hold every key the Kernel registers
     * @param  array<string, true>  $seen
     */
    private function kernelListRunsCsrf(?Expr $list, array $groups, array $aliases, bool $complete, array $seen = []): ?bool
    {
        $entries = $this->kernelListEntries($list, $groups, $aliases, $complete, $seen);

        return $entries !== null ? $this->kernelEntriesRunCsrf($entries) : null;
    }

    /**
     * The middleware a Kernel list finally holds, resolved as Laravel resolves an entry: a group
     * name comes first, then an alias, and only then a class name; a group is never followed back
     * into itself. Each entry is the class name with any :parameters, as an alias passes them on
     * to its target, except empty or '0' ones (see groupEntry()), or null when it cannot be
     * read, with whether the maps it was resolved against are complete, so that a name they lack
     * is a class rather than possibly a group or alias they do not show. An alias names a class,
     * so its target is read without the groups and aliases. Null when the list itself cannot be
     * read.
     *
     * @param  array<string, Expr>  $groups
     * @param  array<string, Expr>  $aliases
     * @param  bool  $complete  Whether $groups and $aliases hold every key the Kernel registers
     * @param  array<string, true>  $seen
     * @return list<array{string|null, bool}>|null
     */
    private function kernelListEntries(?Expr $list, array $groups, array $aliases, bool $complete, array $seen = []): ?array
    {
        $names = $this->middlewareList($list);
        if ($names === null) {
            return null;
        }

        $entries = [];

        foreach ($names as $name) {
            if ($name === null) {
                $entries[] = [null, $complete];

                continue;
            }

            [$alias, $parameters] = array_pad(explode(':', $name, 2), 2, null);
            $parameters = $parameters !== null && $parameters !== '' && $parameters !== '0' ? $parameters : null;

            if (isset($groups[$name])) {
                $nested = isset($seen[$name])
                    ? []
                    : $this->kernelListEntries($groups[$name], $groups, $aliases, $complete, $seen + [$name => true]);
                array_push($entries, ...($nested ?? [[null, $complete]]));
            } elseif (isset($aliases[$alias])) {
                foreach ($this->kernelListEntries($aliases[$alias], [], [], true) ?? [[null, true]] as [$target]) {
                    $entries[] = [$target !== null && $parameters !== null ? "{$target}:{$parameters}" : $target, true];
                }
            } else {
                $entries[] = [$this->groupEntry($name), $complete];
            }
        }

        return $entries;
    }

    /**
     * A middleware group entry as Laravel resolves it:
     * MiddlewareNameResolver::parseMiddlewareGroup() drops empty or '0' parameters, so 'Class:'
     * and 'Class:0' run as the class itself.
     */
    private function groupEntry(string $name): string
    {
        $parts = explode(':', $name, 2);

        return in_array($parts[1] ?? null, [null, '', '0'], true) ? $parts[0] : $name;
    }

    /**
     * Whether resolved Kernel entries run CSRF middleware: true when one does, null when none
     * does but one cannot be settled.
     *
     * @param  list<array{string|null, bool}>  $entries
     */
    private function kernelEntriesRunCsrf(array $entries): ?bool
    {
        $runsCsrf = false;

        foreach ($entries as [$name, $complete]) {
            $entryRunsCsrf = $name !== null ? $this->kernelClassRunsCsrf(explode(':', $name, 2)[0], $complete) : null;

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
     * The CSRF middleware the Kernel's web group holds, from its resolved entries, or null when
     * the group cannot be settled: the list or an entry cannot be read, an entry other than a
     * CSRF class may be a group or alias the incomplete maps do not show, an application class
     * may be CSRF middleware (see kernelEntryIsCsrf()), or the group holds none, which leaves
     * the version fallback to judge an exclusion as before. An entry with :parameters is kept
     * with them, as only an exclusion of the same string removes it (see csrfAncestors()).
     *
     * @param  list<array{string|null, bool}>|null  $entries
     * @return list<string>|null
     */
    private function kernelWebGroupCsrf(?array $entries): ?array
    {
        if ($entries === null) {
            return null;
        }

        $csrf = [];

        foreach ($entries as [$name, $complete]) {
            if ($name === null) {
                return null;
            }

            $class = explode(':', $name, 2)[0];
            if (! $complete && $this->kernelClassRunsCsrf($class, false) !== true) {
                return null;
            }

            $isCsrf = $this->kernelEntryIsCsrf($class);
            if ($isCsrf === null) {
                return null;
            }

            if ($isCsrf) {
                $csrf[] = $name;
            }
        }

        return $csrf !== [] ? $csrf : null;
    }

    /**
     * Whether the Kernel's global $middleware runs CSRF middleware: true when an entry is the
     * framework's CSRF middleware or its parents read from app/ reach it, null when none is but
     * the list or an entry is unknown. Unlike a web group entry (see kernelEntryIsCsrf()), a
     * CSRF name alone proves nothing here, as $globalCsrf credits every route with the check,
     * so an entry counted only by its name, such as a vendor SkipVerifyCsrfToken helper, is
     * unknown.
     *
     * @param  list<array{string|null, bool}>|null  $entries
     */
    private function kernelGlobalRunsCsrf(?array $entries): ?bool
    {
        $runsCsrf = $entries === null ? null : false;

        foreach ($entries ?? [] as [$name]) {
            $class = $name !== null ? explode(':', $name, 2)[0] : null;
            $entryRunsCsrf = match ($class !== null ? $this->csrfChain($class) : 'unknown') {
                'framework' => true,
                'other' => false,
                'ends' => $class !== null && $this->csrfMiddlewareIn($class) !== null ? null : false,
                'unknown', 'deep' => null,
            };

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
     * Whether a Kernel web group entry's class is CSRF middleware (see csrfChain()): it is when
     * it reaches the framework's CSRF middleware, and is not when it reaches another Illuminate
     * class. A chain that ends elsewhere counts it by its name, as in bootstrap/app.php, such as
     * a CustomVerifyCsrfToken that checks the token itself; so does one that cannot be followed
     * when the name holds a CSRF name, which csrfAncestors() assumes extends VerifyCsrfToken,
     * and otherwise it is unknown (null). A chain deeper than the parents followed is unknown
     * too, as csrfAncestors() stops at the same depth.
     */
    private function kernelEntryIsCsrf(string $class): ?bool
    {
        $named = $this->csrfMiddlewareIn($class) !== null;

        return match ($this->csrfChain($class)) {
            'framework' => true,
            'other' => false,
            'ends' => $named,
            'unknown' => $named ? true : null,
            'deep' => null,
        };
    }

    /**
     * Where a middleware class's parents lead, following an application class through the files
     * under app/ for a few levels: 'framework' at the framework's CSRF middleware, 'other' at
     * another Illuminate class, 'ends' at an application class read without a parent or a
     * vendor class whose name holds no CSRF name, 'unknown' at an application class whose file
     * cannot be read or a vendor class whose name holds a CSRF name, which may extend it, and
     * 'deep' when the levels run out still under App.
     *
     * @return 'framework'|'other'|'ends'|'unknown'|'deep'
     */
    private function csrfChain(string $class): string
    {
        $class = ltrim($class, '\\');

        for ($depth = 0; str_starts_with($class, 'App\\'); $depth++) {
            if ($depth === 5) {
                return 'deep';
            }

            $parent = $this->applicationParent($class);
            if ($parent === null) {
                return 'unknown';
            }
            if ($parent === false) {
                return 'ends';
            }
            $class = ltrim($parent, '\\');
        }

        $framework = 'Illuminate\\Foundation\\Http\\Middleware\\';
        if (str_starts_with($class, $framework) && in_array(substr($class, strlen($framework)), self::CSRF_MIDDLEWARE, true)) {
            return 'framework';
        }

        if (str_starts_with($class, 'Illuminate\\')) {
            return 'other';
        }

        return $this->csrfMiddlewareIn($class) !== null ? 'unknown' : 'ends';
    }

    /**
     * Whether bootstrap/app.php starts the application with Application::configure(), whose
     * builder binds the framework's HTTP Kernel, so that app/Http/Kernel.php is a leftover the
     * application does not use. A Laravel 10 bootstrap/app.php binds the application's Kernel
     * itself and has no such call. The class is matched by its last segment, as
     * BootstrapRouteParser matches the builder.
     */
    private function bootstrapConfiguresApplication(): bool
    {
        $file = $this->buildPath('bootstrap', 'app.php');
        if (! file_exists($file)) {
            return false;
        }

        foreach ($this->parser->findNodes($this->resolveNamesForMatching($this->parser->parseFile($file)), Expr\StaticCall::class) as $call) {
            if ($call instanceof Expr\StaticCall
                && $call->class instanceof Name
                && $call->name instanceof Identifier
                && $call->name->toLowerString() === 'configure') {
                $resolved = $call->class->getAttribute('resolvedName');
                $name = ($resolved instanceof Name ? $resolved : $call->class)->getLast();

                if (strcasecmp($name, 'Application') === 0) {
                    return true;
                }
            }
        }

        return false;
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
        $ast = $this->resolveNamesForMatching($this->parser->parseFile($file));
        $calls = $this->configuratorCalls($this->parser, $ast);

        // withMiddleware() given anything but a closure configures the group out of sight
        $opaque = false;
        foreach ($this->parser->findNodes($ast, Expr\MethodCall::class) as $call) {
            if ($call instanceof Expr\MethodCall && $call->name instanceof Identifier
                && $call->name->toLowerString() === 'withmiddleware'
                && ($argument = $this->callArgument($call, 0, 'callback')) !== null
                && ! $argument instanceof Expr\Closure && ! $argument instanceof Expr\ArrowFunction) {
                $opaque = true;
            }
        }

        $this->checkBootstrapCsrfExceptions($calls, $file, $issues);
        $this->checkWebGroupInBootstrap($calls, $file, $issues, $opaque);
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

            $wildcards = array_values(array_filter($exceptions, fn (string $exception): bool => $this->excludesEveryRoute($exception)));

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
     * @param  bool  $opaque  Whether withMiddleware() is given something other than a closure
     */
    private function checkWebGroupInBootstrap(array $calls, string $file, array &$issues, bool $opaque): void
    {
        /** @var array{entries: list<string|null>, line: int}|null $group */
        $group = null;
        /** @var array<string, array{0: string|null, 1: int}> $replacements */
        $replacements = [];
        /** @var array<string, int> $removals */
        $removals = [];
        /** @var list<string|null> $additions */
        $additions = [];
        // An append, prepend, removal or replacement that cannot be read leaves the group unknown,
        // and so does a withMiddleware() not given a closure, whose calls are not read at all
        $unreadable = $opaque;

        foreach ($calls as $call) {
            if (! $call->name instanceof Identifier) {
                continue;
            }

            $line = $call->name->getStartLine();
            $method = $call->name->toLowerString();
            $removing = [];

            if ($method === 'web') {
                $lists = [
                    $this->middlewareList($this->callArgument($call, 2, 'remove')),
                    $this->middlewareList($this->callArgument($call, 0, 'append')),
                    $this->middlewareList($this->callArgument($call, 1, 'prepend')),
                ];
                $unreadable = $unreadable || in_array(null, $lists, true);
                $removing = $lists[0] ?? [];
                $additions = array_merge($additions, $lists[1] ?? [], $lists[2] ?? []);

                $replace = $this->callArgument($call, 3, 'replace');
                $unreadable = $unreadable || ($replace !== null && ! $replace instanceof Expr\Array_);
                foreach ($replace instanceof Expr\Array_ ? $replace->items : [] as $item) {
                    $search = $item instanceof ArrayItem && $item->key !== null ? $this->middlewareName($item->key) : null;

                    if ($item instanceof ArrayItem && $search !== null) {
                        $replacements[$search] = [$this->middlewareName($item->value), $line];
                    } else {
                        $unreadable = true;
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
                        $unreadable = $unreadable || $middleware === null;
                        $additions = array_merge($additions, $middleware ?? []);
                        break;

                    case 'removefromgroup':
                        $unreadable = $unreadable || $middleware === null;
                        $removing = $middleware ?? [];
                        break;

                    case 'replaceingroup':
                        $search = $this->middlewareName($this->callArgument($call, 1, 'search'));

                        if ($search !== null) {
                            $replacements[$search] = [$this->middlewareName($this->callArgument($call, 2, 'replace')), $line];
                        } else {
                            $unreadable = true;
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

        // The group the routes run with: removals take exact names, then prepends and appends join
        $final = [...array_diff($entries, array_keys($removals)), ...$additions];
        $this->webGroupCsrf = $unreadable || in_array(null, $final, true)
            ? null
            : array_values(array_map($this->groupEntry(...), array_filter($final, fn (?string $name): bool => $name !== null && $this->csrfMiddlewareIn($name) !== null)));

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
     * Check custom route files for state-changing routes a load of their file leaves without
     * CSRF protection.
     *
     * IMPORTANT: routes/web.php automatically has 'web' middleware applied globally
     * via RouteServiceProvider (Laravel 10) or bootstrap/app.php (Laravel 11+).
     *
     * Laravel registers a route file's routes once per load, merging the middleware and excluded
     * middleware of every group around the load into each of them, so each load of a file is
     * judged separately and a route is reported when any load leaves it unprotected (see
     * unprotectedBy()). A load carries the CSRF state of the groups around it, merged down require
     * chains of any depth. routes/web.php and a file registered under 'web' externally are loaded
     * under 'web'. routes/api.php and a file registered under 'api' externally are api files, and
     * so is a file such a file loads where neither 'web' nor a CSRF class reaches the load. A load
     * in bootstrap/app.php or a provider, group or not, carries the state of the groups around it.
     * A route file loads a file by requiring it or through a group() path argument, which then
     * counts as a require at that place, and the loaded file gets each load of the route file
     * merged with the groups around the require.
     *
     * Only a load proven to run with its middleware read adds a registration to a file a proven
     * load reaches: not one from a route file nothing is known to load, from a provider method
     * Laravel never calls, or through a group whose middleware or exclusions cannot be read (see
     * externalLoads()). Of the loads through a require_once or include_once only one registers,
     * so they count only when every one of them leaves a route unprotected. A load that a later
     * load of the same routes replaces is dropped.
     *
     * A route file nothing is known to load, and no other route file loads, may never run: it is
     * judged as loaded plainly, and so are the files it loads and any file in a require cycle no
     * known load reaches. Such a file's requires count only where no proven load reaches: a
     * require from it can extend coverage but never take it away, and one there that excludes
     * the CSRF middleware passes nothing on. Every file is read through the AST: see
     * walkRouteNode() for what reaches a route.
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
        $web = ['state' => [...self::NO_CSRF, 'group' => true], 'known' => true, 'proven' => true, 'once' => false, 'apiFile' => false];
        // routes/api.php and files registered under 'api' use token authentication, not CSRF cookies
        $api = ['state' => self::NO_CSRF, 'known' => true, 'proven' => true, 'once' => false, 'apiFile' => true];

        /** @var list<array{string, RouteLoad}> $known */
        $known = [];
        foreach ($webProtectedFiles as $file) {
            $known[] = [$file, $web];
        }
        foreach ($apiRegisteredFiles as $file) {
            $known[] = [$file, $api];
        }

        $walks = [];
        foreach ($routeFiles as $file) {
            $real = realpath($file);
            $normalizedPath = str_replace('\\', '/', $real !== false ? $real : $file);

            if (str_ends_with($normalizedPath, '/routes/api.php')) {
                $known[] = [$normalizedPath, $api];
            }

            // routes/web.php gets 'web' applied globally
            if (str_ends_with($normalizedPath, '/routes/web.php')) {
                $known[] = [$normalizedPath, $web];
            }

            $walks[$normalizedPath] = ['file' => $file, 'walk' => $this->walkRouteFile($file, $routeParser)];
        }

        $known = [...$known, ...$this->externalLoads($routeParser)];

        // The files each route file loads, by a require or a group() path argument, as the walk reads them
        $includes = array_map(fn (array $entry): array => $entry['walk']['includes'], $walks);

        /** @var array<string, array<string, RouteLoad>> $fileLoads */
        $fileLoads = [];
        $queue = [];
        foreach ($known as [$file, $load]) {
            if ($this->addLoad($fileLoads, $file, $load)) {
                $queue[] = [$file, $load];
            }
        }
        $this->propagateLoads($includes, $fileLoads, $queue);

        // A route file no known load reaches is read as loaded plainly for what it loads: first
        // those no other route file loads, then whatever is left, such as a require cycle. The
        // plain load is not one of its own loads, so a file that gets a load another way is
        // judged by that load alone
        $plain = ['state' => self::NO_CSRF, 'known' => false, 'proven' => false, 'once' => false, 'apiFile' => false];
        $targets = [];
        foreach ($includes as $path => $list) {
            foreach ($list as $include) {
                if ($include['file'] !== $path) {
                    $targets[$include['file']] = true;
                }
            }
        }
        $unloaded = array_keys(array_diff_key($walks, $fileLoads, $targets));
        $this->propagateLoads($includes, $fileLoads, array_map(fn (string $path): array => [$path, $plain], $unloaded));
        $unloaded = array_keys(array_diff_key($walks, $fileLoads));
        $this->propagateLoads($includes, $fileLoads, array_map(fn (string $path): array => [$path, $plain], $unloaded));

        // What unprotectedBy() said, by load key (see addLoad()) and serialized route state
        /** @var array<string, array<string, 'missing'|'stripped'|'excluded'|null>> $verdicts */
        $verdicts = [];
        foreach ($walks as $path => $entry) {
            // A file no load reaches is judged as loaded plainly. A load not proven to run with the
            // middleware read adds nothing to a file a proven load reaches
            $loads = $fileLoads[$path] ?? ['plain' => $plain];
            // A require_once or include_once is not proven to register anything either, as PHP
            // skips it for a file already loaded, so a proven plain require leaves it nothing
            $certain = array_filter($loads, fn (array $load): bool => $load['proven'] && ! $load['once']);
            if ($certain !== []) {
                $loads = $certain;
                $once = [];
            } else {
                $proven = array_filter($loads, fn (array $load): bool => $load['proven']);
                $loads = $proven !== [] ? $proven : $loads;
                // Of the loads through a require_once or include_once only one registers, which
                // one is not known, so they leave a route unprotected only when every one does
                $once = array_filter($loads, fn (array $load): bool => $load['once']);
                $loads = array_diff_key($loads, $once);
            }

            $unprotected = [];
            foreach ($entry['walk']['routes'] as $route) {
                // Each state is one registration of the route in its file, and each load of the
                // file registers it again; any that leaves it unprotected is reported, the weakest first
                $reasons = [];
                foreach ($route['states'] as $state) {
                    // Routes of one group share a state, so each load judges it once
                    $stateKey = serialize($state);
                    foreach ($loads as $loadKey => $load) {
                        $reasons[] = $this->judgedOnce($verdicts, (string) $loadKey, $load, $stateKey, $state);
                    }
                    if ($once !== []) {
                        $onceReasons = [];
                        foreach ($once as $loadKey => $load) {
                            $onceReasons[] = $this->judgedOnce($verdicts, (string) $loadKey, $load, $stateKey, $state);
                        }
                        if (! in_array(null, $onceReasons, true)) {
                            // The mildest, as the one that registers may be any of them
                            $reasons[] = in_array('excluded', $onceReasons, true) ? 'excluded' : (in_array('stripped', $onceReasons, true) ? 'stripped' : 'missing');
                        }
                    }
                }
                foreach (['missing', 'stripped', 'excluded'] as $reason) {
                    if (in_array($reason, $reasons, true)) {
                        $unprotected[] = ['line' => $route['line'], 'method' => $route['method'], 'reason' => $reason];

                        break;
                    }
                }
            }
            $this->reportUnprotectedRoutes($entry['file'], $unprotected, $issues);
        }
    }

    /**
     * unprotectedBy() for a load and a route state, kept in $verdicts by their keys, as the
     * routes of one group share a state.
     *
     * @param  array<string, array<string, 'missing'|'stripped'|'excluded'|null>>  $verdicts
     * @param  RouteLoad  $load
     * @param  CsrfState  $state
     * @return 'missing'|'stripped'|'excluded'|null
     */
    private function judgedOnce(array &$verdicts, string $loadKey, array $load, string $stateKey, array $state): ?string
    {
        if (! isset($verdicts[$loadKey]) || ! array_key_exists($stateKey, $verdicts[$loadKey])) {
            $verdicts[$loadKey][$stateKey] = $this->unprotectedBy($load, $state);
        }

        return $verdicts[$loadKey][$stateKey];
    }

    /**
     * Each load bootstrap/app.php or a provider makes, with the CSRF state of the groups around
     * it there. A load is proven when it runs and its middleware is read: a load in a provider
     * method Laravel never calls, or in a withRouting(using: ...) callback beside then:, is not
     * (see sourceScopes()), nor is one with a middleware or exclusion that cannot be read. Of
     * two loads of the same file in the same function with the same prefix and domain only the
     * later in the order they run registers, as RouteCollection keys a route by its method,
     * domain and URI and the later one replaces the earlier.
     *
     * @return list<array{string, RouteLoad}>
     */
    private function externalLoads(BootstrapRouteParser $routeParser): array
    {
        $scopes = [];
        $ordered = [];
        foreach ($routeParser->getExternalRouteFileLoads() as $load) {
            $calls = $load['calls'];
            $state = $calls === [] ? self::NO_CSRF : $this->groupsCsrfState($calls, $routeParser);
            $scopes[$load['source']] ??= $this->sourceScopes($load['source']);
            // The outermost group runs its callback where it is called, so its place orders the load
            [$live, $scope, $order] = $this->scopeOf($calls[0] ?? $load['node'], $load['node'], $scopes[$load['source']]);
            $place = $this->registrationPlace($calls, $routeParser);

            $ordered[] = [
                'key' => $place === null ? null : serialize([$load['source'], $scope, $load['file'], $place]),
                'order' => [$load['source'], ...$order],
                'load' => [$load['file'], ['state' => $state, 'known' => true, 'proven' => $live && ! $state['unread'], 'once' => false, 'apiFile' => false]],
            ];
        }
        usort($ordered, fn (array $a, array $b): int => $a['order'] <=> $b['order']);

        $loads = [];
        foreach ($ordered as $entry) {
            if ($entry['key'] === null) {
                $loads[] = $entry['load'];
            } else {
                unset($loads[$entry['key']]);
                $loads[$entry['key']] = $entry['load'];
            }
        }

        return array_values($loads);
    }

    /**
     * What decides whether and in what order a bootstrap or provider file's loads run, by file
     * position. Dead: each method Laravel never runs, and a withRouting(using: ...) callback
     * beside then:, which ApplicationBuilder then discards. A method runs when it is boot() or
     * register(), map() in a class that extends the framework's RouteServiceProvider and never
     * calls $this->routes(), as loadRoutes() calls map() only then, or a method one of those
     * names in its own class, by a call or as a string, such as a callable, at any depth.
     * Functions: each function or closure, the order of its loads; a $this->routes() callback
     * runs after the method that sets it, so it counts as that method's, deferred.
     *
     * @return array{dead: list<array{int, int}>, functions: list<array{start: int, end: int, id: string, deferred: bool}>}
     */
    private function sourceScopes(string $source): array
    {
        $ast = $this->resolveNamesForMatching($this->parser->parseFile($source));

        $dead = [];
        foreach ($this->parser->findNodes($ast, Stmt\ClassLike::class) as $class) {
            if (! $class instanceof Stmt\ClassLike) {
                continue;
            }
            $live = ['boot' => true, 'register' => true];
            if ($class instanceof Stmt\Class_ && $this->extendsRouteServiceProvider($class) && ! in_array('routes', $this->namesCalledIn($class->getMethods()), true)) {
                $live['map'] = true;
            }
            do {
                $changed = false;
                foreach ($class->getMethods() as $method) {
                    if (! isset($live[$method->name->toLowerString()])) {
                        continue;
                    }
                    foreach ($this->namesCalledIn([$method]) as $name) {
                        if (! isset($live[$name])) {
                            $live[$name] = true;
                            $changed = true;
                        }
                    }
                }
            } while ($changed);

            foreach ($class->getMethods() as $method) {
                if (! isset($live[$method->name->toLowerString()])) {
                    $dead[] = [$method->getStartFilePos(), $method->getEndFilePos()];
                }
            }
        }

        $deferred = [];
        foreach ($this->parser->findNodes($ast, Expr\MethodCall::class) as $call) {
            if (! $call instanceof Expr\MethodCall || ! $call->name instanceof Identifier) {
                continue;
            }
            $name = $call->name->toLowerString();
            if ($name === 'withrouting') {
                // ApplicationBuilder::withRouting() takes $using first and $then ninth, and
                // replaces $using when $then is callable, which null is not
                $arguments = [];
                foreach ($call->args as $index => $arg) {
                    if ($arg instanceof Node\Arg) {
                        $arguments[$arg->name?->toLowerString() ?? [0 => 'using', 8 => 'then'][$index] ?? ''] = $arg->value;
                    }
                }
                $then = $arguments['then'] ?? null;
                if (isset($arguments['using']) && $then !== null
                    && ! ($then instanceof Expr\ConstFetch && $then->name->toLowerString() === 'null')) {
                    $dead[] = [$arguments['using']->getStartFilePos(), $arguments['using']->getEndFilePos()];
                }
            }
            $first = $call->args[0] ?? null;
            if ($name === 'routes' && $call->var instanceof Expr\Variable && $call->var->name === 'this'
                && $first instanceof Node\Arg && ($first->value instanceof Expr\Closure || $first->value instanceof Expr\ArrowFunction)) {
                $deferred[spl_object_id($first->value)] = true;
            }
        }

        $functions = [];
        foreach ($this->parser->findNodes($ast, Node\FunctionLike::class) as $node) {
            $functions[] = [
                'start' => $node->getStartFilePos(),
                'end' => $node->getEndFilePos(),
                'id' => $node->getStartFilePos().':'.$node->getEndFilePos(),
                'deferred' => isset($deferred[spl_object_id($node)]),
            ];
        }
        // A deferred callback belongs to the function around it
        foreach ($functions as $index => $function) {
            if ($function['deferred']) {
                $around = $this->innermostFunction($functions, $function['start'] - 1, $function['end'] + 1);
                $functions[$index]['id'] = $around['id'] ?? 'file';
            }
        }

        return ['dead' => $dead, 'functions' => $functions];
    }

    /**
     * The innermost function that spans the positions $start to $end.
     *
     * @param  list<array{start: int, end: int, id: string, deferred: bool}>  $functions
     * @return array{start: int, end: int, id: string, deferred: bool}|null
     */
    private function innermostFunction(array $functions, int $start, int $end): ?array
    {
        $innermost = null;
        foreach ($functions as $function) {
            if ($function['start'] <= $start && $end <= $function['end']
                && ($innermost === null || $function['end'] - $function['start'] < $innermost['end'] - $innermost['start'])) {
                $innermost = $function;
            }
        }

        return $innermost;
    }

    /**
     * Whether a class extends the framework's RouteServiceProvider, directly or through
     * application classes read from their files (see applicationParent()).
     */
    private function extendsRouteServiceProvider(Stmt\Class_ $class): bool
    {
        if ($class->extends === null) {
            return false;
        }
        $resolved = $class->extends->getAttribute('resolvedName');
        $parent = ltrim(($resolved instanceof Name ? $resolved : $class->extends)->toString(), '\\');

        for ($depth = 0; $depth < 5; $depth++) {
            if ($parent === 'Illuminate\\Foundation\\Support\\Providers\\RouteServiceProvider') {
                return true;
            }
            $next = $this->applicationParent($parent);
            if (! is_string($next)) {
                return false;
            }
            $parent = ltrim($next, '\\');
        }

        return false;
    }

    /**
     * The method names methods may call: those of their method and static calls, and their
     * strings, which a callable may name. Lowercased, as PHP matches method names.
     *
     * @param  array<Stmt\ClassMethod>  $methods
     * @return list<string>
     */
    private function namesCalledIn(array $methods): array
    {
        $names = [];
        foreach ($this->parser->findNodes($methods, Node::class) as $node) {
            if (($node instanceof Expr\MethodCall || $node instanceof Expr\NullsafeMethodCall || $node instanceof Expr\StaticCall)
                && $node->name instanceof Identifier) {
                $names[] = $node->name->toLowerString();
            } elseif ($node instanceof String_) {
                $names[] = strtolower($node->value);
            }
        }

        return $names;
    }

    /**
     * Whether a load runs, false inside anything dead (see sourceScopes()), the innermost
     * function around $anchor, its outermost group call or the load itself, whose loads run in
     * order, and the load's place in that order: a deferred callback's loads after the rest.
     *
     * @param  array{dead: list<array{int, int}>, functions: list<array{start: int, end: int, id: string, deferred: bool}>}  $scopes
     * @return array{bool, string, array{int, int}}
     */
    private function scopeOf(Node $anchor, Node $node, array $scopes): array
    {
        $position = $node->getStartFilePos();

        $live = true;
        foreach ($scopes['dead'] as [$start, $end]) {
            if ($start <= $position && $position <= $end) {
                $live = false;
            }
        }

        $function = $this->innermostFunction($scopes['functions'], $anchor->getStartFilePos(), $anchor->getEndFilePos());

        return [$live, $function['id'] ?? 'file', [($function['deferred'] ?? false) ? 1 : 0, $position]];
    }

    /**
     * The prefixes and domains these nested group calls give the routes they load, outermost
     * first, or null when one cannot be read.
     *
     * @param  list<Expr\MethodCall|Expr\StaticCall>  $calls
     */
    private function registrationPlace(array $calls, BootstrapRouteParser $routeParser): ?string
    {
        $place = [];
        foreach ($calls as $group) {
            // Within one chain a later prefix() or domain() replaces the one before it, as
            // RouteRegistrar::attribute() sets the attribute; nested groups add to it
            $chain = [];
            foreach ($routeParser->groupChain($group) as $link) {
                $name = $link->name instanceof Identifier ? $link->name->toLowerString() : null;
                if ($name === 'attribute' || $name === null) {
                    return null;
                }

                $values = [];
                if ($name === 'prefix' || $name === 'domain') {
                    $first = $link->args[0] ?? null;
                    $values = [$name => $first instanceof Node\Arg ? [BootstrapRouteParser::heldValue($first->value)] : [null]];
                } elseif ($name === 'group' && count($link->args) > 1) {
                    $first = $link->args[0];
                    if (! $first instanceof Node\Arg || ! BootstrapRouteParser::heldValue($first->value) instanceof Expr\Array_) {
                        return null;
                    }
                    foreach (['prefix', 'domain'] as $key) {
                        $values[$key] = $routeParser->groupAttributeEntries([$first], $key);
                    }
                }

                foreach ($values as $key => $entries) {
                    foreach ($entries as $entry) {
                        if (! $entry instanceof String_) {
                            return null;
                        }
                        // An empty prefix or domain gives the same URI as none
                        $value = trim($entry->value, '/');
                        if ($value === '') {
                            unset($chain[$key]);
                        } else {
                            $chain[$key] = $value;
                        }
                    }
                }
            }
            if ($chain !== []) {
                ksort($chain);
                $place[] = $chain;
            }
        }

        return serialize($place);
    }

    /**
     * Follow loads down require chains: each file a loaded route file loads gets that load merged
     * with the groups around the require (see loadThrough()). A file keeps at most
     * MAX_REGISTRATIONS distinct loads, so a require cycle or a file loaded many ways ends.
     *
     * @param  array<string, list<array{file: string, state: CsrfState, once: bool}>>  $includes  The files each route file loads
     * @param  array<string, array<string, RouteLoad>>  $fileLoads  Each file's loads, keyed as addLoad() keys them
     * @param  list<array{string, RouteLoad}>  $queue  Loads of files whose own loads are still to follow
     */
    private function propagateLoads(array $includes, array &$fileLoads, array $queue): void
    {
        while ($queue !== []) {
            [$path, $load] = array_pop($queue);
            foreach ($includes[$path] ?? [] as $include) {
                $child = $this->loadThrough($load, $include['state'], $include['once']);
                if ($child !== null && $this->addLoad($fileLoads, $include['file'], $child)) {
                    $queue[] = [$include['file'], $child];
                }
            }
        }
    }

    /**
     * Record a load of a file unless the file already has it, or has MAX_REGISTRATIONS loads. Its
     * middleware lists are kept sorted and without repeats, so two ways to the same load are one.
     *
     * @param  array<string, array<string, RouteLoad>>  $fileLoads
     * @param  RouteLoad  $load
     */
    private function addLoad(array &$fileLoads, string $file, array $load): bool
    {
        $state = $load['state'];
        $applied = array_values(array_unique($state['applied']));
        sort($applied);
        $names = array_values(array_unique(array_filter($state['excluded'], is_string(...))));
        sort($names);
        $load['state'] = [
            ...$state,
            'applied' => $applied,
            'excluded' => in_array(null, $state['excluded'], true) ? [...$names, null] : $names,
        ];

        $key = serialize($load);
        if (isset($fileLoads[$file][$key]) || count($fileLoads[$file] ?? []) >= self::MAX_REGISTRATIONS) {
            return false;
        }
        $fileLoads[$file][$key] = $load;

        return true;
    }

    /**
     * The load a route file's load gives a file it loads, with $state the groups around the
     * require: both merged, as Laravel merges a group's middleware into what it encloses. A
     * load stays an api file's while neither 'web' nor a CSRF class reaches it. From a file no
     * known load reaches, a require that excludes the CSRF middleware cannot take protection
     * away, so it passes nothing on: null.
     *
     * A load is proven while every load on its way runs and its middleware is read, and once
     * from the first require_once or include_once on its way.
     *
     * @param  RouteLoad  $load
     * @param  CsrfState  $state
     * @return RouteLoad|null
     */
    private function loadThrough(array $load, array $state, bool $once): ?array
    {
        if (! $load['known'] && $this->namesStripCsrf($state['excluded'])) {
            return null;
        }

        $merged = $this->mergeCsrfState($load['state'], $state);

        return [
            'state' => $merged,
            'known' => $load['known'],
            'proven' => $load['proven'] && ! $merged['unread'],
            'once' => $load['once'] || $once,
            'apiFile' => $load['apiFile'] && ! $this->appliesCsrf($merged),
        ];
    }

    /**
     * Whether a load leaves a route unprotected, with $route the route's own state in its file,
     * merged with the load's as Laravel merges a group's middleware into every route inside it:
     * null when it does not, and otherwise the reason reportUnprotectedRoutes() reports.
     *
     * A load 'web' or a CSRF class reaches is a web load, unless its own exclusions remove the
     * check without stripping the web group's, as excluding the exact class it applies does:
     * such a load is judged as a plain one. On a web load the route is reported when its merged
     * exclusions remove every check, as 'stripped' when the load itself excludes CSRF and as
     * 'excluded' when only the route does. In an api file, or where 'api' reaches the route
     * through the load, its own chain or a group around it, only a route that applies 'web' or a
     * CSRF class itself is judged, by the exclusions merged into it, as 'api' routes run
     * without CSRF cookies. Otherwise a route 'web' never reaches is 'missing', and one whose
     * check its exclusions remove is 'stripped'.
     *
     * @param  RouteLoad  $load
     * @param  CsrfState  $route
     * @return 'missing'|'stripped'|'excluded'|null
     */
    private function unprotectedBy(array $load, array $route): ?string
    {
        $state = $this->mergeCsrfState($load['state'], $route);
        $runs = $this->csrfRuns($state['group'], $state['applied'], $state['excluded']);

        ['group' => $loadGroup, 'applied' => $loadApplied, 'excluded' => $loadExcluded] = $load['state'];
        $strips = $this->namesStripCsrf($loadExcluded);
        if ($this->appliesCsrf($load['state']) && ($strips || $this->csrfRuns($loadGroup, $loadApplied, $loadExcluded))) {
            return match (true) {
                $runs => null,
                $strips => 'stripped',
                default => 'excluded',
            };
        }

        // Only what the route applies itself counts from here: the load applies nothing, or what
        // it applies its own exclusions remove
        $reached = $this->appliesCsrf($route);
        if ($load['apiFile'] || $this->apiReaches($state)) {
            return $reached && ! $runs ? 'stripped' : null;
        }

        return match (true) {
            ! $reached => 'missing',
            $runs => null,
            default => 'stripped',
        };
    }

    /**
     * Whether 'web' or a CSRF class is applied at all, so a load is a web load even when the
     * check is then excluded.
     *
     * @param  CsrfState  $state
     */
    private function appliesCsrf(array $state): bool
    {
        return $state['group'] || $state['applied'] !== [];
    }

    /**
     * Report each unprotected route once per line. The reason picks the message: 'missing' when
     * 'web' never reaches the route, 'stripped' when a load of its file, or the route's own chain
     * outside a covered file, excludes the CSRF middleware from it, and 'excluded' when a route in
     * a covered file, such as routes/web.php, excludes it itself.
     *
     * @param  list<array{line: int, method: string, reason: 'missing'|'stripped'|'excluded'}>  $routes
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
                message: match ($route['reason']) {
                    'missing' => sprintf('%s route in custom route file missing CSRF protection - no "web" middleware detected', $route['method']),
                    'stripped' => sprintf('%s route in custom route file missing CSRF protection - the CSRF middleware is excluded from it', $route['method']),
                    'excluded' => sprintf('%s route excludes the CSRF middleware through withoutMiddleware() or excluded_middleware', $route['method']),
                },
                filePath: $file,
                lineNumber: $line,
                severity: Severity::High,
                recommendation: $route['reason'] === 'missing'
                    ? 'Apply the web middleware group to this route or move it into a route group that includes the web middleware, which provides CSRF protection.'
                    : 'Stop excluding the web group or the CSRF middleware from this route through withoutMiddleware() or excluded_middleware. A route that cannot send a token, such as a webhook, belongs in the CSRF middleware exceptions instead, where the exemption is reviewed with the others.',
                metadata: [
                    'method' => $route['method'],
                    'file' => basename($file),
                    'line' => $line,
                    'severity_reason' => $route['reason'] === 'excluded'
                        ? 'High severity - excluding the CSRF middleware removes the protection the web group gives this route'
                        : 'High severity for custom route files - web.php is automatically protected',
                ]
            );
        }
    }

    /**
     * Walk a route file once and resolve what reaches each route: its state-changing routes,
     * each with the CSRF state of its chain and every group around it, and the files it loads
     * by a require or a group() path argument, each with the CSRF state of the groups around
     * the load, which the loaded file's routes merge with what loads this file, and whether it
     * is a require_once or include_once.
     *
     * @return array{routes: list<array{line: int, method: string, states: list<CsrfState>}>, includes: list<array{file: string, state: CsrfState, once: bool}>}
     */
    private function walkRouteFile(string $file, BootstrapRouteParser $routeParser): array
    {
        // A file that does not parse yields no nodes; the report's parse-failure notice covers it.
        // Names are resolved here, not left to whichever analyzer last resolved the cached AST,
        // so an aliased CSRF import reads as its class
        $ast = $this->resolveNamesForMatching($this->parser->parseFile($file));

        // The routes each router group() call loads, with a variable holding route paths read
        // as those paths
        $resolved = $routeParser->routerGroupRoutes($ast);

        // A closure handed to a group through a variable is walked before the group call that
        // makes its first parameter the router, so the walk runs again knowing every such
        // callback until it finds no new one
        $callbacks = [];
        do {
            /** @var RouteWalk $walk */
            $walk = ['routes' => [], 'groups' => [], 'variables' => [], 'resolved' => $resolved, 'includes' => [], 'paths' => [], 'routers' => [], 'callbacks' => $callbacks, 'late' => false];
            foreach ($ast as $node) {
                $this->walkRouteNode($node, [], 0, $walk, $routeParser);
            }
            $callbacks += array_fill_keys(array_keys($walk['groups']), true);
        } while ($walk['late']);
        $groups = $walk['groups'];

        $routes = [];
        foreach ($walk['routes'] as $route) {
            $states = [];
            foreach ($route['states'] as $state) {
                $states = [...$states, ...$this->statesReaching($route['closures'], $groups, $state)];
            }
            $routes[] = ['line' => $route['line'], 'method' => $route['method'], 'states' => $states];
        }

        // A file loaded once per registration of the group around it gets one entry per registration
        $includes = [];
        foreach ($walk['includes'] as $include) {
            $path = $routeParser->includedFile($include['include'], dirname($file));
            if ($path === null) {
                continue;
            }
            // A require_once of a file already required registers nothing
            $once = in_array($include['include']->type, [Expr\Include_::TYPE_INCLUDE_ONCE, Expr\Include_::TYPE_REQUIRE_ONCE], true);
            foreach ($this->statesReaching($include['closures'], $groups, self::NO_CSRF) as $state) {
                $includes[] = ['file' => $path, 'state' => $state, 'once' => $once];
            }
        }
        foreach ($walk['paths'] as $load) {
            $path = $routeParser->groupRouteFile($load['path'], dirname($file));
            if ($path === null) {
                continue;
            }
            foreach ($this->statesReaching($load['closures'], $groups, $load['state']) as $state) {
                $includes[] = ['file' => $path, 'state' => $state, 'once' => false];
            }
        }

        return ['routes' => $routes, 'includes' => $includes];
    }

    /**
     * The CSRF states that reach a node, one per way Laravel registers it: its own chain's state
     * merged with that of each group around it, as Laravel merges a group's middleware and
     * excluded middleware into every route inside it. The innermost group callback around the
     * node decides: each group() call that runs it is one registration, reached in turn through
     * the closures around that call, which differ from the callback's own when it is passed
     * through a variable. csrfRuns() then judges each state.
     *
     * @param  list<int>  $closures  The closures enclosing the node, outermost first
     * @param  array<int, non-empty-list<array{state: CsrfState, closures: list<int>}>>  $groups
     * @param  CsrfState  $state  The node's own chain's state
     * @param  array<int, true>  $seen  Callbacks already on this path, which a callback that runs
     *                                  itself would otherwise revisit forever
     * @return non-empty-list<CsrfState>
     */
    private function statesReaching(array $closures, array $groups, array $state, array $seen = []): array
    {
        for ($index = count($closures) - 1; $index >= 0; $index--) {
            $closure = $closures[$index];
            if (! isset($groups[$closure]) || isset($seen[$closure])) {
                continue;
            }

            // The walk stops once it has the cap's worth of paths, so a file that nests reused
            // callbacks deeply stays cheap; the paths after it are not followed
            $states = [];
            foreach ($groups[$closure] as $registration) {
                $reached = $this->statesReaching($registration['closures'], $groups, $this->mergeCsrfState($state, $registration['state']), $seen + [$closure => true]);
                $states = [...$states, ...$reached];
                if (count($states) >= self::MAX_REGISTRATIONS) {
                    return array_slice($states, 0, self::MAX_REGISTRATIONS);
                }
            }

            return $states;
        }

        return [$state];
    }

    /**
     * Two levels' middleware together, as Laravel merges a group's into what it encloses.
     *
     * @param  CsrfState  $a
     * @param  CsrfState  $b
     * @return CsrfState
     */
    private function mergeCsrfState(array $a, array $b): array
    {
        return [
            'group' => $a['group'] || $b['group'],
            'applied' => [...$a['applied'], ...$b['applied']],
            'excluded' => [...$a['excluded'], ...$b['excluded']],
            'api' => $a['api'] || $b['api'],
            'unread' => $a['unread'] || $b['unread'],
        ];
    }

    /**
     * Whether the 'api' group reaches a registration: applied by its chain or a group around
     * it, and not excluded again, as excluding 'api' removes the group's members.
     *
     * @param  CsrfState  $state
     */
    private function apiReaches(array $state): bool
    {
        return $state['api'] && ! in_array('api', $state['excluded'], true);
    }

    /**
     * Whether a CSRF check still runs on a route: the Kernel's global one (see $globalCsrf), the
     * web group's, when 'web' reaches it and the exclusions do not remove every CSRF entry it
     * holds, or a CSRF class applied directly that no exclusion names, by itself or a class it
     * extends. Excluding 'web' excludes the group's members, as Router::resolveMiddleware()
     * resolves it, so it also removes a class applied directly that is or extends the group's
     * CSRF middleware.
     *
     * @param  list<string>  $applied
     * @param  list<string|null>  $excluded
     */
    private function csrfRuns(bool $group, array $applied, array $excluded): bool
    {
        if ($this->globalCsrf || ($group && ! $this->namesStripCsrf($excluded))) {
            return true;
        }

        $names = array_map(fn (string $name): string => ltrim($name, '\\'), array_filter($excluded, is_string(...)));
        if (in_array('web', $names, true)) {
            // With the group not settled, any CSRF class is assumed to be in it, as namesStripCsrf()
            // assumes before Laravel 13; on 13 every CSRF class extends PreventRequestForgery anyway
            if ($this->webGroupCsrf === null) {
                return false;
            }
            $names = [...$names, ...$this->webGroupCsrf];
        }
        foreach ($applied as $class) {
            if (array_intersect($this->csrfAncestors($class), $names) === []) {
                return true;
            }
        }

        return false;
    }

    /**
     * Walk one node of a route file, recording into $walk its route registrations, the groups
     * that open a closure, closures assigned to variables, require/include expressions, group()
     * path arguments and the variables that hold the router, each route, include and path with
     * the closures enclosing it.
     *
     * Each route and group carries the CSRF state of its chain (see chainCsrfState()): 'web' and
     * the CSRF classes its ->middleware(...) calls and 'middleware' attribute or action key
     * apply, and what its ->withoutMiddleware(...) calls and 'excluded_middleware' attribute or
     * action key exclude. A route merges the state of every group around it, and csrfRuns()
     * judges whether a check still runs. Method names are matched case-insensitively, as PHP calls them.
     *
     * Each function scope keeps the variables that hold the router (see openScope()), and an
     * assignment updates its own scope's set as the walk reaches it, in source order.
     *
     * @param  list<int>  $closures  spl_object_id()s of the closures enclosing $node, outermost first
     * @param  int  $scope  spl_object_id() of the function enclosing $node, or 0 for the file
     * @param  RouteWalk  $walk
     */
    private function walkRouteNode(Node $node, array $closures, int $scope, array &$walk, BootstrapRouteParser $routeParser): void
    {
        if ($node instanceof Expr\MethodCall || $node instanceof Expr\StaticCall || $node instanceof Expr\NullsafeMethodCall) {
            // A nullsafe call on a route or a registrar runs as a plain one
            $this->walkCallChain($node instanceof Expr\StaticCall ? $node : $routeParser->nullsafeStandIn($node), $closures, $scope, $walk, $routeParser);

            return;
        }

        if ($node instanceof Node\FunctionLike) {
            $scope = $this->openScope($node, $scope, $walk);
        }

        if ($node instanceof Expr\Closure || $node instanceof Expr\ArrowFunction) {
            $closures[] = spl_object_id($node);
        } elseif ($node instanceof Expr\Include_) {
            $walk['includes'][] = ['include' => $node, 'closures' => $closures];
        } elseif ($node instanceof Expr\Assign && $node->var instanceof Expr\Variable && is_string($node->var->name)) {
            if ($node->expr instanceof Expr\Closure || $node->expr instanceof Expr\ArrowFunction) {
                $walk['variables'][$node->var->name] = spl_object_id($node->expr);
            }

            if ($this->isRouterExpr($node->expr, $scope, $walk)) {
                $walk['routers'][$scope][$node->var->name] = true;
            } else {
                unset($walk['routers'][$scope][$node->var->name]);
            }
        }

        foreach ($node->getSubNodeNames() as $name) {
            $sub = $node->$name;
            foreach (is_array($sub) ? $sub : [$sub] as $child) {
                if ($child instanceof Node) {
                    $this->walkRouteNode($child, $closures, $scope, $walk, $routeParser);
                }
            }
        }
    }

    /**
     * Open the scope of a function the walk enters, recording the variables that hold the router
     * in it: parameters typed Router or Registrar, the first parameter of a group callback, which
     * Laravel calls with the router, and router variables a closure captures through use(). An
     * arrow function sees its parent scope's variables, as PHP binds them by value.
     *
     * @param  RouteWalk  $walk
     */
    private function openScope(Node\FunctionLike $function, int $parent, array &$walk): int
    {
        $id = spl_object_id($function);
        $parentRouters = $walk['routers'][$parent] ?? [];

        $routers = $function instanceof Expr\ArrowFunction ? $parentRouters : [];
        if ($function instanceof Expr\Closure) {
            foreach ($function->uses as $use) {
                if (is_string($use->var->name) && isset($parentRouters[$use->var->name])) {
                    $routers[$use->var->name] = true;
                }
            }
        }

        foreach ($function->getParams() as $index => $param) {
            if ($param->var instanceof Expr\Variable && is_string($param->var->name)
                && ($this->isRouterType($param->type) || ($index === 0 && (isset($walk['groups'][$id]) || isset($walk['callbacks'][$id]))))) {
                $routers[$param->var->name] = true;
            }
        }

        $walk['routers'][$id] = $routers;

        return $id;
    }

    /**
     * Whether a parameter type is the router: Illuminate\Routing\Router or the
     * Illuminate\Contracts\Routing\Registrar contract, nullable or not.
     */
    private function isRouterType(?Node $type): bool
    {
        if ($type instanceof Node\NullableType) {
            $type = $type->type;
        }

        if (! $type instanceof Name) {
            return false;
        }

        $resolved = $type->getAttribute('resolvedName');

        return in_array(($resolved instanceof Name ? $resolved : $type)->toString(), self::ROUTER_CLASSES, true);
    }

    /**
     * Whether an expression is the router: a variable named $router, which Laravel defines in
     * every route file it loads, or a variable that holds it in this scope; $this->router, the
     * RouteFileRegistrar a route file runs in; app() or resolve() given 'router', Router or
     * Registrar; and app()->make() given the same.
     *
     * @param  RouteWalk  $walk
     */
    private function isRouterExpr(Node $expr, int $scope, array $walk): bool
    {
        if ($expr instanceof Expr\Variable) {
            return is_string($expr->name) && ($expr->name === 'router' || isset($walk['routers'][$scope][$expr->name]));
        }

        if ($expr instanceof Expr\PropertyFetch) {
            return $expr->var instanceof Expr\Variable && $expr->var->name === 'this'
                && $expr->name instanceof Identifier && $expr->name->toLowerString() === 'router';
        }

        if ($expr instanceof Expr\FuncCall && $this->isFunctionNamed($expr, ['app', 'resolve'])) {
            return $this->namesRouter($expr);
        }

        return $expr instanceof Expr\MethodCall && $this->isContainerMake($expr);
    }

    /**
     * Whether a call is app()->make() given 'router', Router or Registrar.
     */
    private function isContainerMake(Expr\MethodCall $call): bool
    {
        return $call->name instanceof Identifier && $call->name->toLowerString() === 'make'
            && $call->var instanceof Expr\FuncCall && $this->isFunctionNamed($call->var, ['app']) && $call->var->args === []
            && $this->namesRouter($call);
    }

    /**
     * Whether a call names an unqualified or fully qualified function in $names, case-insensitively.
     *
     * @param  list<string>  $names
     */
    private function isFunctionNamed(Expr\FuncCall $call, array $names): bool
    {
        return $call->name instanceof Name && in_array($call->name->toLowerString(), $names, true);
    }

    /**
     * Whether a container call's first argument is the router's binding: 'router', Router::class
     * or Registrar::class.
     */
    private function namesRouter(Expr\FuncCall|Expr\MethodCall $call): bool
    {
        $first = $call->args[0] ?? null;
        if (! $first instanceof Node\Arg) {
            return false;
        }

        $name = $this->middlewareName($first->value);

        return $name !== null && in_array(ltrim($name, '\\'), ['router', ...self::ROUTER_CLASSES], true);
    }

    /**
     * Walk a method-call chain as one unit: read it as a route registration when its root is
     * the router (see isRouterChainRoot()), or when a group in it is made on a variable holding
     * a registrar, which the route parser then reads starting at the calls that built it (see
     * BootstrapRouteParser::groupChain()); the chain is read as the parser reads it. Then walk its root and each call's arguments, which may hold
     * further routes.
     *
     * @param  list<int>  $closures
     * @param  RouteWalk  $walk
     */
    private function walkCallChain(Expr\MethodCall|Expr\StaticCall $call, array $closures, int $scope, array &$walk, BootstrapRouteParser $routeParser): void
    {
        [$chain, $base] = $this->unwindChain($call);
        $registration = $routeParser->groupChain($call);

        // app()->make('router') unwinds with make() as the chain's first call
        $start = $registration[0] instanceof Expr\MethodCall && $this->isContainerMake($registration[0]) ? 1 : 0;
        // A chain the route parser continued through a registrar variable starts elsewhere
        $continued = $registration[0] !== $routeParser->attributeStandIn($chain[0]);
        if ($start === 1 || $continued || $this->isRouterChainRoot($base, $scope, $walk)) {
            $this->readRouteChain(array_slice($registration, $start), $closures, $walk, $routeParser);
        }

        $children = [$base];
        foreach ($chain as $link) {
            $children = [...$children, $link->name, ...$link->args];
        }

        foreach ($children as $child) {
            $this->walkRouteNode($child, $closures, $scope, $walk, $routeParser);
        }
    }

    /**
     * Whether a chain's root is the router: the Route facade, by any alias it is imported
     * under, or an expression isRouterExpr() accepts.
     *
     * @param  RouteWalk  $walk
     */
    private function isRouterChainRoot(Node $base, int $scope, array $walk): bool
    {
        if ($base instanceof Name) {
            $resolved = $base->getAttribute('resolvedName');

            return $base->getLast() === 'Route'
                || ($resolved instanceof Name && $resolved->toString() === 'Illuminate\Support\Facades\Route');
        }

        return $this->isRouterExpr($base, $scope, $walk);
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
        // Calls after resource() and the other resource registrations configure their pending
        // registration, which reads them by its own rules (see resourceState()); calls up to
        // it read as on any route
        $resourceAt = null;
        foreach ($chain as $index => $link) {
            if ($link->name instanceof Identifier && isset(self::RESOURCE_REGISTRATIONS[$link->name->toLowerString()])) {
                $resourceAt = $index;

                break;
            }
        }

        $calls = $this->callsByName($resourceAt === null ? $chain : array_slice($chain, 0, $resourceAt + 1));
        $state = $resourceAt === null ? $this->chainCsrfState($chain, $routeParser) : self::NO_CSRF;

        if (isset($calls['group'])) {
            $args = $calls['group'][0]->args;

            // Each callback the group loads, including each item of a list, opens its closure; a
            // variable callback opens the closure assigned to it last before this call, as PHP reads
            // it. Any other entry is a route file path Router::loadRoutes() requires inside the
            // group, read from a variable holding it as the route parser reads it
            foreach ($walk['resolved'][spl_object_id($calls['group'][0])] ?? $routeParser->groupRoutes($args) as $callback) {
                $direct = $callback instanceof Expr\Closure || $callback instanceof Expr\ArrowFunction;
                $closureId = match (true) {
                    $direct => spl_object_id($callback),
                    $callback instanceof Expr\Variable && is_string($callback->name) => $walk['variables'][$callback->name] ?? null,
                    default => null,
                };
                if ($closureId === null) {
                    $walk['paths'][] = ['path' => $callback, 'state' => $state, 'closures' => $closures];

                    continue;
                }

                // The variable's closure was walked before its first parameter was known as the router
                $walk['late'] = $walk['late'] || (! $direct && ! isset($walk['callbacks'][$closureId]));
                // Each group() call that runs the callback registers its routes once more, under
                // that call's own chain and the closures around it, wherever the callback was written
                $walk['groups'][$closureId][] = ['state' => $state, 'closures' => $closures];
            }

            return;
        }

        $method = $this->stateChangingRouteMethod($calls);
        $states = [$state];
        if ($resourceAt !== null) {
            [$writes, $states] = $this->resourceState(
                $chain[$resourceAt],
                array_slice($chain, 0, $resourceAt),
                array_slice($chain, $resourceAt + 1),
                $routeParser,
            );
            $method = $writes ? $this->resourceRegistration($chain[$resourceAt])[0] : null;
        }

        $registration = $this->registeringCall($chain);
        if ($method !== null && $registration !== null) {
            // A statement on a variable holding the route, such as $route->middleware('web'), is
            // read through the calls that built it (see BootstrapRouteParser::groupChain()), so
            // it reaches the same registering call with every call made on the route so far,
            // as Route::middleware() and withoutMiddleware() change the route itself
            $walk['routes'][spl_object_id($registration)] = [
                // The statement that registers the route, not the one that built a registrar
                // held in a variable it is made on
                'line' => $registration->getStartLine(),
                'method' => $method,
                'states' => $states,
                'closures' => $closures,
            ];
        } elseif ($registration !== null) {
            // A later statement on the variable, such as $photos->only(['index']), left the
            // registration no write
            unset($walk['routes'][spl_object_id($registration)]);
        }
    }

    /**
     * The call in a route chain that registers the route or opens the group: the first route
     * verb, resource registration or group() call, so a chain made on a call the router hands
     * back, such as Route::getFacadeRoot() or a router macro, registers at its verb. A chain
     * with none registers at the first call that is neither a registrar attribute nor a
     * where*() constraint. Null when every call only sets attributes.
     *
     * @param  list<Expr\MethodCall|Expr\StaticCall>  $chain  The chain's calls, root first
     */
    private function registeringCall(array $chain): Expr\MethodCall|Expr\StaticCall|null
    {
        foreach ($chain as $link) {
            $name = $link->name instanceof Identifier ? $link->name->toLowerString() : null;
            if (in_array($name, self::ROUTE_REGISTRATIONS, true) || isset(self::RESOURCE_REGISTRATIONS[$name ?? ''])) {
                return $link;
            }
        }

        foreach ($chain as $link) {
            $name = $link->name instanceof Identifier ? $link->name->toLowerString() : null;
            if (! (in_array($name, self::REGISTRAR_ATTRIBUTES, true) || ($name !== null && str_starts_with($name, 'where')))) {
                return $link;
            }
        }

        return null;
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
     * The CSRF state of a chain: whether it applies 'web', the CSRF classes it applies, and
     * what it excludes, through ->middleware(...) and ->withoutMiddleware(...) and the
     * 'middleware' and 'excluded_middleware' keys of a group's attribute array or of the
     * action array the route is registered with, which Route reads as its own middleware.
     *
     * Calls before the route or group is registered set RouteRegistrar attributes, where each
     * middleware() call replaces the last; after it, a route's middleware() calls add up.
     * RouteRegistrar::compileAction() merges the action array over those attributes, so a key
     * the action names replaces the registrar's middleware or exclusions, even with an empty
     * list (see routeActionMiddleware()).
     *
     * @param  list<Expr\MethodCall|Expr\StaticCall>  $chain  The chain's calls, root first
     * @return CsrfState
     */
    private function chainCsrfState(array $chain, BootstrapRouteParser $routeParser): array
    {
        $applied = [];
        $registrarApplied = [];
        $excluded = [];
        $registrarExcluded = [];
        $action = self::NO_ACTION_MIDDLEWARE;
        $registered = false;
        $registration = $this->registeringCall($chain);
        foreach ($chain as $link) {
            $name = $link->name instanceof Identifier ? $link->name->toLowerString() : null;
            $registers = $link === $registration;
            $registered = $registered || $registers;

            if ($registers) {
                $action = $this->routeActionMiddleware($link, $routeParser);
            } elseif ($name === 'middleware') {
                $names = $this->entryNames(BootstrapRouteParser::heldEntries($routeParser->middlewareEntries($link)));
                if ($registered) {
                    $applied = [...$applied, ...$names];
                } else {
                    $registrarApplied = $names;
                }
            } elseif ($name === 'withoutmiddleware') {
                // Route::withoutMiddleware() and the registrar take one argument and wrap it
                $names = $this->entryNames(BootstrapRouteParser::heldEntries($this->wrappedFirstArgument($link)));
                if ($registered) {
                    $excluded = [...$excluded, ...$names];
                } else {
                    $registrarExcluded = [...$registrarExcluded, ...$names];
                }
            }
        }

        if ($action['dropsRegistrar']) {
            $registrarApplied = [];
            $registrarExcluded = [];
        }
        if ($action['middleware'] !== null) {
            // An entry that cannot be read keeps the registrar's middleware alongside the action's,
            // so an unread name is not taken to drop 'web'
            $registrarApplied = in_array(null, $action['middleware'], true)
                ? [...$registrarApplied, ...$action['middleware']]
                : $action['middleware'];
        }
        if ($action['excluded'] !== null) {
            // An unread exclusion removes nothing csrfRuns() can name, so replacing still holds
            $registrarExcluded = $action['excluded'];
        }

        $calls = $this->callsByName($chain);
        $args = isset($calls['group']) ? $calls['group'][0]->args : [];

        return $this->csrfState(
            [...$registrarApplied, ...$applied, ...$this->entryNames($routeParser->groupAttributeEntries($args, 'middleware'))],
            [...$registrarExcluded, ...$excluded, ...$this->entryNames($routeParser->groupAttributeEntries($args, 'excluded_middleware'))],
        );
    }

    /**
     * The middleware a route's action array names under 'middleware' and 'excluded_middleware',
     * each null when the action has no such key, as Laravel reads the action.
     *
     * An action Reflector::isCallable() accepts by its syntax, any item at index 0 and a string
     * at index 1, is reduced to its controller by RouteAction::parse(), so it names none. When it
     * also has string keys it is not a list, so RouteRegistrar::compileAction() merges it over
     * the registrar's attributes instead of converting it first, and RouteAction::parse() drops
     * those attributes too ('dropsRegistrar'). An action that is not an array literal, or has a
     * key or an unpacked item that cannot be read, names none.
     *
     * @return ActionMiddleware
     */
    private function routeActionMiddleware(Expr\MethodCall|Expr\StaticCall $call, BootstrapRouteParser $routeParser): array
    {
        $action = $this->routeActionArgument($call);
        $action = $action === null ? null : BootstrapRouteParser::heldValue($action);
        if (! $action instanceof Expr\Array_) {
            return self::NO_ACTION_MIDDLEWARE;
        }

        $indexed = [];
        $keys = [];
        foreach ($action->items as $item) {
            if (! $item instanceof ArrayItem || $item->unpack) {
                return self::NO_ACTION_MIDDLEWARE;
            }
            if ($item->key === null) {
                $indexed[] = $item->value;
            } elseif ($item->key instanceof String_) {
                $keys[$item->key->value] = true;
            } else {
                return self::NO_ACTION_MIDDLEWARE;
            }
        }

        if (isset($indexed[0], $indexed[1]) && $indexed[1] instanceof String_) {
            return [...self::NO_ACTION_MIDDLEWARE, 'dropsRegistrar' => $keys !== []];
        }

        $args = [new Node\Arg($action)];

        return [
            'middleware' => isset($keys['middleware']) ? $this->entryNames($routeParser->groupAttributeEntries($args, 'middleware')) : null,
            'excluded' => isset($keys['excluded_middleware']) ? $this->entryNames($routeParser->groupAttributeEntries($args, 'excluded_middleware')) : null,
            'dropsRegistrar' => false,
        ];
    }

    /**
     * The action a route verb call registers its route with, or null for any other call: the
     * argument named action:, otherwise the second positional argument of get(), post(), put(),
     * patch(), delete(), options() and any(), or the third of match().
     */
    private function routeActionArgument(Expr\MethodCall|Expr\StaticCall $call): ?Expr
    {
        $name = $call->name instanceof Identifier ? $call->name->toLowerString() : null;
        $position = match (true) {
            $name === 'match' => 2,
            in_array($name, ['get', 'post', 'put', 'patch', 'delete', 'options', 'any'], true) => 1,
            default => null,
        };

        return $position === null ? null : $this->callArgument($call, $position, 'action');
    }

    /**
     * The CSRF state of a middleware list and an excluded list: whether the list names 'web',
     * the CSRF classes it applies itself, what is excluded, and whether the list names 'api'.
     *
     * @param  list<string|null>  $middleware
     * @param  list<string|null>  $excluded
     * @return CsrfState
     */
    private function csrfState(array $middleware, array $excluded): array
    {
        return [
            'group' => in_array('web', $middleware, true),
            'applied' => array_values(array_filter($middleware, fn (?string $name): bool => $name !== null && $this->csrfMiddlewareIn($name) !== null)),
            'excluded' => $excluded,
            'api' => in_array('api', $middleware, true),
            'unread' => in_array(null, $middleware, true) || in_array(null, $excluded, true),
        ];
    }

    /**
     * The CSRF state the groups a route file is loaded through, outermost first, hand it,
     * merged as chainCsrfState() reads the chain the route parser reads for each (see
     * BootstrapRouteParser::groupChain()).
     *
     * @param  non-empty-list<Expr\MethodCall|Expr\StaticCall>  $groups
     * @return CsrfState
     */
    private function groupsCsrfState(array $groups, BootstrapRouteParser $routeParser): array
    {
        $state = self::NO_CSRF;
        foreach ($groups as $group) {
            $chain = $routeParser->groupChain($group);
            // app()->make('router') unwinds with make() as the chain's first call
            $start = $chain[0] instanceof Expr\MethodCall && $this->isContainerMake($chain[0]) ? 1 : 0;
            $state = $this->mergeCsrfState($state, $this->chainCsrfState(array_slice($chain, $start), $routeParser));
        }

        return $state;
    }

    /**
     * The method a route chain registers when it accepts a request CSRF checks, or null:
     * post, put, patch, delete and any, and match() listing such a verb in its first argument
     * or the one named methods:. resource() is judged by resourceState().
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
            $first = $this->callArgument($calls['match'][0], 0, 'methods');
            $methods = $first !== null
                ? $this->entryNames($this->wrapped($first))
                : [];
            $methods = array_map(strtoupper(...), array_filter($methods, is_string(...)));

            return array_diff($methods, ['GET', 'HEAD', 'OPTIONS']) !== [] ? 'MATCH' : null;
        }

        return null;
    }

    /**
     * What a resource or singleton registration applies, as Laravel's pending registrations and
     * ResourceRegistrar read it: whether it keeps any write method, and one CSRF state per kept
     * write, each judged on its own.
     *
     * A resource writes through store, update and destroy, and a singleton through update, plus
     * store and destroy when creatable or destroy when destroyable. apiResource() and
     * apiSingleton() narrow 'only' to a list that keeps every write, so they read as resource()
     * and singleton(). The plural forms register each entry of a literal array with the same
     * options and return nothing to chain; any other first argument is skipped.
     *
     * The options array sets only, except, middleware, excluded_middleware, creatable and
     * destroyable. Calls before the registration, such as Route::middleware('web')->resource(),
     * build RouteRegistrar attributes that take the place of the same options: the last
     * middleware() call, read as a route's, and every withoutMiddleware() first argument. The
     * calls chained after it then change those options in order, as the
     * pending registration does: only(), except() and middleware() replace theirs, and
     * withoutMiddleware() adds to excluded_middleware. middlewareFor() gives the listed methods
     * the middleware set so far plus its own, and a later middleware() adds to those too;
     * withoutMiddlewareFor() replaces the listed methods' own exclusions, which add to
     * excluded_middleware. middleware() and withoutMiddleware() wrap their first argument and
     * ignore any others; only() and except() take a list or every argument, as a route's
     * middleware() does. A method list that cannot be read is skipped by middlewareFor(), so it
     * protects nothing, and applies to every method in withoutMiddlewareFor().
     *
     * @param  list<Expr\MethodCall|Expr\StaticCall>  $registrar  The calls before the registration
     * @param  list<Expr\MethodCall|Expr\StaticCall>  $pending  The calls chained after the registration
     * @return array{bool, non-empty-list<CsrfState>}
     */
    private function resourceState(Expr\MethodCall|Expr\StaticCall $resource, array $registrar, array $pending, BootstrapRouteParser $routeParser): array
    {
        [$label, $plural] = $this->resourceRegistration($resource);

        if ($plural) {
            $registered = $resource->args[0] ?? null;
            if (! $registered instanceof Node\Arg || ! $registered->value instanceof Expr\Array_ || $registered->value->items === []) {
                return [false, [self::NO_CSRF]];
            }
        }

        $optionsArg = $resource->args[$plural ? 1 : 2] ?? null;
        $options = $optionsArg instanceof Node\Arg && $optionsArg->value instanceof Expr\Array_ ? $optionsArg->value : null;

        $filters = ['only' => $this->resourceOption($options, 'only'), 'except' => $this->resourceOption($options, 'except')];
        $creatable = $this->resourceOption($options, 'creatable') !== null;
        $destroyable = $this->resourceOption($options, 'destroyable') !== null;
        $middleware = $this->entryNames($this->resourceOption($options, 'middleware') ?? []);
        $excluded = $this->entryNames($this->resourceOption($options, 'excluded_middleware') ?? []);

        $attributes = $this->callsByName($registrar);
        if (isset($attributes['middleware'])) {
            $middleware = $this->entryNames($routeParser->middlewareEntries($attributes['middleware'][count($attributes['middleware']) - 1]));
        }
        if (isset($attributes['withoutmiddleware'])) {
            $excluded = [];
            foreach ($attributes['withoutmiddleware'] as $link) {
                $excluded = [...$excluded, ...$this->entryNames($this->wrappedFirstArgument($link))];
            }
        }

        $middlewareFor = [];
        $excludedFor = [];

        foreach ($pending as $link) {
            $name = $link->name instanceof Identifier ? $link->name->toLowerString() : null;
            match ($name) {
                'only', 'except' => $filters[$name] = $routeParser->middlewareEntries($link),
                'creatable' => $creatable = true,
                'destroyable' => $destroyable = true,
                default => null,
            };

            if ($name === 'middleware') {
                $middleware = $this->entryNames($this->wrappedFirstArgument($link));
                foreach ($middlewareFor as $method => $names) {
                    $middlewareFor[$method] = [...$names, ...$middleware];
                }
            } elseif ($name === 'withoutmiddleware') {
                $excluded = [...$excluded, ...$this->entryNames($this->wrappedFirstArgument($link))];
            } elseif ($name === 'middlewarefor' || $name === 'withoutmiddlewarefor') {
                $methods = $this->entryNames($this->wrappedFirstArgument($link));
                $second = $link->args[1] ?? null;
                $names = $second instanceof Node\Arg ? $this->entryNames($this->wrapped($second->value)) : [];

                foreach ($methods as $method) {
                    if ($name === 'middlewarefor') {
                        if ($method !== null) {
                            $middlewareFor[$method] = [...$middleware, ...$names];
                        }
                    } else {
                        $excludedFor[$method ?? '*'] = $names;
                    }
                }
            }
        }

        $writes = match (true) {
            $label === 'RESOURCE' => ['store', 'update', 'destroy'],
            $creatable => ['update', 'store', 'destroy'],
            $destroyable => ['update', 'destroy'],
            default => ['update'],
        };
        foreach (['only' => true, 'except' => false] as $filter => $keeps) {
            if ($filters[$filter] === null) {
                continue;
            }

            $names = $this->entryNames($filters[$filter]);
            if (in_array(null, $names, true)) {
                return [false, [self::NO_CSRF]];
            }
            $writes = $keeps ? array_intersect($writes, $names) : array_diff($writes, $names);
        }

        // One finding stands for every write, each judged by its own state
        $states = [];
        foreach ($writes as $method) {
            $states[] = $this->csrfState($middlewareFor[$method] ?? $middleware, [...$excluded, ...($excludedFor[$method] ?? []), ...($excludedFor['*'] ?? [])]);
        }

        return $states === [] ? [false, [self::NO_CSRF]] : [true, $states];
    }

    /**
     * The method label a resource registration call reports under, and whether it is a plural
     * form that registers a list of resources.
     *
     * @return array{string, bool}
     */
    private function resourceRegistration(Expr\MethodCall|Expr\StaticCall $call): array
    {
        $name = $call->name instanceof Identifier ? $call->name->toLowerString() : '';

        return self::RESOURCE_REGISTRATIONS[$name] ?? ['RESOURCE', false];
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
     * Whether excluding these middleware removes the web group's CSRF protection: they name
     * 'web', or the CSRF middleware the group holds or a class it extends. Never while the
     * Kernel's global middleware runs CSRF (see $globalCsrf). A CSRF class a route applies
     * itself is judged by csrfRuns().
     *
     * Laravel's Router::resolveMiddleware() drops a middleware when it is an excluded name or a
     * subclass of one. When app/Http/Kernel.php or bootstrap/app.php settles the web group, its
     * CSRF entries are known, and the exclusion has to name each entry or a class it extends (see
     * csrfAncestors()). Otherwise, for a group that cannot be settled, the class is assumed:
     * before Laravel 13 any CSRF name removes it, as the framework's VerifyCsrfToken is the base
     * class. Laravel 13 makes
     * PreventRequestForgery the base, with VerifyCsrfToken and ValidateCsrfToken as empty
     * subclasses, so there only PreventRequestForgery, an application's own CSRF class, or the
     * framework's VerifyCsrfToken when the application has a CSRF subclass in
     * app/Http/Middleware, which extends it, removes the check.
     *
     * @param  list<string|null>  $names
     */
    private function namesStripCsrf(array $names): bool
    {
        if ($this->globalCsrf) {
            return false;
        }

        if (in_array('web', $names, true)) {
            return true;
        }

        if ($this->webGroupCsrf !== null) {
            // Every CSRF entry the group holds has to go: one left behind still checks the token
            $excluded = array_map(fn (string $name): string => ltrim($name, '\\'), array_filter($names, is_string(...)));
            foreach ($this->webGroupCsrf as $entry) {
                if (array_intersect($this->csrfAncestors($entry), $excluded) === []) {
                    return false;
                }
            }

            return $this->webGroupCsrf !== [];
        }

        foreach ($names as $name) {
            if ($name === null || $this->csrfMiddlewareIn($name) === null) {
                continue;
            }

            $class = ltrim($name, '\\');

            if (! $this->isLaravel13OrNewer()
                || ! str_starts_with($class, 'Illuminate\\')
                || str_ends_with($class, '\\PreventRequestForgery')
                || ($class === self::FRAMEWORK_VERIFY_CSRF && $this->csrfMiddlewareFile() !== null)) {
                return true;
            }
        }

        return false;
    }

    /**
     * CSRF middleware $entry and every class it extends, nearest first: the classes an exclusion
     * may name to remove it. An application class is read from its file under app/, following
     * the App namespace; one whose file cannot be read is assumed to extend the framework's
     * VerifyCsrfToken, as Laravel's stubs do, while one read without an extends clause extends
     * nothing an exclusion may name. Laravel 13 derives VerifyCsrfToken and
     * ValidateCsrfToken from PreventRequestForgery; earlier versions derive ValidateCsrfToken
     * from VerifyCsrfToken. An entry with :parameters is only itself: Router::resolveMiddleware()
     * drops it for an exclusion of the same string, as 'Class:params' is not a class to subclass.
     * A group entry's empty or '0' parameters are dropped before it gets here (see groupEntry()).
     *
     * @return list<string>
     */
    private function csrfAncestors(string $entry): array
    {
        $framework = 'Illuminate\\Foundation\\Http\\Middleware\\';
        $ancestors = [];
        $class = ltrim($entry, '\\');

        if (str_contains($class, ':')) {
            return [$class];
        }

        // A few levels of application subclasses, then the framework hierarchy
        for ($depth = 0; $depth < 5 && ! str_starts_with($class, 'Illuminate\\'); $depth++) {
            $ancestors[] = $class;
            $parent = $this->applicationParent($class);
            if ($parent === false) {
                return $ancestors;
            }
            $class = $parent ?? self::FRAMEWORK_VERIFY_CSRF;
        }
        $ancestors[] = $class;

        $base = $this->isLaravel13OrNewer() ? $framework.'PreventRequestForgery' : self::FRAMEWORK_VERIFY_CSRF;
        if (str_starts_with($class, $framework) && $class !== $base && $this->csrfMiddlewareIn($class) !== null) {
            $ancestors[] = $base;
        }

        return $ancestors;
    }

    /**
     * The class an App-namespaced class extends, read from its file under app/, false when the
     * file declares the class without an extends clause, or null when the class is not under App
     * or its file is missing, does not parse or does not declare it.
     */
    private function applicationParent(string $class): string|false|null
    {
        if (! str_starts_with($class, 'App\\')) {
            return null;
        }

        $segments = explode('\\', substr($class, 4));
        $path = $this->buildPath('app', ...$segments).'.php';
        if (! file_exists($path)) {
            return null;
        }

        $short = $segments[count($segments) - 1];
        foreach ($this->parser->findNodes($this->resolveNamesForMatching($this->parser->parseFile($path)), Stmt\Class_::class) as $node) {
            if ($node instanceof Stmt\Class_ && $node->name?->toString() === $short) {
                if ($node->extends === null) {
                    return false;
                }

                $resolved = $node->extends->getAttribute('resolvedName');

                return ($resolved instanceof Name ? $resolved : $node->extends)->toString();
            }
        }

        return null;
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
