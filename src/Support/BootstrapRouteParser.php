<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use Closure;
use PhpParser\Node;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Include_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Scalar\MagicConst\Dir;
use PhpParser\Node\Scalar\String_;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\Concerns\ResolvesClassNames;

/**
 * Detects route files covered by web or API middleware through external registration.
 *
 * Two sources are checked per middleware group:
 *   1. Files require'd/include'd from routes/web.php or routes/api.php
 *      (inherit that file's middleware group automatically)
 *   2. Files registered via Route::middleware('web|api')->...->group(base_path('...'))
 *      or Route::group(['middleware' => 'web|api'], base_path('...')), each file of a list
 *      given in their place, or require'd inside such a group's closure, in
 *      bootstrap/app.php's withRouting(then: ...) callback or in app/Providers/*.php.
 *      The middleware reaches the file from any enclosing group unless one excludes
 *      it, as Laravel merges group attributes
 *
 * It also exposes {@see self::getThrottledGroupLineRanges()} for the in-file case:
 * the line spans of throttled Route::...->group(Closure) blocks declared directly
 * inside a route file (fluent and array forms), used to tell whether a given route
 * line is covered by group-level throttling.
 *
 * A group counts as throttled by the middleware MiddlewareThrottleDetector recognises,
 * with class names resolved against the imports of the file that declares the group.
 *
 * @phpstan-type RouteFileWalk array{loads: list<array{file: string, calls: list<MethodCall|StaticCall>}>, routesFrom: list<array{file: string, calls: list<MethodCall|StaticCall>}>, closures: list<array{closure: Node, calls: non-empty-list<MethodCall|StaticCall>}>, groups: array<int, list<Node\Expr>>, bindings: array<int, string>}
 */
class BootstrapRouteParser
{
    use ResolvesClassNames;

    private readonly MiddlewareThrottleDetector $throttles;

    /**
     * The classes the container resolves the router as, besides its 'router' binding.
     */
    private const ROUTER_CLASSES = ['Illuminate\\Routing\\Router', 'Illuminate\\Contracts\\Routing\\Registrar'];

    /** @var array<string, RouteFileWalk> */
    private array $walks = [];

    /**
     * The judge, $nameThrottles, says whether one middleware name throttles, as
     * {@see MiddlewareThrottleDetector::__construct()} describes. Without one, only the
     * framework's throttle classes and the 'throttle' alias Laravel registers count.
     *
     * @param  (Closure(string): bool)|null  $nameThrottles
     */
    public function __construct(
        private readonly string $basePath,
        private readonly ParserInterface $parser,
        ?Closure $nameThrottles = null,
    ) {
        $this->throttles = new MiddlewareThrottleDetector($basePath, $parser, $nameThrottles);
    }

    /**
     * Returns absolute paths of route files covered by 'web' middleware
     * through external registration (not declared inside the file).
     *
     * @return array<string>
     */
    public function getWebProtectedRouteFiles(): array
    {
        return array_values(array_unique(array_merge(
            $this->getFilesRequiredFromWebPhp(),
            $this->getFilesRegisteredWithWebMiddlewareInBootstrap(),
            $this->getFilesFromWithRoutingWebArg(),
            $this->getFilesRegisteredWithWebMiddlewareInProvidersDir(),
        )));
    }

    /**
     * Returns absolute paths of route files registered under the 'api' middleware group
     * through external registration (require from api.php, or bootstrap/app.php, or app/Providers).
     *
     * @return array<string>
     */
    public function getApiRegisteredRouteFiles(): array
    {
        return array_values(array_unique(array_merge(
            $this->getFilesRequiredFromApiPhp(),
            $this->getFilesRegisteredWithApiMiddlewareInBootstrap(),
            $this->getFilesFromWithRoutingApiArg(),
            $this->getFilesRegisteredWithApiMiddlewareInProvidersDir(),
        )));
    }

    /**
     * Finds route files require'd/include'd from routes/web.php.
     * These inherit the 'web' middleware group automatically.
     *
     * @return array<string>
     */
    private function getFilesRequiredFromWebPhp(): array
    {
        return $this->getFilesRequiredFromRouteFile('routes/web.php');
    }

    /**
     * Finds route files require'd/include'd from routes/api.php.
     * These inherit the 'api' middleware group automatically.
     *
     * @return array<string>
     */
    private function getFilesRequiredFromApiPhp(): array
    {
        return $this->getFilesRequiredFromRouteFile('routes/api.php');
    }

    /**
     * Finds route files require'd/include'd from a given route file.
     *
     * @return array<string>
     */
    private function getFilesRequiredFromRouteFile(string $relativeRouteFile): array
    {
        $routeFilePath = $this->basePath.'/'.$relativeRouteFile;
        if (! file_exists($routeFilePath)) {
            return [];
        }

        $ast = $this->parser->parseFile($routeFilePath);
        if (empty($ast)) {
            return [];
        }

        $found = [];
        $includes = $this->parser->findNodes($ast, Include_::class);

        foreach ($includes as $include) {
            if (! ($include instanceof Include_)) {
                continue;
            }
            $path = $this->resolveIncludePath($include->expr, dirname($routeFilePath));
            if ($path !== null && file_exists($path)) {
                $normalized = $this->normalizePath($path);
                if ($normalized !== null) {
                    $found[] = $normalized;
                }
            }
        }

        return $found;
    }

    /**
     * Returns absolute paths of route files registered on a throttled group in
     * bootstrap/app.php or app/Providers/*.php, in the forms
     * {@see self::filesGroupsApply()} reads.
     *
     * Matches any throttle variant: 'throttle:5,1', ThrottleRequests::class,
     * ThrottleRequests::class.':5,1', ThrottleRequests::using('login') or
     * ThrottleRequests::with(5, 1), under any import alias, or an app alias the
     * judge resolves to one.
     *
     * @return array<string>
     */
    public function getThrottleProtectedRouteFiles(): array
    {
        return array_values(array_unique(array_merge(
            $this->getFilesRegisteredWithThrottleMiddlewareInBootstrap(),
            $this->getFilesRegisteredWithThrottleMiddlewareInProvidersDir(),
        )));
    }

    /**
     * Route files a group registers, each with the group calls it inherits its
     * middleware from, as {@see self::groupRegistrations()} reads them. Read from
     * bootstrap/app.php, app/Providers/*.php and, unless $routeFiles is false, the route
     * files, so the caller can resolve the groups' middleware against the imports of the
     * file that declares them.
     *
     * @return array<int, array{file: string, source: string, calls: non-empty-list<MethodCall|StaticCall>}>
     *
     * @internal An implementation detail of csrf-protection and login-throttling, outside this package's backward-compatibility promise.
     */
    public function getGroupRegisteredRouteFiles(bool $routeFiles = true): array
    {
        $sources = [
            $this->basePath.'/bootstrap/app.php',
            ...($routeFiles ? $this->phpFilesUnder('routes') : []),
            ...$this->phpFilesUnder('app/Providers'),
        ];

        $found = [];
        foreach ($sources as $source) {
            foreach ($this->groupRegistrations($source) as $registration) {
                $found[] = ['file' => $registration['file'], 'source' => $source, 'calls' => $registration['calls']];
            }
        }

        return $found;
    }

    /**
     * The route files each PHP file under routes/ loads, keyed by the loading file's
     * normalized path: a file it require's/include's, at any depth of nested groups or
     * outside any group, or a group path argument, each with the group calls enclosing
     * the load in that file, outermost first, which may be none. A loaded file inherits
     * what the loading file was registered with, as Laravel loads it in that context.
     * A require_once is read as a require.
     *
     * @return array<string, list<array{file: string, calls: list<MethodCall|StaticCall>}>>
     *
     * @internal An implementation detail of login-throttling, outside this package's backward-compatibility promise.
     */
    public function getRouteFileLoads(): array
    {
        $found = [];
        foreach ($this->phpFilesUnder('routes') as $source) {
            $loads = $this->routeFileLoads($source);
            $normalized = $this->normalizePath($source);
            if ($loads !== [] && $normalized !== null) {
                $found[$normalized] = $loads;
            }
        }

        return $found;
    }

    /**
     * Every route file bootstrap/app.php and app/Providers/*.php load, group or not: the
     * loads {@see self::getGroupRegisteredRouteFiles()} reads, the files they
     * require/include inside a group or outside one, and those $this->loadRoutesFrom(...)
     * requires, each with the source file and the group calls enclosing the load, outermost
     * first, which may be none.
     *
     * @return list<array{file: string, source: string, calls: list<MethodCall|StaticCall>}>
     *
     * @internal An implementation detail of csrf-protection, outside this package's backward-compatibility promise.
     */
    public function getExternalRouteFileLoads(): array
    {
        $found = [];
        foreach ([$this->basePath.'/bootstrap/app.php', ...$this->phpFilesUnder('app/Providers')] as $source) {
            $walk = $this->walkFile($source);
            foreach ([...$walk['loads'], ...$walk['routesFrom']] as $load) {
                $found[] = ['file' => $load['file'], 'source' => $source, 'calls' => $load['calls']];
            }
        }

        return $found;
    }

    /**
     * The PHP files under a directory of the base path, at any depth.
     *
     * @return list<string>
     */
    private function phpFilesUnder(string $relativeDir): array
    {
        if (! is_dir($this->basePath.'/'.$relativeDir)) {
            return [];
        }

        $paths = [];
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->basePath.'/'.$relativeDir, \FilesystemIterator::SKIP_DOTS));
        foreach ($files as $file) {
            if ($file instanceof \SplFileInfo && $file->isFile() && $file->getExtension() === 'php') {
                $paths[] = $file->getPathname();
            }
        }

        return $paths;
    }

    /**
     * Returns the line ranges of throttled Route::...->group(Closure) blocks
     * declared inside the given route file. Covers both the fluent form
     * (Route::middleware([...'throttle'...])->group(fn)) and the array form
     * (Route::group(['middleware' => 'throttle...'], fn)), one range for each closure a
     * list passes, with the throttle variants
     * {@see self::getThrottleProtectedRouteFiles()} matches. A group is
     * throttled when its own or an enclosing group's throttle is not excluded by
     * ->withoutMiddleware(...) or 'excluded_middleware' at any level, by the exact name
     * {@see MiddlewareThrottleDetector::throttlesAfterExclusion()} matches. A throttled
     * group's range leaves out the lines strictly inside the nested groups that are not:
     * the lines such a group opens and closes on can hold routes outside it. Overlapping ranges
     * are returned as-is, so a route line inside any range is covered. Path-argument
     * groups (->group(base_path(...))) open no closure and are intentionally ignored here.
     *
     * @return array<int, array{start: int, end: int}>
     */
    public function getThrottledGroupLineRanges(string $filePath): array
    {
        if (! file_exists($filePath)) {
            return [];
        }

        $scopes = $this->walkFile($filePath)['closures'];

        $throttled = [];
        foreach ($scopes as $index => $scope) {
            $throttled[$index] = $this->groupsThrottle($scope['calls']);
        }

        $ranges = [];
        foreach ($scopes as $index => $scope) {
            if (! $throttled[$index]) {
                continue;
            }

            $segments = [['start' => $scope['closure']->getStartLine(), 'end' => $scope['closure']->getEndLine()]];
            $group = $scope['calls'][count($scope['calls']) - 1];
            foreach ($scopes as $other => $nested) {
                if ($other !== $index && ! $throttled[$other] && in_array($group, $nested['calls'], true)) {
                    $segments = $this->withoutLines($segments, $nested['closure']->getStartLine() + 1, $nested['closure']->getEndLine() - 1);
                }
            }
            array_push($ranges, ...$segments);
        }

        return $ranges;
    }

    /**
     * Whether a throttle one of these nested group calls applies survives the middleware
     * any of them excludes, as Laravel merges both down nested groups.
     *
     * @param  list<MethodCall|StaticCall>  $calls
     */
    private function groupsThrottle(array $calls): bool
    {
        $applied = [];
        $excluded = [];
        foreach ($calls as $call) {
            array_push($applied, ...$this->groupEntries($call, 'middleware', 'middleware'));
            array_push($excluded, ...$this->groupEntries($call, 'withoutmiddleware', 'excluded_middleware'));
        }

        return $this->throttles->throttlesAfterExclusion($applied, $excluded);
    }

    /**
     * Line ranges with the lines $start to $end taken out.
     *
     * @param  list<array{start: int, end: int}>  $segments
     * @return list<array{start: int, end: int}>
     */
    private function withoutLines(array $segments, int $start, int $end): array
    {
        $kept = [];
        foreach ($segments as $segment) {
            if ($segment['start'] < $start) {
                $kept[] = ['start' => $segment['start'], 'end' => min($segment['end'], $start - 1)];
            }
            if ($segment['end'] > $end) {
                $kept[] = ['start' => max($segment['start'], $end + 1), 'end' => $segment['end']];
            }
        }

        return $kept;
    }

    /**
     * The Closure/ArrowFunction callbacks a group() call loads, as {@see self::groupRoutes()}
     * reads them, in argument order.
     *
     * @param  array<Node>  $args  Raw argument list; only plain Args carry a value.
     * @return list<Node\Expr\Closure|Node\Expr\ArrowFunction>
     *
     * @internal An implementation detail of login-throttling and of this class itself, outside this package's backward-compatibility promise.
     */
    public function closureArguments(array $args): array
    {
        return array_values(array_filter(
            $this->groupRoutes($args),
            fn (Node\Expr $entry): bool => $entry instanceof Node\Expr\Closure || $entry instanceof Node\Expr\ArrowFunction,
        ));
    }

    /**
     * The values a group() call is given, with its routes argument read as Router::group()
     * reads it through Arr::wrap(): each item of a list, or the value itself. The routes
     * argument is the one named routes: (Router::group()) or callback:
     * (RouteRegistrar::group()), otherwise the last positional one, as Router::group()
     * takes its attribute array first and RouteRegistrar::group() takes only the routes.
     * The other arguments' values follow as they are, so an attribute array is never read
     * as routes; callers find no route file or closure in it.
     *
     * @param  array<Node>  $args  Raw argument list; only plain Args carry a value.
     * @return list<Node\Expr>
     *
     * @internal An implementation detail of authentication-authorization, csrf-protection and this class itself, outside this package's backward-compatibility promise.
     */
    public function groupRoutes(array $args): array
    {
        $routes = $this->routesArgument($args);
        $entries = [];
        foreach ($args as $arg) {
            if (! $arg instanceof Node\Arg) {
                continue;
            }
            if ($arg !== $routes || ! $arg->value instanceof Node\Expr\Array_) {
                $entries[] = $arg->value;

                continue;
            }
            foreach ($arg->value->items as $item) {
                if ($item instanceof Node\Expr\ArrayItem) {
                    $entries[] = $item->value;
                }
            }
        }

        return $entries;
    }

    /**
     * The argument a group() call passes its routes in: the one named routes: or callback:,
     * matched case-sensitively as PHP matches parameter names, otherwise the last positional
     * one. Null when an argument is unpacked, as its items' positions cannot be read.
     *
     * @param  array<Node>  $args  Raw argument list; only plain Args carry a value.
     */
    private function routesArgument(array $args): ?Node\Arg
    {
        $positional = null;
        foreach ($args as $arg) {
            if (! $arg instanceof Node\Arg) {
                continue;
            }
            if ($arg->unpack) {
                return null;
            }
            if ($arg->name === null) {
                $positional = $arg;
            } elseif (in_array($arg->name->toString(), ['routes', 'callback'], true)) {
                return $arg;
            }
        }

        return $positional;
    }

    /**
     * Whether $judge accepts any of these middleware entries.
     *
     * @param  array<Node\Expr>  $entries
     * @param  Closure(Node\Expr): bool  $judge
     */
    private function anyEntry(array $entries, Closure $judge): bool
    {
        foreach ($entries as $entry) {
            if ($judge($entry)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The entries a group's attribute array lists under $key, such as 'middleware' or
     * 'excluded_middleware': each item of an array value, or the value itself.
     *
     * @param  array<Node>  $args  Raw argument list; only plain Args carry a value.
     * @return array<Node\Expr>
     *
     * @internal An implementation detail of csrf-protection and of this class itself, outside this package's backward-compatibility promise.
     */
    public function groupAttributeEntries(array $args, string $key): array
    {
        $entries = [];
        foreach ($args as $arg) {
            if (! ($arg instanceof Node\Arg) || ! ($arg->value instanceof Node\Expr\Array_)) {
                continue;
            }
            foreach ($arg->value->items as $item) {
                if (! ($item instanceof Node\Expr\ArrayItem)
                    || ! ($item->key instanceof String_)
                    || $item->key->value !== $key) {
                    continue;
                }
                if (! ($item->value instanceof Node\Expr\Array_)) {
                    $entries[] = $item->value;

                    continue;
                }
                foreach ($item->value->items as $listed) {
                    if ($listed instanceof Node\Expr\ArrayItem) {
                        $entries[] = $listed->value;
                    }
                }
            }
        }

        return $entries;
    }

    /**
     * Returns route files declared via withRouting(api: ...) in bootstrap/app.php.
     * Supports both a single path and an array of paths (e.g. versioned API files).
     *
     * @return array<string>
     */
    private function getFilesFromWithRoutingApiArg(): array
    {
        return $this->getFilesFromWithRoutingArg('api');
    }

    /**
     * Returns route files declared via withRouting(web: ...) in bootstrap/app.php.
     *
     * @return array<string>
     */
    private function getFilesFromWithRoutingWebArg(): array
    {
        return $this->getFilesFromWithRoutingArg('web');
    }

    /**
     * Parses bootstrap/app.php and extracts file paths from the withRouting(argName: ...)
     * named argument. Supports both a single path expression and an array of path expressions.
     *
     * @return array<string>
     */
    private function getFilesFromWithRoutingArg(string $argName): array
    {
        $bootstrapPath = $this->basePath.'/bootstrap/app.php';
        if (! file_exists($bootstrapPath)) {
            return [];
        }

        $ast = $this->parser->parseFile($bootstrapPath);
        if (empty($ast)) {
            return [];
        }

        $bootstrapDir = dirname($bootstrapPath);
        $found = [];

        $calls = $this->parser->findMethodCalls($ast, 'withRouting');
        foreach ($calls as $call) {
            if (! ($call instanceof MethodCall)) {
                continue;
            }
            foreach ($call->args as $arg) {
                if (! ($arg instanceof Node\Arg)) {
                    continue;
                }
                if (! ($arg->name instanceof Identifier) || $arg->name->name !== $argName) {
                    continue;
                }
                $paths = $this->extractWithRoutingPaths($arg->value, $bootstrapDir);
                foreach ($paths as $path) {
                    $normalized = $this->normalizePath($path);
                    if ($normalized !== null && file_exists($normalized)) {
                        $found[] = $normalized;
                    }
                }
            }
        }

        return $found;
    }

    /**
     * Extracts file path strings from a withRouting named argument value.
     * Handles both a single path expression and an array of path expressions.
     *
     * @return array<string>
     */
    private function extractWithRoutingPaths(Node $expr, string $dir): array
    {
        if ($expr instanceof Node\Expr\Array_) {
            $paths = [];
            foreach ($expr->items as $item) {
                if ($item instanceof Node\Expr\ArrayItem) {
                    $resolved = $this->resolveWithRoutingPath($item->value, $dir);
                    if ($resolved !== null) {
                        $paths[] = $resolved;
                    }
                }
            }

            return $paths;
        }

        $resolved = $this->resolveWithRoutingPath($expr, $dir);

        return $resolved !== null ? [$resolved] : [];
    }

    /**
     * Resolves a single withRouting path expression to a raw (un-normalized) path string.
     * Handles __DIR__.'/...' concat, base_path('...'), and bare string literals.
     */
    private function resolveWithRoutingPath(Node $expr, string $dir): ?string
    {
        // __DIR__.'/../routes/api.php'
        if ($expr instanceof Concat && $expr->left instanceof Dir && $expr->right instanceof String_) {
            return $dir.$expr->right->value;
        }

        // base_path('routes/api.php')
        $basePath = $this->extractBasePathArgument($expr);
        if ($basePath !== null) {
            return $basePath;
        }

        // Bare string literal
        if ($expr instanceof String_) {
            return str_starts_with($expr->value, '/') ? $expr->value : $dir.'/'.$expr->value;
        }

        return null;
    }

    /**
     * Normalizes a path by resolving '..' segments.
     * Uses realpath() when the file exists; falls back to manual segment resolution.
     */
    private function normalizePath(string $path): ?string
    {
        $real = realpath($path);
        if ($real !== false) {
            return str_replace('\\', '/', $real);
        }

        $parts = explode('/', str_replace('\\', '/', $path));
        $resolved = [];
        foreach ($parts as $part) {
            if ($part === '..') {
                array_pop($resolved);
            } elseif ($part !== '.') {
                $resolved[] = $part;
            }
        }

        return implode('/', $resolved) ?: null;
    }

    /**
     * Finds route files registered on a 'web' group inside bootstrap/app.php's
     * withRouting(then: ...) callback, in the forms
     * {@see self::getFilesRegisteredWithMiddlewareInFile()} reads.
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithWebMiddlewareInBootstrap(): array
    {
        return $this->getFilesRegisteredWithMiddlewareInFile(
            $this->basePath.'/bootstrap/app.php', 'web'
        );
    }

    /**
     * Finds route files registered on an 'api' group inside bootstrap/app.php's
     * withRouting(then: ...) callback, in the forms
     * {@see self::getFilesRegisteredWithMiddlewareInFile()} reads.
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithApiMiddlewareInBootstrap(): array
    {
        return $this->getFilesRegisteredWithMiddlewareInFile(
            $this->basePath.'/bootstrap/app.php', 'api'
        );
    }

    /**
     * Finds route files registered on a 'web' group in any PHP file under app/Providers/
     * (e.g. RouteServiceProvider, RoutingServiceProvider).
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithWebMiddlewareInProvidersDir(): array
    {
        return $this->getFilesRegisteredWithMiddlewareInProvidersDir('web');
    }

    /**
     * Finds route files registered on an 'api' group in any PHP file under app/Providers/.
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithApiMiddlewareInProvidersDir(): array
    {
        return $this->getFilesRegisteredWithMiddlewareInProvidersDir('api');
    }

    /**
     * Scans all PHP files in app/Providers/ for groups that carry the given middleware name.
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithMiddlewareInProvidersDir(string $middlewareName): array
    {
        $providersDir = $this->basePath.'/app/Providers';
        if (! is_dir($providersDir)) {
            return [];
        }

        $found = [];
        foreach (glob($providersDir.'/*.php') ?: [] as $file) {
            $found = array_merge($found, $this->getFilesRegisteredWithMiddlewareInFile($file, $middlewareName));
        }

        return $found;
    }

    /**
     * Finds route files registered on a group carrying middlewareName in the given PHP file,
     * read as {@see self::filesGroupsApply()} reads them. Excluding the name, which Laravel
     * matches exactly, at any level wins.
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithMiddlewareInFile(string $filePath, string $middlewareName): array
    {
        return $this->filesGroupsApply(
            $filePath,
            fn (Node\Expr $entry): bool => $entry instanceof String_ && $entry->value === $middlewareName,
        );
    }

    /**
     * The route files groups in $filePath load that $judge says their groups apply to them:
     * a group enclosing the load names a matching middleware in the last ->middleware(...)
     * call on its chain, or in its 'middleware' attribute. Laravel merges the middleware
     * down nested groups. A group that excludes a matching middleware through
     * ->withoutMiddleware(...) or its 'excluded_middleware' attribute drops the file.
     *
     * @param  Closure(Node\Expr): bool  $judge
     * @return array<string>
     */
    private function filesGroupsApply(string $filePath, Closure $judge): array
    {
        $found = [];
        foreach ($this->groupRegistrations($filePath) as $registration) {
            $applied = false;
            foreach ($registration['calls'] as $call) {
                if ($this->anyEntry($this->groupEntries($call, 'withoutmiddleware', 'excluded_middleware'), $judge)) {
                    continue 2;
                }
                $applied = $applied || $this->anyEntry($this->groupEntries($call, 'middleware', 'middleware'), $judge);
            }
            if ($applied) {
                $found[] = $registration['file'];
            }
        }

        return $found;
    }

    /**
     * The middleware a group call lists through its chain's ->$chainMethod(...) calls
     * (lowercase), read as {@see self::chainEntries()} reads them, and under $attributeKey
     * in its attribute array.
     *
     * @return array<Node\Expr>
     */
    private function groupEntries(MethodCall|StaticCall $call, string $chainMethod, string $attributeKey): array
    {
        return [
            ...($call instanceof MethodCall ? $this->chainEntries($call->var, $chainMethod) : []),
            ...$this->groupAttributeEntries($call->args, $attributeKey),
        ];
    }

    /**
     * Route files the groups in $source load, each with the group calls it inherits
     * middleware from, outermost first: a path argument, ->group(base_path('...')) or
     * ->group(__DIR__.'/...'), which Router::loadRoutes() requires, each such path in a
     * list read as {@see self::groupRoutes()} reads it, or a file
     * require'd/include'd inside a group's closure, at any depth of nested groups. Each
     * file is read once, with class names resolved for matching.
     *
     * @return list<array{file: string, calls: non-empty-list<MethodCall|StaticCall>}>
     */
    private function groupRegistrations(string $source): array
    {
        $registrations = [];
        foreach ($this->routeFileLoads($source) as $load) {
            if ($load['calls'] !== []) {
                $registrations[] = ['file' => $load['file'], 'calls' => $load['calls']];
            }
        }

        return $registrations;
    }

    /**
     * The route files $source loads: those {@see self::groupRegistrations()} reads, and
     * the files it require's/include's outside any group, with no group calls.
     *
     * @return list<array{file: string, calls: list<MethodCall|StaticCall>}>
     */
    private function routeFileLoads(string $source): array
    {
        return $this->walkFile($source)['loads'];
    }

    /**
     * The group(...) calls in a tree that are made on the router (see
     * {@see self::isGroupCall()}), keyed by spl_object_id(), so a caller reading the same
     * tree can tell a route group from a group() on another object.
     *
     * @param  array<Node>  $ast
     * @return array<int, true>
     *
     * @internal An implementation detail of login-throttling, outside this package's backward-compatibility promise.
     */
    public function routerGroupCalls(array $ast): array
    {
        return array_fill_keys(array_keys($this->routerGroupRoutes($ast)), true);
    }

    /**
     * The routes each group(...) call {@see self::routerGroupCalls()} finds loads, keyed by
     * spl_object_id(), as {@see self::groupRoutes()} reads them, with a variable holding route
     * paths read as those paths (see {@see self::assignedPaths()}).
     *
     * @param  array<Node>  $ast
     * @return array<int, list<Node\Expr>>
     *
     * @internal An implementation detail of csrf-protection and of this class itself, outside this package's backward-compatibility promise.
     */
    public function routerGroupRoutes(array $ast): array
    {
        $walk = ['loads' => [], 'routesFrom' => [], 'closures' => [], 'groups' => [], 'bindings' => []];
        $routers = [];
        $paths = [];
        $ast = $this->resolveNamesForMatching($ast);
        $walk['bindings'] = $this->touchesGlobals($ast) ? [] : $this->pathBindings($this->scopeStatements($ast))['bindings'];
        foreach ($ast as $node) {
            $this->walkRouteNode($node, [], $routers, $paths, null, $walk);
        }

        return $walk['groups'];
    }

    /**
     * One walk of a file, with class names resolved for matching, read once per file.
     *
     * @return RouteFileWalk
     */
    private function walkFile(string $path): array
    {
        if (! isset($this->walks[$path])) {
            $walk = ['loads' => [], 'routesFrom' => [], 'closures' => [], 'groups' => [], 'bindings' => []];
            $routers = [];
            $paths = [];
            if (file_exists($path)) {
                $ast = $this->resolveNamesForMatching($this->parser->parseFile($path));
                $walk['bindings'] = $this->touchesGlobals($ast) ? [] : $this->pathBindings($this->scopeStatements($ast))['bindings'];
                foreach ($ast as $node) {
                    $this->walkRouteNode($node, [], $routers, $paths, dirname($path), $walk);
                }
            }
            $this->walks[$path] = $walk;
        }

        return $this->walks[$path];
    }

    /**
     * Walk one node, recording into $walk the route files it loads (a require/include, or
     * a group path argument), each with the group calls enclosing the load, which may be
     * none; each group closure with the group calls enclosing it, ending with its own; and
     * each group call made on the router.
     *
     * Variables that hold the router are tracked per function scope, in the order the code
     * runs: see {@see self::functionRouters()}, and a variable assigned the router, or a
     * call chain on it, holds it until it is assigned something else. Variables that hold
     * route paths are tracked per function scope too (see {@see self::functionPaths()}), but
     * only through the assignments {@see self::pathBindings()} finds: a group given one
     * loads the paths last assigned to it before the call.
     *
     * @param  list<MethodCall|StaticCall>  $groups  The group calls enclosing $node, outermost first
     * @param  array<string, true>  $routers  Variables that hold the router in this function scope
     * @param  array<string, non-empty-list<Node\Expr>>  $paths  Variables that hold route paths in this function scope
     * @param  ?string  $dir  The directory of the file being walked; null records no loads
     * @param  bool  $callback  Whether $node is a group call's callback, which Laravel calls with the router
     * @param  RouteFileWalk  $walk
     */
    private function walkRouteNode(Node $node, array $groups, array &$routers, array &$paths, ?string $dir, array &$walk, bool $callback = false): void
    {
        if ($node instanceof Node\FunctionLike) {
            $scope = $this->functionRouters($node, $routers, $callback);
            $scopePaths = $this->functionPaths($node, $paths);
            if (! $node instanceof Node\Expr\ArrowFunction) {
                // An imported variable the function writes any other way is not read either
                $writes = $this->pathBindings($node->getStmts() ?? [], $this->references($node));
                $walk['bindings'] += $writes['bindings'];
                $scopePaths = $writes['disabled'] ? [] : array_diff_key($scopePaths, $writes['untracked']);
            }
            foreach ($this->childNodes($node) as $child) {
                $this->walkRouteNode($child, $groups, $scope, $scopePaths, $dir, $walk);
            }

            return;
        }

        if ($node instanceof Node\Expr\Assign && $node->var instanceof Node\Expr\Variable && is_string($node->var->name)) {
            if ($this->chainOnRouter($node->expr, $routers)) {
                $routers[$node->var->name] = true;
            } else {
                unset($routers[$node->var->name]);
            }
        }

        // The value is read before the variable is written
        $bound = null;
        if ($node instanceof Node\Stmt\Expression && $node->expr instanceof Node\Expr\Assign && isset($walk['bindings'][spl_object_id($node)])) {
            $bound = [$walk['bindings'][spl_object_id($node)], $this->assignedPaths($node->expr->expr, $paths)];
        }

        if ($node instanceof Include_ && $dir !== null) {
            $path = $this->includedFile($node, $dir);
            if ($path !== null) {
                $walk['loads'][] = ['file' => $path, 'calls' => $groups];
            }
        }

        // ServiceProvider::loadRoutesFrom() requires the file where it is called, kept apart
        // from the loads so only getExternalRouteFileLoads() reads it
        if ($dir !== null && $this->isLoadRoutesFrom($node)) {
            $first = $this->firstArgument($node);
            $path = $first !== null ? $this->groupRouteFile($first, $dir) : null;
            if ($path !== null) {
                $walk['routesFrom'][] = ['file' => $path, 'calls' => $groups];
            }
        }

        if ($this->isGroupCall($node, $routers)) {
            $routes = $this->resolvedRoutes($node->args, $paths);
            $walk['groups'][spl_object_id($node)] = $routes;
            $inner = [...$groups, $node];
            foreach ($this->closureArguments($node->args) as $closure) {
                $walk['closures'][] = ['closure' => $closure, 'calls' => $inner];
            }
            foreach ($routes as $entry) {
                $path = $dir !== null ? $this->groupRouteFile($entry, $dir) : null;
                if ($path !== null) {
                    $walk['loads'][] = ['file' => $path, 'calls' => $inner];
                } else {
                    $isCallback = $entry instanceof Node\Expr\Closure || $entry instanceof Node\Expr\ArrowFunction;
                    $this->walkRouteNode($entry, $inner, $routers, $paths, $dir, $walk, $isCallback);
                }
            }
            $children = [$node instanceof MethodCall ? $node->var : $node->class];
        } else {
            $children = $this->childNodes($node);
        }

        foreach ($children as $child) {
            $this->walkRouteNode($child, $groups, $routers, $paths, $dir, $walk);
        }

        if ($bound !== null) {
            [$name, $assigned] = $bound;
            if ($assigned !== null) {
                $paths[$name] = $assigned;
            } else {
                unset($paths[$name]);
            }
        }
    }

    /**
     * The routes a group() call loads, as {@see self::groupRoutes()} reads them, with each
     * variable that holds route paths in this scope read as those paths.
     *
     * @param  array<Node>  $args  Raw argument list; only plain Args carry a value.
     * @param  array<string, non-empty-list<Node\Expr>>  $paths
     * @return list<Node\Expr>
     */
    private function resolvedRoutes(array $args, array $paths): array
    {
        $routes = [];
        foreach ($this->groupRoutes($args) as $entry) {
            if ($entry instanceof Node\Expr\Variable && is_string($entry->name) && isset($paths[$entry->name])) {
                array_push($routes, ...$paths[$entry->name]);
            } else {
                $routes[] = $entry;
            }
        }

        return $routes;
    }

    /**
     * The route paths a variable assigned $expr holds: a path {@see self::groupRouteFile()}
     * reads, a variable holding paths, or a non-empty list of them, each kept once. Null for
     * anything else, which leaves the variable unread.
     *
     * @param  array<string, non-empty-list<Node\Expr>>  $paths
     * @return non-empty-list<Node\Expr>|null
     */
    private function assignedPaths(Node\Expr $expr, array $paths): ?array
    {
        $entries = [$expr];
        if ($expr instanceof Node\Expr\Array_) {
            $entries = [];
            foreach ($expr->items as $item) {
                if (! $item instanceof Node\Expr\ArrayItem || $item->unpack || $item->byRef) {
                    return null;
                }
                $entries[] = $item->value;
            }
        }

        $found = [];
        foreach ($entries as $entry) {
            if ($entry instanceof Node\Expr\Variable && is_string($entry->name) && isset($paths[$entry->name])) {
                foreach ($paths[$entry->name] as $path) {
                    $found[spl_object_id($path)] = $path;
                }
            } elseif (! $entry instanceof String_ && $this->resolveWithRoutingPath($entry, '') !== null) {
                // The directory only completes a path, so any reads its form
                $found[spl_object_id($entry)] = $entry;
            } else {
                return null;
            }
        }

        return $found === [] ? null : array_values($found);
    }

    /**
     * The variables that hold route paths inside a function: those a closure imports by
     * value through use(), or, in an arrow function, its parent's, as PHP binds them by
     * value, less any parameter of the same name. A variable imported by reference may be
     * written whenever the closure runs, so it is not read.
     *
     * @param  array<string, non-empty-list<Node\Expr>>  $outer  The variables of the enclosing scope
     * @return array<string, non-empty-list<Node\Expr>>
     */
    private function functionPaths(Node\FunctionLike $function, array $outer): array
    {
        $paths = $function instanceof Node\Expr\ArrowFunction ? $outer : [];
        if ($function instanceof Node\Expr\Closure) {
            foreach ($function->uses as $use) {
                if (! $use->byRef && is_string($use->var->name) && isset($outer[$use->var->name])) {
                    $paths[$use->var->name] = $outer[$use->var->name];
                }
            }
        }

        foreach ($function->getParams() as $param) {
            if ($param->var instanceof Node\Expr\Variable && is_string($param->var->name)) {
                unset($paths[$param->var->name]);
            }
        }

        return $paths;
    }

    /**
     * The statements a function scope runs in order: the file's, including those of a
     * namespace block, or a function's body.
     *
     * @param  array<Node>  $ast
     * @return array<Node>
     */
    private function scopeStatements(array $ast): array
    {
        $statements = [];
        foreach ($ast as $node) {
            array_push($statements, ...$node instanceof Node\Stmt\Namespace_ ? $node->stmts : [$node]);
        }

        return $statements;
    }

    /**
     * The assignments in one function scope that set a variable the walk reads as route
     * paths, keyed by spl_object_id() of their statement: a `$var = ...;` statement among
     * the scope's own statements, outside any branch or loop, for a variable the scope writes
     * no other way. Any other write, anywhere in the scope, including inside an expression,
     * an arrow function or a branch, or the reference a nested closure imports, leaves the
     * variable unread. So does the whole scope when it can write variables it does not name:
     * through extract(), parse_str() with one argument, eval(), a variable variable,
     * \$GLOBALS, goto, a file it requires or includes, any reference (a by-reference foreach
     * value, array item or destructuring, `=&`, or a closure importing by reference), or a
     * function declared in it that reads a global. Each node is read once by its own scope,
     * and a declared function's body once more for its global statements.
     *
     * @param  array<Node>  $statements
     * @param  array<string, true>  $references  Variables that are references on entry, which a callee may write
     * @return array{bindings: array<int, string>, untracked: array<string, true>, disabled: bool}
     */
    private function pathBindings(array $statements, array $references = []): array
    {
        $candidates = [];
        $direct = [];
        foreach ($statements as $statement) {
            if ($statement instanceof Node\Stmt\Expression && $statement->expr instanceof Node\Expr\Assign
                && $statement->expr->var instanceof Node\Expr\Variable && is_string($statement->expr->var->name)) {
                $candidates[spl_object_id($statement)] = $statement->expr->var->name;
                $direct[spl_object_id($statement->expr)] = true;
            }
        }

        $disabled = ['bindings' => [], 'untracked' => [], 'disabled' => true];
        $untracked = $references;
        $pending = $statements;
        while ($pending !== []) {
            $node = array_pop($pending);
            if ($node instanceof Node\Stmt\Goto_ || $node instanceof Node\Stmt\Label || $node instanceof Include_
                || $node instanceof Node\Expr\Eval_ || $node instanceof Node\Expr\AssignRef
                || ($node instanceof Node\Stmt\Foreach_ && $node->byRef)
                || ($node instanceof Node\Expr\ArrayItem && $node->byRef)
                || ($node instanceof Node\Expr\Closure && array_filter($node->uses, fn (Node\ClosureUse $use): bool => $use->byRef) !== [])
                || ($node instanceof Node\Stmt\Function_ && $this->readsGlobals($node))
                || ($node instanceof FuncCall && ($this->isFunction($node, ['extract']) || ($this->isFunction($node, ['parse_str']) && count($node->args) === 1)))) {
                return $disabled;
            }

            $written = $this->writtenVariables($node);
            if ($node instanceof Node\Expr\Assign && $node->var instanceof Node\Expr\Variable && ! isset($direct[spl_object_id($node)])) {
                $written[] = $node->var;
            }
            foreach ($written as $variable) {
                if (! is_string($variable->name) || $variable->name === 'GLOBALS') {
                    return $disabled;
                }
                $untracked[$variable->name] = true;
            }

            if (! $node instanceof Node\FunctionLike || $node instanceof Node\Expr\ArrowFunction) {
                array_push($pending, ...$this->childNodes($node));
            }
        }

        return ['bindings' => array_diff($candidates, array_keys($untracked)), 'untracked' => $untracked, 'disabled' => false];
    }

    /**
     * The variables a function receives as references: those a closure imports by reference
     * and its by-reference parameters.
     *
     * @return array<string, true>
     */
    private function references(Node\FunctionLike $function): array
    {
        $references = [];
        foreach ($function instanceof Node\Expr\Closure ? $function->uses : [] as $use) {
            if ($use->byRef && is_string($use->var->name)) {
                $references[$use->var->name] = true;
            }
        }
        foreach ($function->getParams() as $param) {
            if ($param->byRef && $param->var instanceof Node\Expr\Variable && is_string($param->var->name)) {
                $references[$param->var->name] = true;
            }
        }

        return $references;
    }

    /**
     * Whether anything in a file, at any depth, declares a global or writes \$GLOBALS, so a
     * variable of the file's own scope may change without being named there.
     *
     * @param  array<Node>  $ast
     */
    private function touchesGlobals(array $ast): bool
    {
        $pending = $ast;
        while ($pending !== []) {
            $node = array_pop($pending);
            if ($node instanceof Node\Stmt\Global_) {
                return true;
            }
            $written = $this->writtenVariables($node);
            if ($node instanceof Node\Expr\Assign && $node->var instanceof Node\Expr\Variable) {
                $written[] = $node->var;
            }
            foreach ($written as $variable) {
                if ($variable->name === 'GLOBALS') {
                    return true;
                }
            }
            array_push($pending, ...$this->childNodes($node));
        }

        return false;
    }

    /**
     * Whether a function body, outside the functions declared in it, holds a global statement.
     */
    private function readsGlobals(Node\Stmt\Function_ $function): bool
    {
        $pending = $function->stmts;
        while ($pending !== []) {
            $node = array_pop($pending);
            if ($node instanceof Node\Stmt\Global_) {
                return true;
            }
            if (! $node instanceof Node\FunctionLike) {
                array_push($pending, ...$this->childNodes($node));
            }
        }

        return false;
    }

    /**
     * The variables a node writes other than by a plain assignment to a variable: the
     * targets of a foreach, of destructuring, of a reference assignment on either side, of a
     * compound assignment, an increment or an array write, a static, global or catch
     * variable, an unset() variable, a variable a closure imports by reference, and a
     * variable passed to a call, which may take it by reference. The routes argument of a
     * group() call on the Route facade or another receiver {@see self::isRouteRoot()} knows
     * without tracked variables is only read.
     *
     * @return list<Node\Expr\Variable>
     */
    private function writtenVariables(Node $node): array
    {
        $targets = match (true) {
            $node instanceof Node\Expr\Assign => $node->var instanceof Node\Expr\Variable ? [] : [$node->var],
            $node instanceof Node\Expr\AssignRef => [$node->var, $node->expr],
            $node instanceof Node\Expr\AssignOp, $node instanceof Node\Expr\PreInc, $node instanceof Node\Expr\PostInc,
            $node instanceof Node\Expr\PreDec, $node instanceof Node\Expr\PostDec => [$node->var],
            $node instanceof Node\Stmt\Foreach_ => [$node->keyVar, $node->valueVar],
            $node instanceof Node\Stmt\Static_ => array_map(fn (Node\StaticVar $static): Node => $static->var, $node->vars),
            $node instanceof Node\Stmt\Global_, $node instanceof Node\Stmt\Unset_ => $node->vars,
            $node instanceof Node\Stmt\Catch_ => [$node->var],
            $node instanceof Node\Expr\Closure => array_map(
                fn (Node\ClosureUse $use): Node => $use->var,
                array_values(array_filter($node->uses, fn (Node\ClosureUse $use): bool => $use->byRef)),
            ),
            default => [],
        };

        if ($node instanceof Node\Expr\CallLike && ! $node->isFirstClassCallable()) {
            // Only a group on what is known to be the router reads its routes and nothing more
            $routes = $this->isGroupCall($node, []) ? $this->routesArgument($node->args) : null;
            foreach ($node->getArgs() as $arg) {
                if ($arg !== $routes) {
                    $targets[] = $arg->value;
                }
            }
        }

        $variables = [];
        while ($targets !== []) {
            $target = array_pop($targets);
            if ($target instanceof Node\Expr\Variable) {
                $variables[] = $target;
            } elseif ($target instanceof Node\Expr\List_ || $target instanceof Node\Expr\Array_) {
                foreach ($target->items as $item) {
                    if ($item instanceof Node\Expr\ArrayItem) {
                        $targets[] = $item->value;
                    }
                }
            } elseif ($target instanceof Node\Expr\ArrayDimFetch) {
                $targets[] = $target->var;
            }
        }

        return $variables;
    }

    /**
     * Whether a node is $this->loadRoutesFrom(...), as a service provider calls it. The name
     * is matched case-insensitively, as PHP calls methods.
     *
     * @phpstan-assert-if-true MethodCall $node
     */
    private function isLoadRoutesFrom(Node $node): bool
    {
        return $node instanceof MethodCall
            && $node->var instanceof Node\Expr\Variable
            && $node->var->name === 'this'
            && $node->name instanceof Identifier
            && $node->name->toLowerString() === 'loadroutesfrom';
    }

    /**
     * @return list<Node>
     */
    private function childNodes(Node $node): array
    {
        $children = [];
        foreach ($node->getSubNodeNames() as $name) {
            foreach (is_array($node->$name) ? $node->$name : [$node->$name] as $child) {
                if ($child instanceof Node) {
                    $children[] = $child;
                }
            }
        }

        return $children;
    }

    /**
     * The variables that hold the router inside a function: parameters typed Router or
     * Registrar, the first parameter of a group callback, which Laravel calls with the
     * router, and router variables a closure captures through use(). An arrow function
     * sees its parent's variables by value.
     *
     * @param  array<string, true>  $outer  The router variables of the enclosing scope
     * @return array<string, true>
     */
    private function functionRouters(Node\FunctionLike $function, array $outer, bool $callback): array
    {
        $routers = $function instanceof Node\Expr\ArrowFunction ? $outer : [];
        if ($function instanceof Node\Expr\Closure) {
            foreach ($function->uses as $use) {
                if (is_string($use->var->name) && isset($outer[$use->var->name])) {
                    $routers[$use->var->name] = true;
                }
            }
        }

        foreach ($function->getParams() as $index => $param) {
            if ($param->var instanceof Node\Expr\Variable && is_string($param->var->name)
                && (($index === 0 && $callback) || $this->namesRouterClass($param->type))) {
                $routers[$param->var->name] = true;
            }
        }

        return $routers;
    }

    /**
     * Whether a type or class name is one the container resolves the router as, or a
     * nullable, union or intersection type naming one.
     */
    private function namesRouterClass(?Node $name): bool
    {
        if ($name instanceof Node\NullableType) {
            return $this->namesRouterClass($name->type);
        }

        if ($name instanceof Node\UnionType || $name instanceof Node\IntersectionType) {
            foreach ($name->types as $type) {
                if ($this->namesRouterClass($type)) {
                    return true;
                }
            }

            return false;
        }

        if (! $name instanceof Node\Name) {
            return false;
        }
        $resolved = $name->getAttribute('resolvedName');

        return in_array(($resolved instanceof Node\Name ? $resolved : $name)->toString(), self::ROUTER_CLASSES, true);
    }

    /**
     * The existing route file a group argument names by path, __DIR__.'/...' or
     * base_path('...'), or null. A bare string is not read: Router::loadRoutes()
     * requires it from the include path, not the declaring file's directory.
     *
     * @internal An implementation detail of csrf-protection and of this class itself, outside this package's backward-compatibility promise.
     */
    public function groupRouteFile(Node\Expr $expr, string $dir): ?string
    {
        $path = $expr instanceof String_ ? null : $this->resolveWithRoutingPath($expr, $dir);
        $normalized = $path === null ? null : $this->normalizePath($path);

        return $normalized !== null && file_exists($normalized) ? $normalized : null;
    }

    /**
     * Whether a node is a group(...) call on the router: Route::group(...), or ->group(...)
     * at the end of a chain the router starts (see {@see self::chainOnRouter()}). The name
     * is matched case-insensitively, as PHP calls methods.
     *
     * @param  array<string, true>  $routers  Variables that hold the router in this scope
     *
     * @phpstan-assert-if-true MethodCall|StaticCall $node
     */
    private function isGroupCall(Node $node, array $routers): bool
    {
        return ($node instanceof MethodCall || $node instanceof StaticCall)
            && $node->name instanceof Identifier
            && $node->name->toLowerString() === 'group'
            && $this->chainOnRouter($node instanceof MethodCall ? $node->var : $node, $routers);
    }

    /**
     * Whether a call chain is made on the router: one of its links, or the class of a
     * static call it starts at, is the router (see {@see self::isRouteRoot()}). A chain
     * on Route::middleware(...) holds the router's registrar, whose calls register routes.
     *
     * @param  array<string, true>  $routers
     */
    private function chainOnRouter(Node $node, array $routers): bool
    {
        while (true) {
            if ($this->isRouteRoot($node, $routers)) {
                return true;
            }
            if ($node instanceof MethodCall) {
                $node = $node->var;

                continue;
            }

            return $node instanceof StaticCall && $this->isRouteRoot($node->class, $routers);
        }
    }

    /**
     * Whether a node is the router: the Route facade, by the name as written or the name
     * an import resolves it to, so an aliased import counts; a $router variable or one of
     * $routers; $this->router; or the container's router, reached as app('router'),
     * resolve(Router::class), App::make('router'), or on the container ($this->app, $app,
     * app() or Container::getInstance()) through ['router'], ->router, ->make(...),
     * ->get(...) or ->makeWith(...), given 'router', Router::class or Registrar::class.
     *
     * @param  array<string, true>  $routers
     */
    private function isRouteRoot(Node $root, array $routers): bool
    {
        if ($root instanceof Node\Name) {
            $resolved = $root->getAttribute('resolvedName');

            return strcasecmp($root->getLast(), 'Route') === 0
                || ($resolved instanceof Node\Name && strcasecmp($resolved->getLast(), 'Route') === 0);
        }

        if ($root instanceof Node\Expr\Variable) {
            return is_string($root->name) && ($root->name === 'router' || isset($routers[$root->name]));
        }

        if ($root instanceof Node\Expr\PropertyFetch) {
            return $root->name instanceof Identifier && $root->name->toLowerString() === 'router'
                && (($root->var instanceof Node\Expr\Variable && $root->var->name === 'this') || $this->isContainer($root->var));
        }

        if ($root instanceof Node\Expr\ArrayDimFetch) {
            return $this->isContainer($root->var) && $this->namesRouter($root->dim);
        }

        if ($root instanceof FuncCall) {
            return $this->isFunction($root, ['app', 'resolve']) && $this->namesRouter($this->firstArgument($root));
        }

        $resolves = ($root instanceof MethodCall || $root instanceof StaticCall)
            && $root->name instanceof Identifier
            && in_array($root->name->toLowerString(), ['make', 'get', 'makewith'], true)
            && $this->namesRouter($this->firstArgument($root));

        return $resolves && (($root instanceof MethodCall && $this->isContainer($root->var))
            || ($root instanceof StaticCall && $root->class instanceof Node\Name && strcasecmp($this->resolvedLast($root->class), 'App') === 0));
    }

    /**
     * Whether an expression is the application container: $this->app, $this->container,
     * $app, $container, app() or Container::getInstance().
     */
    private function isContainer(Node $expr): bool
    {
        if ($expr instanceof Node\Expr\Variable) {
            return in_array($expr->name, ['app', 'container'], true);
        }

        if ($expr instanceof Node\Expr\PropertyFetch) {
            return $expr->var instanceof Node\Expr\Variable && $expr->var->name === 'this'
                && $expr->name instanceof Identifier && in_array($expr->name->toLowerString(), ['app', 'container'], true);
        }

        if ($expr instanceof FuncCall) {
            return $this->isFunction($expr, ['app']) && $expr->args === [];
        }

        return $expr instanceof StaticCall && $expr->class instanceof Node\Name
            && strcasecmp($this->resolvedLast($expr->class), 'Container') === 0
            && $expr->name instanceof Identifier && $expr->name->toLowerString() === 'getinstance';
    }

    /**
     * The last segment of a class name as an import resolves it, or as written.
     */
    private function resolvedLast(Node\Name $name): string
    {
        $resolved = $name->getAttribute('resolvedName');

        return ($resolved instanceof Node\Name ? $resolved : $name)->getLast();
    }

    /**
     * @param  list<string>  $names  Lowercase function names
     */
    private function isFunction(FuncCall $call, array $names): bool
    {
        return $call->name instanceof Node\Name && in_array(ltrim($call->name->toLowerString(), '\\'), $names, true);
    }

    private function firstArgument(FuncCall|MethodCall|StaticCall $call): ?Node\Expr
    {
        $first = $call->args[0] ?? null;

        return $first instanceof Node\Arg ? $first->value : null;
    }

    /**
     * Whether a value is the router's container binding: 'router', Router::class or
     * Registrar::class.
     */
    private function namesRouter(?Node\Expr $value): bool
    {
        if ($value instanceof String_) {
            return $value->value === 'router' || in_array(ltrim($value->value, '\\'), self::ROUTER_CLASSES, true);
        }

        return $value instanceof Node\Expr\ClassConstFetch
            && $value->name instanceof Identifier && $value->name->toLowerString() === 'class'
            && $this->namesRouterClass($value->class);
    }

    /**
     * The normalized absolute path of an existing file a require/include in $dir loads,
     * or null when the path cannot be read or the file does not exist.
     *
     * @internal An implementation detail of csrf-protection and of this class itself, outside this package's backward-compatibility promise.
     */
    public function includedFile(Include_ $include, string $dir): ?string
    {
        $path = $this->resolveIncludePath($include->expr, $dir);

        return $path !== null && file_exists($path) ? $this->normalizePath($path) : null;
    }

    /**
     * Finds route files registered with a throttle middleware on their group
     * inside bootstrap/app.php.
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithThrottleMiddlewareInBootstrap(): array
    {
        return $this->getFilesRegisteredWithThrottleMiddlewareInFile(
            $this->basePath.'/bootstrap/app.php'
        );
    }

    /**
     * Finds route files registered with a throttle middleware on their group
     * in any PHP file under app/Providers/.
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithThrottleMiddlewareInProvidersDir(): array
    {
        $providersDir = $this->basePath.'/app/Providers';
        if (! is_dir($providersDir)) {
            return [];
        }

        $found = [];
        foreach (glob($providersDir.'/*.php') ?: [] as $file) {
            $found = array_merge($found, $this->getFilesRegisteredWithThrottleMiddlewareInFile($file));
        }

        return $found;
    }

    /**
     * Finds route files registered with a throttle middleware on their group in the
     * given PHP file, as {@see self::groupRegistrations()} reads them, unless the groups
     * exclude it by its exact name (see {@see self::groupsThrottle()}).
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithThrottleMiddlewareInFile(string $filePath): array
    {
        $found = [];
        foreach ($this->groupRegistrations($filePath) as $registration) {
            if ($this->groupsThrottle($registration['calls'])) {
                $found[] = $registration['file'];
            }
        }

        return $found;
    }

    /**
     * The middleware the ->$method(...) calls (lowercase) in a group's registrar chain
     * apply, such as ->middleware('web'), ->middleware('auth', 'web') or
     * ->withoutMiddleware(['web']), which reads only its first argument. Every
     * ->withoutMiddleware() call counts, as RouteRegistrar merges them; only the last
     * ->middleware() call does, as each middleware() call replaces the last. Walking the
     * chain inward, that is the first one met.
     *
     * @return array<Node\Expr>
     */
    private function chainEntries(Node $node, string $method): array
    {
        $entries = [];
        while ($node instanceof MethodCall || $node instanceof StaticCall) {
            if ($node->name instanceof Identifier && $node->name->toLowerString() === $method) {
                if ($method !== 'withoutmiddleware') {
                    return $this->middlewareEntries($node);
                }
                array_push($entries, ...$this->excludedEntries($node));
            }
            if (! $node instanceof MethodCall) {
                break;
            }
            $node = $node->var;
        }

        return $entries;
    }

    /**
     * The middleware a ->withoutMiddleware(...) call excludes: its first argument, a list or
     * one middleware, as Route::withoutMiddleware() wraps it and RouteRegistrar passes it on.
     * Later arguments are dropped.
     *
     * @return array<Node\Expr>
     */
    private function excludedEntries(StaticCall|MethodCall $call): array
    {
        $first = $call->args[0] ?? null;
        if (! $first instanceof Node\Arg) {
            return [];
        }

        if (! $first->value instanceof Node\Expr\Array_) {
            return [$first->value];
        }

        $entries = [];
        foreach ($first->value->items as $item) {
            if ($item instanceof Node\Expr\ArrayItem) {
                $entries[] = $item->value;
            }
        }

        return $entries;
    }

    /**
     * The middleware a ->middleware(...) call registers, read as Laravel's Router and
     * RouteRegistrar read their arguments: a leading array is the whole list and any
     * later arguments are dropped; otherwise every argument is one middleware.
     *
     * @return array<Node\Expr>
     *
     * @internal An implementation detail of csrf-protection and of this class itself, outside this package's backward-compatibility promise.
     */
    public function middlewareEntries(StaticCall|MethodCall $call): array
    {
        $firstArg = $call->args[0] ?? null;
        if ($firstArg instanceof Node\Arg && $firstArg->value instanceof Node\Expr\Array_) {
            $entries = [];
            foreach ($firstArg->value->items as $item) {
                if ($item instanceof Node\Expr\ArrayItem) {
                    $entries[] = $item->value;
                }
            }

            return $entries;
        }

        $entries = [];
        foreach ($call->args as $arg) {
            if ($arg instanceof Node\Arg) {
                $entries[] = $arg->value;
            }
        }

        return $entries;
    }

    /**
     * Extracts the file path from a base_path('routes/X.php') expression.
     */
    private function extractBasePathArgument(Node $node): ?string
    {
        if (! ($node instanceof FuncCall)) {
            return null;
        }

        $name = $node->name;
        if (! ($name instanceof Node\Name) || (string) $name !== 'base_path') {
            return null;
        }

        $firstArg = $node->args[0] ?? null;
        if (! ($firstArg instanceof Node\Arg)) {
            return null;
        }

        $arg = $firstArg->value;
        if (! ($arg instanceof String_)) {
            return null;
        }

        return $this->basePath.'/'.ltrim($arg->value, '/');
    }

    /**
     * Resolves a require/include expression to an absolute path.
     * Handles __DIR__ . '/file.php', base_path('routes/file.php') and bare 'file.php' patterns.
     */
    private function resolveIncludePath(Node $expr, string $dir): ?string
    {
        // __DIR__ . '/auth.php'
        if ($expr instanceof Concat && $expr->left instanceof Dir && $expr->right instanceof String_) {
            return $dir.$expr->right->value;
        }

        // base_path('routes/auth.php')
        $basePath = $this->extractBasePathArgument($expr);
        if ($basePath !== null) {
            return $basePath;
        }

        // 'auth.php' (bare relative string)
        if ($expr instanceof String_) {
            $value = $expr->value;

            return str_starts_with($value, '/') ? $value : $dir.'/'.$value;
        }

        return null;
    }
}
