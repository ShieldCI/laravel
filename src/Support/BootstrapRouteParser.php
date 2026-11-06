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
use PhpParser\NodeFinder;
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
 */
class BootstrapRouteParser
{
    use ResolvesClassNames;

    private readonly MiddlewareThrottleDetector $throttles;

    /** @var array<string, list<array{file: string, calls: non-empty-list<MethodCall|StaticCall>}>> */
    private array $registrations = [];

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
     */
    public function getGroupRegisteredRouteFiles(bool $routeFiles = true): array
    {
        $sources = [$this->basePath.'/bootstrap/app.php'];
        foreach ($routeFiles ? ['routes', 'app/Providers'] : ['app/Providers'] as $dir) {
            if (is_dir($this->basePath.'/'.$dir)) {
                $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->basePath.'/'.$dir, \FilesystemIterator::SKIP_DOTS));
                foreach ($files as $file) {
                    if ($file instanceof \SplFileInfo && $file->isFile() && $file->getExtension() === 'php') {
                        $sources[] = $file->getPathname();
                    }
                }
            }
        }

        $found = [];
        foreach ($sources as $source) {
            foreach ($this->groupRegistrations($source) as $registration) {
                $found[] = ['file' => $registration['file'], 'source' => $source, 'calls' => $registration['calls']];
            }
        }

        return $found;
    }

    /**
     * Returns the line ranges of throttled Route::...->group(Closure) blocks
     * declared inside the given route file. Covers both the fluent form
     * (Route::middleware([...'throttle'...])->group(fn)) and the array form
     * (Route::group(['middleware' => 'throttle...'], fn)), one range for each closure a
     * list passes, with the throttle variants
     * {@see self::getThrottleProtectedRouteFiles()} matches, and is nesting-safe:
     * overlapping ranges are returned as-is, so a route line inside any range
     * is treated as covered. Path-argument groups (->group(base_path(...))) open
     * no closure and are intentionally ignored here.
     *
     * @return array<int, array{start: int, end: int}>
     */
    public function getThrottledGroupLineRanges(string $filePath): array
    {
        if (! file_exists($filePath)) {
            return [];
        }

        $ast = $this->parser->parseFile($filePath);
        if (empty($ast)) {
            return [];
        }
        $ast = $this->resolveNamesForMatching($ast);

        $ranges = [];

        // Fluent form: Route::middleware([...'throttle'...])->group(function () {...}),
        // throttled on the chain; array form: Route::group(['middleware' =>
        // 'throttle...'], function () {...}), throttled in its attribute array.
        /** @var list<MethodCall|StaticCall> $calls */
        $calls = (new NodeFinder)->find($ast, $this->isGroupCall(...));
        foreach ($calls as $call) {
            $this->collectThrottledGroupRange(
                $call->args,
                $call instanceof MethodCall && $this->anyEntry($this->chainEntries($call->var, 'middleware'), $this->throttles->expressionIsThrottle(...)),
                $ranges,
            );
        }

        return $ranges;
    }

    /**
     * Records the closure argument's line range when the group is throttled —
     * either through its method chain ($chainThrottled) or a config-array argument.
     *
     * @param  array<Node>  $args  Raw argument list; only plain Args carry a value.
     * @param  array<int, array{start: int, end: int}>  $ranges
     */
    private function collectThrottledGroupRange(array $args, bool $chainThrottled, array &$ranges): void
    {
        $closures = $this->closureArguments($args);
        if ($closures !== [] && ($chainThrottled || $this->anyEntry($this->groupAttributeEntries($args, 'middleware'), $this->throttles->expressionIsThrottle(...)))) {
            foreach ($closures as $closure) {
                $ranges[] = ['start' => $closure->getStartLine(), 'end' => $closure->getEndLine()];
            }
        }
    }

    /**
     * The Closure/ArrowFunction callbacks a group() call loads, as {@see self::groupRoutes()}
     * reads them, in argument order.
     *
     * @param  array<Node>  $args  Raw argument list; only plain Args carry a value.
     * @return list<Node\Expr\Closure|Node\Expr\ArrowFunction>
     */
    public function closureArguments(array $args): array
    {
        return array_values(array_filter(
            $this->groupRoutes($args),
            fn (Node\Expr $entry): bool => $entry instanceof Node\Expr\Closure || $entry instanceof Node\Expr\ArrowFunction,
        ));
    }

    /**
     * What a group() call loads, as Router::group() reads its routes argument through
     * Arr::wrap(): each item of a list, or the value itself. The routes argument is the one
     * named routes: (Router::group()) or callback: (RouteRegistrar::group()), otherwise the
     * last positional one, as Router::group() takes its attribute array first. The other
     * arguments' values follow as they are, so an attribute array is never read as routes.
     *
     * @param  array<Node>  $args  Raw argument list; only plain Args carry a value.
     * @return list<Node\Expr>
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
            true,
        );
    }

    /**
     * The route files groups in $filePath load that $judge says their groups apply to them:
     * a group enclosing the load names a matching middleware on its chain,
     * ->middleware(...), or in its 'middleware' attribute. Laravel merges the middleware
     * down nested groups. With $exclusionWins, a group that excludes a matching middleware
     * through ->withoutMiddleware(...) or its 'excluded_middleware' attribute drops the file.
     *
     * @param  Closure(Node\Expr): bool  $judge
     * @return array<string>
     */
    private function filesGroupsApply(string $filePath, Closure $judge, bool $exclusionWins): array
    {
        $found = [];
        foreach ($this->groupRegistrations($filePath) as $registration) {
            $applied = false;
            foreach ($registration['calls'] as $call) {
                if ($exclusionWins && $this->anyEntry($this->groupEntries($call, 'withoutmiddleware', 'excluded_middleware'), $judge)) {
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
     * (lowercase) and under $attributeKey in its attribute array.
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
        if (! isset($this->registrations[$source])) {
            $found = [];
            if (file_exists($source)) {
                foreach ($this->resolveNamesForMatching($this->parser->parseFile($source)) as $node) {
                    $this->collectGroupRegistrations($node, [], dirname($source), $found);
                }
            }
            $this->registrations[$source] = $found;
        }

        return $this->registrations[$source];
    }

    /**
     * @param  list<MethodCall|StaticCall>  $groups  The group calls enclosing $node, outermost first
     * @param  list<array{file: string, calls: non-empty-list<MethodCall|StaticCall>}>  $found
     */
    private function collectGroupRegistrations(Node $node, array $groups, string $dir, array &$found): void
    {
        if ($node instanceof Include_ && $groups !== []) {
            $path = $this->includedFile($node, $dir);
            if ($path !== null) {
                $found[] = ['file' => $path, 'calls' => $groups];
            }
        }

        if ($this->isGroupCall($node)) {
            $inner = [...$groups, $node];
            foreach ($this->groupRoutes($node->args) as $entry) {
                $path = $this->groupRouteFile($entry, $dir);
                if ($path !== null) {
                    $found[] = ['file' => $path, 'calls' => $inner];
                } else {
                    $this->collectGroupRegistrations($entry, $inner, $dir, $found);
                }
            }
            $children = [$node instanceof MethodCall ? $node->var : $node->class];
        } else {
            $children = [];
            foreach ($node->getSubNodeNames() as $name) {
                foreach (is_array($node->$name) ? $node->$name : [$node->$name] as $child) {
                    if ($child instanceof Node) {
                        $children[] = $child;
                    }
                }
            }
        }

        foreach ($children as $child) {
            $this->collectGroupRegistrations($child, $groups, $dir, $found);
        }
    }

    /**
     * The existing route file a group argument names by path, __DIR__.'/...' or
     * base_path('...'), or null. A bare string is not read: Router::loadRoutes()
     * requires it from the include path, not the declaring file's directory.
     */
    private function groupRouteFile(Node\Expr $expr, string $dir): ?string
    {
        $path = $expr instanceof String_ ? null : $this->resolveWithRoutingPath($expr, $dir);
        $normalized = $path === null ? null : $this->normalizePath($path);

        return $normalized !== null && file_exists($normalized) ? $normalized : null;
    }

    /**
     * Whether a node is a ->group(...) or Route::group(...) call, matched
     * case-insensitively, as PHP calls methods.
     *
     * @phpstan-assert-if-true MethodCall|StaticCall $node
     */
    private function isGroupCall(Node $node): bool
    {
        return ($node instanceof MethodCall || $node instanceof StaticCall)
            && $node->name instanceof Identifier
            && $node->name->toLowerString() === 'group';
    }

    /**
     * The normalized absolute path of an existing file a require/include in $dir loads,
     * or null when the path cannot be read or the file does not exist.
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
     * given PHP file, read as {@see self::filesGroupsApply()} reads them. Exclusion is
     * not read: Laravel excludes only the exact name, so excluding throttle:api leaves
     * throttle:login in place, and the throttle variants are not told apart here.
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithThrottleMiddlewareInFile(string $filePath): array
    {
        return $this->filesGroupsApply($filePath, $this->throttles->expressionIsThrottle(...), false);
    }

    /**
     * The middleware every ->$method(...) call (lowercase) in a method-call chain lists,
     * such as ->middleware('web'), ->middleware('auth', 'web') or
     * ->withoutMiddleware(['web']).
     *
     * @return array<Node\Expr>
     */
    private function chainEntries(Node $node, string $method): array
    {
        $entries = [];
        while ($node instanceof MethodCall || $node instanceof StaticCall) {
            if ($node->name instanceof Identifier && $node->name->toLowerString() === $method) {
                array_push($entries, ...$this->middlewareEntries($node));
            }
            if (! $node instanceof MethodCall) {
                break;
            }
            $node = $node->var;
        }

        return $entries;
    }

    /**
     * The middleware a ->middleware(...) call registers, read as Laravel's Router and
     * RouteRegistrar read their arguments: a leading array is the whole list and any
     * later arguments are dropped; otherwise every argument is one middleware.
     *
     * @return array<Node\Expr>
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
     * Handles __DIR__ . '/file.php' and bare 'file.php' patterns.
     */
    private function resolveIncludePath(Node $expr, string $dir): ?string
    {
        // __DIR__ . '/auth.php'
        if ($expr instanceof Concat && $expr->left instanceof Dir && $expr->right instanceof String_) {
            return $dir.$expr->right->value;
        }

        // 'auth.php' (bare relative string)
        if ($expr instanceof String_) {
            $value = $expr->value;

            return str_starts_with($value, '/') ? $value : $dir.'/'.$value;
        }

        return null;
    }
}
