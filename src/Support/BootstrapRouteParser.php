<?php

declare(strict_types=1);

namespace ShieldCI\Support;

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

/**
 * Detects route files covered by web or API middleware through external registration.
 *
 * Two sources are checked per middleware group:
 *   1. Files require'd/include'd from routes/web.php or routes/api.php
 *      (inherit that file's middleware group automatically)
 *   2. Files registered via Route::middleware('web|api')->...->group(base_path('...'))
 *      in bootstrap/app.php's withRouting(then: ...) callback or in app/Providers/*.php
 */
class BootstrapRouteParser
{
    public function __construct(
        private readonly string $basePath,
        private readonly ParserInterface $parser,
    ) {}

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
     * Returns absolute paths of route files registered with a throttle middleware
     * directly on their group in bootstrap/app.php or app/Providers/*.php.
     *
     * Matches any throttle variant: 'throttle:5,1', 'throttle:api.rest', etc.
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
     * Finds route files registered via Route::middleware('web')->group(base_path('...'))
     * inside bootstrap/app.php's withRouting(then: ...) callback.
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
     * Finds route files registered via Route::middleware('api')->group(base_path('...'))
     * inside bootstrap/app.php's withRouting(then: ...) callback.
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
     * Finds route files registered via Route::middleware('web')->group(base_path('...'))
     * in any PHP file under app/Providers/ (e.g. RouteServiceProvider, RoutingServiceProvider).
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithWebMiddlewareInProvidersDir(): array
    {
        return $this->getFilesRegisteredWithMiddlewareInProvidersDir('web');
    }

    /**
     * Finds route files registered via Route::middleware('api')->group(base_path('...'))
     * in any PHP file under app/Providers/.
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithApiMiddlewareInProvidersDir(): array
    {
        return $this->getFilesRegisteredWithMiddlewareInProvidersDir('api');
    }

    /**
     * Scans all PHP files in app/Providers/ for Route::middleware(...)->group(base_path(...))
     * chains matching the given middleware name.
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
     * Finds route files registered via Route::middleware(middlewareName)->group(base_path('...'))
     * in the given PHP file. Supports both string and array middleware forms.
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithMiddlewareInFile(string $filePath, string $middlewareName): array
    {
        if (! file_exists($filePath)) {
            return [];
        }

        $ast = $this->parser->parseFile($filePath);
        if (empty($ast)) {
            return [];
        }

        $found = [];
        $groupCalls = $this->parser->findMethodCalls($ast, 'group');

        foreach ($groupCalls as $call) {
            if (! ($call instanceof MethodCall)) {
                continue;
            }

            $firstArg = $call->args[0] ?? null;
            if (! ($firstArg instanceof Node\Arg)) {
                continue;
            }

            // Arg must be base_path('routes/X.php')
            $routeFile = $this->extractBasePathArgument($firstArg->value);
            if ($routeFile === null) {
                continue;
            }

            // Walk the chain to check the specified middleware is present
            if ($this->chainContainsMiddleware($call->var, $middlewareName)) {
                $normalized = $this->normalizePath($routeFile);
                if ($normalized !== null) {
                    $found[] = $normalized;
                }
            }
        }

        return $found;
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
     * Finds route files registered with a throttle middleware on their group
     * in the given PHP file.
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithThrottleMiddlewareInFile(string $filePath): array
    {
        if (! file_exists($filePath)) {
            return [];
        }

        $ast = $this->parser->parseFile($filePath);
        if (empty($ast)) {
            return [];
        }

        $found = [];
        $groupCalls = $this->parser->findMethodCalls($ast, 'group');

        foreach ($groupCalls as $call) {
            if (! ($call instanceof MethodCall)) {
                continue;
            }

            $firstArg = $call->args[0] ?? null;
            if (! ($firstArg instanceof Node\Arg)) {
                continue;
            }

            $routeFile = $this->extractBasePathArgument($firstArg->value);
            if ($routeFile === null) {
                continue;
            }

            if ($this->chainContainsThrottleMiddleware($call->var)) {
                $normalized = $this->normalizePath($routeFile);
                if ($normalized !== null) {
                    $found[] = $normalized;
                }
            }
        }

        return $found;
    }

    /**
     * Walks a method-call chain (right to left) looking for ->middleware(name)
     * or Route::middleware(name) anywhere in the chain.
     *
     * Supports both string and array forms:
     *   ->middleware('web')
     *   ->middleware(['web', 'throttle:60,1'])
     */
    private function chainContainsMiddleware(Node $node, string $middlewareName): bool
    {
        if ($node instanceof StaticCall || $node instanceof MethodCall) {
            if ($node->name instanceof Identifier && $node->name->name === 'middleware') {
                $firstArg = $node->args[0] ?? null;
                if ($firstArg instanceof Node\Arg) {
                    $arg = $firstArg->value;
                    // ->middleware('web')
                    if ($arg instanceof String_ && $arg->value === $middlewareName) {
                        return true;
                    }
                    // ->middleware(['web', 'throttle:api.rest'])
                    if ($arg instanceof Node\Expr\Array_) {
                        foreach ($arg->items as $item) {
                            if ($item instanceof Node\Expr\ArrayItem
                                && $item->value instanceof String_
                                && $item->value->value === $middlewareName) {
                                return true;
                            }
                        }
                    }
                }
            }
            if ($node instanceof MethodCall) {
                return $this->chainContainsMiddleware($node->var, $middlewareName);
            }
        }

        return false;
    }

    /**
     * Walks a method-call chain (right to left) looking for ->middleware(...)
     * where any value starts with 'throttle' (matches 'throttle:5,1', 'throttle:api.rest', etc.).
     *
     * Supports both string and array forms:
     *   ->middleware('throttle:5,1')
     *   ->middleware(['api', 'throttle:api.rest'])
     */
    private function chainContainsThrottleMiddleware(Node $node): bool
    {
        if ($node instanceof StaticCall || $node instanceof MethodCall) {
            if ($node->name instanceof Identifier && $node->name->name === 'middleware') {
                $firstArg = $node->args[0] ?? null;
                if ($firstArg instanceof Node\Arg) {
                    $arg = $firstArg->value;
                    // ->middleware('throttle:5,1')
                    if ($arg instanceof String_ && str_starts_with($arg->value, 'throttle')) {
                        return true;
                    }
                    // ->middleware(['api', 'throttle:api.rest'])
                    if ($arg instanceof Node\Expr\Array_) {
                        foreach ($arg->items as $item) {
                            if ($item instanceof Node\Expr\ArrayItem
                                && $item->value instanceof String_
                                && str_starts_with($item->value->value, 'throttle')) {
                                return true;
                            }
                        }
                    }
                }
            }
            if ($node instanceof MethodCall) {
                return $this->chainContainsThrottleMiddleware($node->var);
            }
        }

        return false;
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
