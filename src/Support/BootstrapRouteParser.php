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
 *      in bootstrap/app.php's withRouting(then: ...) callback
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
        )));
    }

    /**
     * Returns absolute paths of route files registered under the 'api' middleware group
     * through external registration (require from api.php, or bootstrap/app.php).
     *
     * @return array<string>
     */
    public function getApiRegisteredRouteFiles(): array
    {
        return array_values(array_unique(array_merge(
            $this->getFilesRequiredFromApiPhp(),
            $this->getFilesRegisteredWithApiMiddlewareInBootstrap(),
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
                $found[] = $path;
            }
        }

        return $found;
    }

    /**
     * Finds route files registered via Route::middleware('web')->group(base_path('...'))
     * inside bootstrap/app.php's withRouting(then: ...) callback.
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithWebMiddlewareInBootstrap(): array
    {
        return $this->getFilesRegisteredWithMiddlewareInBootstrap('web');
    }

    /**
     * Finds route files registered via Route::middleware('api')->group(base_path('...'))
     * inside bootstrap/app.php's withRouting(then: ...) callback.
     * Supports both string and array middleware, e.g.:
     *   ->middleware('api')
     *   ->middleware(['api', 'throttle:api.rest'])
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithApiMiddlewareInBootstrap(): array
    {
        return $this->getFilesRegisteredWithMiddlewareInBootstrap('api');
    }

    /**
     * Finds route files registered via Route::middleware(...)->group(base_path('...'))
     * inside bootstrap/app.php, matching a specific middleware name.
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithMiddlewareInBootstrap(string $middlewareName): array
    {
        $bootstrapPath = $this->basePath.'/bootstrap/app.php';
        if (! file_exists($bootstrapPath)) {
            return [];
        }

        $ast = $this->parser->parseFile($bootstrapPath);
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
            $filePath = $this->extractBasePathArgument($firstArg->value);
            if ($filePath === null) {
                continue;
            }

            // Walk the chain to check the specified middleware is present
            if ($this->chainContainsMiddleware($call->var, $middlewareName)) {
                $found[] = $filePath;
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
