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
 * Detects route files that are covered by web middleware through external registration.
 *
 * Two sources are checked:
 *   1. Files require'd/include'd from routes/web.php (inherit web middleware automatically)
 *   2. Files registered via Route::middleware('web')->...->group(base_path('...'))
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
     * Finds route files require'd/include'd from routes/web.php.
     * These inherit the 'web' middleware group automatically.
     *
     * @return array<string>
     */
    private function getFilesRequiredFromWebPhp(): array
    {
        $webPhpPath = $this->basePath.'/routes/web.php';
        if (! file_exists($webPhpPath)) {
            return [];
        }

        $ast = $this->parser->parseFile($webPhpPath);
        if (empty($ast)) {
            return [];
        }

        $protected = [];
        $includes = $this->parser->findNodes($ast, Include_::class);

        foreach ($includes as $include) {
            if (! ($include instanceof Include_)) {
                continue;
            }
            $path = $this->resolveIncludePath($include->expr, dirname($webPhpPath));
            if ($path !== null && file_exists($path)) {
                $protected[] = $path;
            }
        }

        return $protected;
    }

    /**
     * Finds route files registered via Route::middleware('web')->group(base_path('...'))
     * inside bootstrap/app.php's withRouting(then: ...) callback.
     *
     * @return array<string>
     */
    private function getFilesRegisteredWithWebMiddlewareInBootstrap(): array
    {
        $bootstrapPath = $this->basePath.'/bootstrap/app.php';
        if (! file_exists($bootstrapPath)) {
            return [];
        }

        $ast = $this->parser->parseFile($bootstrapPath);
        if (empty($ast)) {
            return [];
        }

        $protected = [];
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

            // Walk the chain to check Route::middleware('web') is present
            if ($this->chainContainsWebMiddleware($call->var)) {
                $protected[] = $filePath;
            }
        }

        return $protected;
    }

    /**
     * Walks a method-call chain (right to left) looking for ->middleware('web')
     * or Route::middleware('web') anywhere in the chain.
     */
    private function chainContainsWebMiddleware(Node $node): bool
    {
        if ($node instanceof StaticCall || $node instanceof MethodCall) {
            if ($node->name instanceof Identifier && $node->name->name === 'middleware') {
                $firstArg = $node->args[0] ?? null;
                if ($firstArg instanceof Node\Arg) {
                    $arg = $firstArg->value;
                    if ($arg instanceof String_ && $arg->value === 'web') {
                        return true;
                    }
                }
            }
            if ($node instanceof MethodCall) {
                return $this->chainContainsWebMiddleware($node->var);
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
