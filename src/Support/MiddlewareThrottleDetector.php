<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use Closure;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\Concerns\ResolvesClassNames;

/**
 * Detects a throttle that covers every route in a middleware group.
 *
 * A group is covered by a throttle it lists itself or by one on the global stack, which
 * runs on every route in every group. Both are read from app/Http/Kernel.php (Laravel 10
 * and earlier) and from the withMiddleware() configurator in bootstrap/app.php (Laravel
 * 11+). Class names are resolved against each file's imports, so an aliased import of
 * ThrottleRequests reads as the class it names.
 *
 * Which middleware names throttle is decided by name, never by what a name contains: an
 * alias the app registers, such as 'signin.cap', can name ThrottleRequests, and a class
 * such as ThrottleRequestsLogger need not be one. A caller that reads the app's aliases
 * passes a judge that resolves them.
 */
class MiddlewareThrottleDetector
{
    use ResolvesClassNames;

    /**
     * The framework's throttle middleware: ThrottleRequests, which the 'throttle'
     * alias names, and the Redis-backed variant.
     */
    public const THROTTLE_MIDDLEWARE = [
        'Illuminate\\Routing\\Middleware\\ThrottleRequests',
        'Illuminate\\Routing\\Middleware\\ThrottleRequestsWithRedis',
    ];

    /**
     * Name-resolved ASTs, keyed by path, for this instance.
     *
     * @var array<string, array<Node>>
     */
    private array $resolved = [];

    /**
     * The judge, $nameThrottles, says whether one middleware name throttles. It is handed
     * a string as written ('throttle:60,1', 'signin.cap'), or a class reference fully
     * qualified with a leading backslash, so it never reads as an alias. Without a judge,
     * only the framework's classes and the 'throttle' alias Laravel registers count.
     *
     * @param  (Closure(string): bool)|null  $nameThrottles
     */
    public function __construct(
        private readonly string $basePath,
        private readonly ParserInterface $parser,
        private readonly ?Closure $nameThrottles = null,
    ) {}

    /**
     * Whether a throttle covers every route in any of the given groups: one the group
     * lists, or one on the global stack.
     *
     * @param  array<int, string>  $groups
     */
    public function throttlesGroups(array $groups): bool
    {
        return $this->kernelThrottles($groups) || $this->bootstrapThrottles($groups);
    }

    /**
     * Whether a middleware expression is, or (as an array) lists, a throttle:
     * 'throttle:60,1', ThrottleRequests::class, ThrottleRequests::class.':60,1',
     * ThrottleRequests::using('login') or ThrottleRequests::with(5, 1), or an app
     * alias the judge resolves to one.
     *
     * A class name is read from its resolvedName attribute when there is one, so pass
     * a tree resolveNamesForMatching() has seen for aliased imports to count. Without
     * it a name is read as written: a short ThrottleRequests names \ThrottleRequests.
     */
    public function expressionIsThrottle(Expr $expr): bool
    {
        if ($expr instanceof Expr\Array_) {
            foreach ($expr->items as $item) {
                if ($item instanceof Expr\ArrayItem && $this->expressionIsThrottle($item->value)) {
                    return true;
                }
            }

            return false;
        }

        $name = $this->middlewareName($expr);

        return $name !== null && $this->nameThrottles($name);
    }

    /**
     * Whether the Kernel's global $middleware, or its $middlewareGroups entry for one
     * of the given groups, carries a throttle.
     *
     * @param  array<int, string>  $groups
     */
    private function kernelThrottles(array $groups): bool
    {
        foreach ($this->parser->findNodes($this->resolvedAst('app/Http/Kernel.php'), Node\Stmt\Property::class) as $property) {
            foreach ($property instanceof Node\Stmt\Property ? $property->props : [] as $prop) {
                if (! $prop->default instanceof Expr\Array_) {
                    continue;
                }

                $name = $prop->name->toString();

                if ($name === 'middleware' && $this->expressionIsThrottle($prop->default)) {
                    return true;
                }

                if ($name !== 'middlewareGroups') {
                    continue;
                }

                foreach ($prop->default->items as $item) {
                    if ($item instanceof Expr\ArrayItem
                        && $item->key instanceof String_
                        && in_array($item->key->value, $groups, true)
                        && $this->expressionIsThrottle($item->value)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Whether a Middleware configurator call in bootstrap/app.php throttles the global
     * stack or one of the given groups.
     *
     * @param  array<int, string>  $groups
     */
    private function bootstrapThrottles(array $groups): bool
    {
        foreach ($this->parser->findNodes($this->resolvedAst('bootstrap/app.php'), Expr\MethodCall::class) as $call) {
            if ($call instanceof Expr\MethodCall
                && $call->name instanceof Identifier
                && $this->chainStartsAtVariable($call->var)
                && $this->middlewareCallThrottlesGroup($call, $call->name->toLowerString(), $groups)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a call's receiver is the configurator variable, directly
     * ($middleware->web(...)) or through a chain ($middleware->alias([...])->web(...)).
     * Every Middleware method returns the configurator, so a chain keeps configuring it.
     */
    private function chainStartsAtVariable(Expr $expr): bool
    {
        while ($expr instanceof Expr\MethodCall) {
            $expr = $expr->var;
        }

        return $expr instanceof Expr\Variable;
    }

    /**
     * Whether one Middleware configurator call adds a throttle that covers one of the
     * given groups:
     * - append(...) / prepend(...) / use([...]), the global stack
     * - appendToGroup(group, ...) / prependToGroup(group, ...) / group(group, [...])
     * - web(append: [...]) / api(prepend: [...], replace: [...])
     * - throttleApi(), for the api group only
     *
     * @param  array<int, string>  $groups
     */
    private function middlewareCallThrottlesGroup(Expr\MethodCall $call, string $method, array $groups): bool
    {
        switch ($method) {
            // throttleApi() injects throttle:api into the api group at runtime (with
            // or without arguments). There is no throttleWeb() equivalent, and
            // throttleWithRedis() merely swaps the driver, so it must not count.
            case 'throttleapi':
                return in_array('api', $groups, true);

            case 'append':
            case 'prepend':
            case 'use':
                $middleware = $this->callArgument($call, 0, 'middleware');

                return $middleware !== null && $this->expressionIsThrottle($middleware);

            case 'appendtogroup':
            case 'prependtogroup':
            case 'group':
                $groupName = $this->callArgument($call, 0, 'group');
                $middleware = $this->callArgument($call, 1, 'middleware');

                return $groupName instanceof String_
                    && in_array($groupName->value, $groups, true)
                    && $middleware !== null
                    && $this->expressionIsThrottle($middleware);

            case 'web':
            case 'api':
                if (! in_array($method, $groups, true)) {
                    return false;
                }

                // web(append, prepend, remove, replace): a throttle under remove:
                // takes it out of the group, so only the other three count.
                foreach (['append' => 0, 'prepend' => 1, 'replace' => 3] as $name => $position) {
                    $middleware = $this->callArgument($call, $position, $name);
                    if ($middleware !== null && $this->expressionIsThrottle($middleware)) {
                        return true;
                    }
                }
        }

        return false;
    }

    /**
     * The value of a call argument, given by name or by position.
     */
    private function callArgument(Expr\MethodCall $call, int $position, string $name): ?Expr
    {
        foreach ($call->args as $index => $arg) {
            if (! $arg instanceof Node\Arg) {
                continue;
            }

            if ($arg->name !== null ? $arg->name->toString() === $name : $index === $position) {
                return $arg->value;
            }
        }

        return null;
    }

    /**
     * The name a middleware value hands the router: a string as written, or a class
     * reference fully qualified with a leading backslash, for X::class,
     * X::class.':params' and X::using(...) / X::with(...), which build the
     * 'Class:params' string. Null for anything else.
     */
    private function middlewareName(Expr $expr): ?string
    {
        if ($expr instanceof String_) {
            return $expr->value;
        }

        if ($expr instanceof Expr\BinaryOp\Concat) {
            return $this->middlewareName($expr->left);
        }

        if ($expr instanceof Expr\ClassConstFetch
            && $expr->class instanceof Name
            && $expr->name instanceof Identifier
            && $expr->name->toLowerString() === 'class') {
            return '\\'.$this->className($expr->class);
        }

        if ($expr instanceof Expr\StaticCall
            && $expr->class instanceof Name
            && $expr->name instanceof Identifier
            && in_array($expr->name->toLowerString(), ['using', 'with'], true)) {
            return '\\'.$this->className($expr->class);
        }

        return null;
    }

    /**
     * Whether a middleware name throttles, by the caller's judge or, without one, by
     * the framework's own names.
     */
    private function nameThrottles(string $name): bool
    {
        if ($this->nameThrottles !== null) {
            return ($this->nameThrottles)($name);
        }

        $class = ltrim((string) strtok($name, ':'), '\\');

        return $class === 'throttle' || in_array($class, self::THROTTLE_MIDDLEWARE, true);
    }

    /**
     * The fully qualified name a class reference resolves to, or the name as written
     * when the tree was not resolved.
     */
    private function className(Name $name): string
    {
        $resolved = $name->getAttribute('resolvedName');

        return ($resolved instanceof Name ? $resolved : $name)->toString();
    }

    /**
     * A file under the base path, parsed and name-resolved once per instance; empty
     * when the file does not exist.
     *
     * @return array<Node>
     */
    private function resolvedAst(string $relativePath): array
    {
        $path = $this->basePath.DIRECTORY_SEPARATOR.str_replace('/', DIRECTORY_SEPARATOR, $relativePath);

        if (! isset($this->resolved[$path])) {
            $this->resolved[$path] = file_exists($path)
                ? $this->resolveNamesForMatching($this->parser->parseFile($path))
                : [];
        }

        return $this->resolved[$path];
    }
}
