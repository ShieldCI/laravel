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
use ShieldCI\Concerns\ReadsMiddlewareConfigurator;
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
    use ReadsMiddlewareConfigurator;
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

    private ?string $throttleAliasClass = null;

    /**
     * The judge, $nameThrottles, says whether one middleware name throttles. It is handed
     * a string as written ('throttle:60,1', 'signin.cap'), or a class reference fully
     * qualified with a leading backslash, so it never reads as an alias, followed by any
     * parameters X::class.':60,1', X::using(...) or X::with(...) give it. Without a judge,
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
        $throttles = $this->groupThrottleNames($groups);

        return $throttles['global'] || $throttles['names'] !== [];
    }

    /**
     * The throttles that reach every route in any of the given groups: whether the global
     * stack carries one, which no route can exclude, and the names the groups list, as
     * {@see self::middlewareNameWithParameters()} reads them, so a caller can tell which of
     * them a route excludes. Read from the Kernel's $middleware and $middlewareGroups
     * (Laravel 10 and earlier) and the withMiddleware() configurator (Laravel 11+).
     *
     * @param  array<int, string>  $groups
     * @return array{global: bool, names: list<string>}
     *
     * @internal Shared between this package's analyzers, outside its backward-compatibility promise.
     */
    public function groupThrottleNames(array $groups): array
    {
        $throttles = ['global' => false, 'names' => []];
        $this->collectKernelThrottles($groups, $throttles);
        $this->collectBootstrapThrottles($groups, $throttles);

        return $throttles;
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
     * Whether a throttle among the applied middleware entries survives the excluded ones.
     * Laravel's Router drops an applied middleware only when an excluded one resolves to
     * exactly the same name: the alias resolved to its class, with its parameters. So
     * excluding 'throttle:5,1' drops ThrottleRequests::class.':5,1', while excluding
     * 'throttle:api' or ThrottleRequests::class leaves 'throttle:5,1' in place.
     *
     * Only the 'throttle' alias is resolved; other aliases and middleware groups match as
     * written. Laravel also drops a parameterless subclass of an excluded class, which is
     * not read. An exclusion this cannot match leaves the throttle counted.
     *
     * @param  array<Expr>  $applied
     * @param  array<Expr>  $excluded
     */
    public function throttlesAfterExclusion(array $applied, array $excluded): bool
    {
        $removed = [];
        foreach ($this->listedNames($excluded) as $name) {
            $removed[$this->resolvedName($name)] = true;
        }

        foreach ($this->listedNames($applied) as $name) {
            if (! isset($removed[$this->resolvedName($name)]) && $this->nameThrottles($name)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The name a middleware value hands the router, with its parameters: a string as
     * written, or a class reference fully qualified with a leading backslash, followed by
     * the parameters X::class.':5,1', X::using('login') and X::with(5, 1) append. A part
     * that is not a literal reads as a parameter that equals no other, so it never matches
     * an exclusion. Null for a value that names no middleware.
     *
     * @internal Shared between this package's analyzers, outside its backward-compatibility promise.
     */
    public function middlewareNameWithParameters(Expr $expr): ?string
    {
        if ($expr instanceof Expr\BinaryOp\Concat) {
            $left = $this->middlewareNameWithParameters($expr->left);
            if ($left === null) {
                return null;
            }

            return $expr->right instanceof String_
                ? $left.$expr->right->value
                : $left.(str_contains($left, ':') ? '' : ':').self::unknownParameter($expr->right);
        }

        // ThrottleRequests::using($name) builds 'Class:'.$name, ::with(...) 'Class:' and its
        // arguments joined by commas
        if ($expr instanceof Expr\StaticCall
            && $expr->class instanceof Name
            && $expr->name instanceof Identifier
            && in_array($expr->name->toLowerString(), ['using', 'with'], true)) {
            $parameters = [];
            foreach ($expr->args as $arg) {
                $value = $arg instanceof Node\Arg ? $arg->value : $arg;
                $parameters[] = match (true) {
                    $value instanceof String_ => $value->value,
                    $value instanceof Node\Scalar\Int_ => (string) $value->value,
                    default => self::unknownParameter($value),
                };
            }

            return '\\'.$this->className($expr->class).':'.implode(',', $parameters);
        }

        return $this->middlewareName($expr);
    }

    /**
     * Whether the Kernel's global $middleware carries a throttle, and the throttles its
     * $middlewareGroups entry for one of the given groups lists.
     *
     * @param  array<int, string>  $groups
     * @param  array{global: bool, names: list<string>}  $throttles
     */
    private function collectKernelThrottles(array $groups, array &$throttles): void
    {
        foreach ($this->parser->findNodes($this->resolvedAst('app/Http/Kernel.php'), Node\Stmt\Property::class) as $property) {
            foreach ($property instanceof Node\Stmt\Property ? $property->props : [] as $prop) {
                if (! $prop->default instanceof Expr\Array_) {
                    continue;
                }

                $name = $prop->name->toString();

                if ($name === 'middleware' && $this->expressionIsThrottle($prop->default)) {
                    $throttles['global'] = true;
                }

                if ($name !== 'middlewareGroups') {
                    continue;
                }

                foreach ($prop->default->items as $item) {
                    if ($item instanceof Expr\ArrayItem
                        && $item->key instanceof String_
                        && in_array($item->key->value, $groups, true)) {
                        $this->collectThrottleNames($item->value, $throttles);
                    }
                }
            }
        }
    }

    /**
     * Collects what the Middleware configurator calls in bootstrap/app.php add to the
     * global stack or one of the given groups:
     * - append(...) / prepend(...) / use([...]), the global stack
     * - appendToGroup(group, ...) / prependToGroup(group, ...) / group(group, [...])
     * - web(append: [...]) / api(prepend: [...], replace: [...])
     * - throttleApi(), for the api group only
     *
     * @param  array<int, string>  $groups
     * @param  array{global: bool, names: list<string>}  $throttles
     */
    private function collectBootstrapThrottles(array $groups, array &$throttles): void
    {
        foreach ($this->configuratorCalls($this->parser, $this->resolvedAst('bootstrap/app.php')) as $call) {
            // configuratorCalls() returns only calls with an identifier name
            $method = $call->name instanceof Identifier ? $call->name->toLowerString() : '';
            switch ($method) {
                // throttleApi($limiter = 'api') puts 'throttle:'.$limiter into the api group at
                // runtime. There is no throttleWeb() equivalent, and throttleWithRedis()
                // merely swaps the driver, so it must not count.
                case 'throttleapi':
                    if (in_array('api', $groups, true)) {
                        $limiter = $this->callArgument($call, 0, 'limiter');
                        $throttles['names'][] = 'throttle:'.match (true) {
                            $limiter === null => 'api',
                            $limiter instanceof String_ => $limiter->value,
                            default => self::unknownParameter($limiter),
                        };
                    }
                    break;

                case 'append':
                case 'prepend':
                case 'use':
                    $middleware = $this->callArgument($call, 0, 'middleware');
                    if ($middleware !== null && $this->expressionIsThrottle($middleware)) {
                        $throttles['global'] = true;
                    }
                    break;

                case 'appendtogroup':
                case 'prependtogroup':
                case 'group':
                    $groupName = $this->callArgument($call, 0, 'group');
                    $middleware = $this->callArgument($call, 1, 'middleware');
                    if ($groupName instanceof String_ && in_array($groupName->value, $groups, true) && $middleware !== null) {
                        $this->collectThrottleNames($middleware, $throttles);
                    }
                    break;

                case 'web':
                case 'api':
                    if (! in_array($method, $groups, true)) {
                        break;
                    }

                    // web(append, prepend, remove, replace): a throttle under remove:
                    // takes it out of the group, so only the other three count.
                    foreach (['append' => 0, 'prepend' => 1, 'replace' => 3] as $name => $position) {
                        $middleware = $this->callArgument($call, $position, $name);
                        if ($middleware !== null) {
                            $this->collectThrottleNames($middleware, $throttles);
                        }
                    }
            }
        }
    }

    /**
     * Adds the throttles a middleware value names, one or a list, to $throttles.
     *
     * @param  array{global: bool, names: list<string>}  $throttles
     */
    private function collectThrottleNames(Expr $middleware, array &$throttles): void
    {
        foreach ($this->listedNames([$middleware]) as $name) {
            if ($this->nameThrottles($name)) {
                $throttles['names'][] = $name;
            }
        }
    }

    /**
     * The names middleware entries hand the router (see middlewareNameWithParameters()),
     * an array entry read as the list it holds.
     *
     * @param  array<Expr>  $entries
     * @return list<string>
     */
    private function listedNames(array $entries): array
    {
        $names = [];
        foreach ($entries as $entry) {
            if ($entry instanceof Expr\Array_) {
                $items = [];
                foreach ($entry->items as $item) {
                    if ($item instanceof Expr\ArrayItem) {
                        $items[] = $item->value;
                    }
                }
                array_push($names, ...$this->listedNames($items));
            } elseif (($name = $this->middlewareNameWithParameters($entry)) !== null) {
                $names[] = $name;
            }
        }

        return $names;
    }

    /**
     * The name Laravel's MiddlewareNameResolver compares an excluded middleware by: the
     * 'throttle' alias resolved to its class (see throttleAliasClass()), a class without
     * its leading backslash, and the parameters kept.
     */
    private function resolvedName(string $name): string
    {
        $parts = explode(':', $name, 2);
        $base = ltrim($parts[0], '\\');

        return ($base === 'throttle' ? $this->throttleAliasClass() : $base).(isset($parts[1]) ? ':'.$parts[1] : '');
    }

    /**
     * The class the 'throttle' alias names: the one the app registers for it, in the
     * Kernel's $middlewareAliases / $routeMiddleware or through $middleware->alias([...])
     * in bootstrap/app.php, which Laravel merges over its own; otherwise
     * {@see self::frameworkThrottleClass()}.
     *
     * @internal Shared between this package's analyzers, outside its backward-compatibility promise.
     */
    public function throttleAliasClass(): string
    {
        if ($this->throttleAliasClass === null) {
            $registered = null;
            foreach ($this->configuratorCalls($this->parser, $this->resolvedAst('bootstrap/app.php')) as $call) {
                $aliases = $call->name instanceof Identifier && $call->name->toLowerString() === 'alias'
                    ? $this->callArgument($call, 0, 'aliases')
                    : null;
                if ($aliases instanceof Expr\Array_) {
                    $registered = $this->throttleAliasIn($aliases) ?? $registered;
                }
            }

            foreach ($this->parser->findNodes($this->resolvedAst('app/Http/Kernel.php'), Node\Stmt\Property::class) as $property) {
                foreach ($property instanceof Node\Stmt\Property ? $property->props : [] as $prop) {
                    if (in_array($prop->name->toString(), ['middlewareAliases', 'routeMiddleware'], true) && $prop->default instanceof Expr\Array_) {
                        $registered = $this->throttleAliasIn($prop->default) ?? $registered;
                    }
                }
            }

            $this->throttleAliasClass = $registered ?? $this->frameworkThrottleClass();
        }

        return $this->throttleAliasClass;
    }

    /**
     * The class Laravel itself registers the 'throttle' alias as: ThrottleRequestsWithRedis
     * once bootstrap/app.php calls throttleWithRedis() or throttleApi() with redis true,
     * otherwise ThrottleRequests.
     *
     * @internal Shared between this package's analyzers, outside its backward-compatibility promise.
     */
    public function frameworkThrottleClass(): string
    {
        foreach ($this->configuratorCalls($this->parser, $this->resolvedAst('bootstrap/app.php')) as $call) {
            $method = $call->name instanceof Identifier ? $call->name->toLowerString() : '';
            $redis = $method === 'throttleapi' ? $this->callArgument($call, 1, 'redis') : null;
            if ($method === 'throttlewithredis'
                || ($redis instanceof Expr\ConstFetch && $redis->name->toLowerString() === 'true')) {
                return self::THROTTLE_MIDDLEWARE[1];
            }
        }

        return self::THROTTLE_MIDDLEWARE[0];
    }

    /**
     * The class an alias array registers under 'throttle', or null.
     */
    private function throttleAliasIn(Expr\Array_ $aliases): ?string
    {
        foreach ($aliases->items as $item) {
            if ($item instanceof Expr\ArrayItem && $item->key instanceof String_ && $item->key->value === 'throttle') {
                $name = $this->middlewareName($item->value);

                return $name === null ? null : ltrim((string) strtok($name, ':'), '\\');
            }
        }

        return null;
    }

    /**
     * A parameter standing for a value that is not a literal, unique to that value, so it
     * never equals a parameter written anywhere else.
     */
    private static function unknownParameter(Node $value): string
    {
        return "\0".spl_object_id($value);
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
