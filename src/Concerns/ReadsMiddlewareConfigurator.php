<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Identifier;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;

/**
 * Reads the calls bootstrap/app.php makes on the withMiddleware() configurator
 * (Illuminate\Foundation\Configuration\Middleware) in Laravel 11+.
 *
 * @internal An implementation detail of csrf-protection and login-throttling, outside this package's backward-compatibility promise.
 */
trait ReadsMiddlewareConfigurator
{
    /**
     * The configurator calls in an AST: method calls whose chain starts at a variable,
     * such as $middleware->web(...) or $middleware->alias([...])->web(...).
     *
     * @param  array<Node>  $ast
     * @return list<Expr\MethodCall>
     */
    private function configuratorCalls(ParserInterface $parser, array $ast): array
    {
        $calls = [];

        foreach ($parser->findNodes($ast, Expr\MethodCall::class) as $call) {
            if ($call instanceof Expr\MethodCall
                && $call->name instanceof Identifier
                && $this->chainStartsAtVariable($call->var)) {
                $calls[] = $call;
            }
        }

        return $calls;
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
     * The value of a call argument, given by name or by position.
     */
    private function callArgument(Expr\MethodCall|Expr\StaticCall $call, int $position, string $name): ?Expr
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
}
