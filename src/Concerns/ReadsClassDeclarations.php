<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use PhpParser\Modifiers;
use PhpParser\Node;

/**
 * What a class-like declaration states about itself: the declarations it draws members from,
 * and the declared type of each property it holds.
 *
 * Every answer here is resolved against the imports of the file the reader is walking, through
 * the resolvedClassFqn() the consumer supplies. That is why this is a trait and not a method on
 * the registry: the registry finishes indexing before the analysis pass starts, so a node handed
 * to it afterwards would be resolved against whichever file it indexed last. A reader names the
 * declaration it is standing on with its own table and asks the registry by name.
 *
 * @internal This trait is an implementation detail shared between this package's analyzers,
 * and its shape is not covered by the package's backward-compatibility promise.
 */
trait ReadsClassDeclarations
{
    /**
     * Stands in for the type of a property that has one no reader can reduce to a single FQN:
     * none at all, a scalar, a union or an intersection. It is not a class name and cannot
     * collide with one, so a walk weighing candidate types sees it as the one thing it is, a
     * type that is not a known client.
     *
     * A method rather than a constant because trait constants are PHP 8.2 and this package
     * supports 8.1. Static so that a static closure filtering on it can still reach it.
     */
    private static function untypable(): string
    {
        return '?untypable';
    }

    /**
     * The declarations $class draws members from directly. Traits come first because that is
     * PHP's own precedence: a trait a class uses overrides what it would have inherited.
     *
     * @return list<string>
     */
    private function declaredAncestorsOf(Node\Stmt\ClassLike $class): array
    {
        $ancestors = [];

        foreach ($class->getTraitUses() as $use) {
            foreach ($use->traits as $trait) {
                $ancestors[] = $this->resolvedClassFqn($trait);
            }
        }

        if ($class instanceof Node\Stmt\Class_ && $class->extends !== null) {
            $ancestors[] = $this->resolvedClassFqn($class->extends);
        }

        return $ancestors;
    }

    /**
     * Map every property a declaration holds itself to its declared type FQN, covering plain
     * declarations and constructor-promoted parameters alike. Properties with no type, or a
     * scalar or composite type, are omitted so they stay conservative (flaggable).
     *
     * @return array<string, string>
     */
    private function declaredPropertyTypes(Node\Stmt\ClassLike $class): array
    {
        return array_filter(
            $this->propertyViews($class)['declared'],
            static fn (string $type): bool => $type !== self::untypable(),
        );
    }

    /**
     * The two views of a declaration's own properties, from one walk of its statements.
     *
     * `inheritable` is what a different declaration can see and put a name to: no private
     * entries, and nothing whose type is missing or composite. It answers what a class
     * inherits, where an entry that cannot be resolved to one FQN is better left out so the
     * property stays flaggable.
     *
     * `declared` is every property the declaration holds, private included, with the untypable
     * sentinel standing in where there is no single type FQN to record. It answers the opposite
     * question, what the declarations drawing from this one hold, and there an entry that
     * cannot be resolved must still be present: that walk exempts a property only when every
     * candidate for it is a known client, so a property omitted for want of a type would be
     * read as agreement rather than as the unknown it is.
     *
     * @return array{inheritable: array<string, string>, declared: array<string, string>}
     */
    private function propertyViews(Node\Stmt\ClassLike $class): array
    {
        $inheritable = [];
        $declared = [];

        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\Property) {
                $type = $this->typeFqn($stmt->type);

                foreach ($stmt->props as $prop) {
                    $name = $prop->name->toString();

                    $declared[$name] = $type ?? self::untypable();
                    if ($type !== null && ! $stmt->isPrivate()) {
                        $inheritable[$name] = $type;
                    }
                }

                continue;
            }

            if (! $stmt instanceof Node\Stmt\ClassMethod || $stmt->name->toString() !== '__construct') {
                continue;
            }

            foreach ($stmt->params as $param) {
                if ($param->flags === 0
                    || ! $param->var instanceof Node\Expr\Variable
                    || ! is_string($param->var->name)
                ) {
                    continue;
                }

                $type = $this->typeFqn($param->type);
                $name = $param->var->name;

                $declared[$name] = $type ?? self::untypable();
                if ($type !== null && ($param->flags & Modifiers::PRIVATE) === 0) {
                    $inheritable[$name] = $type;
                }
            }
        }

        return ['inheritable' => $inheritable, 'declared' => $declared];
    }

    /**
     * Resolve a declared type to its fully-qualified name, or null when it is not a plain
     * class name (scalar, union, intersection, or absent).
     */
    private function typeFqn(?Node $type): ?string
    {
        if ($type instanceof Node\NullableType) {
            $type = $type->type;
        }

        if (! $type instanceof Node\Name) {
            return null;
        }

        return $this->resolvedClassFqn($type);
    }

    /**
     * Declared rather than implemented for the reason IdentifiesNonQueryClasses declares its
     * own: the resolver belongs to whatever collects the reader's imports, and a consumer must
     * not be able to supply a different one by accident. TracksImportedNames satisfies it.
     */
    abstract protected function resolvedClassFqn(Node\Name $class): string;
}
