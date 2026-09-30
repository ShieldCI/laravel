<?php

declare(strict_types=1);

namespace ShieldCI\Support;

/**
 * The inheritance graph of a project's class-like declarations: what each one extends and
 * which traits it uses, read in both directions.
 *
 * The declaration a pass needs is often not the one it is standing in. A service writing to
 * an injected cache client routinely inherits that property from an abstract base in another
 * file, or picks it up from a trait; and the mirror of that, a trait holding the method while
 * the class using it declares the property, needs the same edges read inwards.
 *
 * Nothing here touches an AST. A caller walks its own files, resolves names with its own
 * imports, and records the resulting strings, which is what lets two analyzers with different
 * walk shapes share one graph: one is a NodeVisitor over a full traversal, the other a
 * statement recursion that deliberately does not descend into method bodies.
 *
 * Keys are case folded, because PHP resolves a class name without regard to case and a
 * reference spelled differently from its declaration names the same class. Any name may be
 * passed in whatever case the source spells it. What comes back differs by question, and the
 * difference is load bearing: parentOf() and ancestorsOf() answer with names, as recorded, to
 * be looked up here again or compared against a written type; descendantsOf() answers with
 * folded keys, because its caller uses them to index a payload it filed under the key record()
 * returned. Remembering an original spelling per declaration would buy nothing and cost a map.
 *
 * @internal This class is an implementation detail shared between this package's analyzers,
 * and its shape is not covered by the package's backward-compatibility promise.
 */
final class ClassHierarchyIndex
{
    /** @var array<string, string|null> class key => parent FQN, null when it has no parent */
    private array $parents = [];

    /** @var array<string, list<string>> class or trait key => FQNs of the traits it uses */
    private array $traitUses = [];

    /**
     * Whether each declaration came from a file the caller's analysis pass will judge. Read
     * only when deriving the reverse edges, where a declaration the pass skips must not answer
     * for one it reports on.
     *
     * @var array<string, bool>
     */
    private array $judged = [];

    /** @var array<string, list<string>>|null trait key => keys of the declarations using it */
    private ?array $traitUsers = null;

    /** @var array<string, list<string>>|null parent key => keys of the declarations extending it */
    private ?array $children = null;

    /**
     * The key a name is filed under. Folded because PHP resolves a class name without regard
     * to case, so a reference spelled differently is still the same class.
     */
    public static function key(string $fqn): string
    {
        return strtolower($fqn);
    }

    /**
     * Record one declaration's edges, returning the key it was filed under so that a caller
     * keeping a payload of its own can key it the same way.
     *
     * Every map is written whatever the declaration holds, so a name declared twice cannot
     * leave one declaration's parent standing beside another's traits. A trait records a null
     * parent, which reads the same as having none.
     *
     * @param  list<string>  $traits
     */
    public function record(string $fqn, ?string $parent, array $traits, bool $judged): string
    {
        $key = self::key($fqn);

        $this->parents[$key] = $parent;
        $this->traitUses[$key] = $traits;
        $this->judged[$key] = $judged;

        // The reverse edges are derived from these maps rather than recorded beside them, so
        // they have to be discarded whenever the maps change. Appending to them as
        // declarations arrived kept the edges of a name declared twice, and a parent no longer
        // extended went on being answered for by a class that had stopped extending it.
        $this->traitUsers = null;
        $this->children = null;

        return $key;
    }

    public function parentOf(string $fqn): ?string
    {
        return $this->parents[self::key($fqn)] ?? null;
    }

    /**
     * The declarations $fqn draws members from directly. Traits come first because that is
     * PHP's own precedence: a trait a class uses overrides what it would have inherited.
     *
     * @return list<string>
     */
    public function ancestorsOf(string $fqn): array
    {
        $key = self::key($fqn);

        $ancestors = $this->traitUses[$key] ?? [];

        $parent = $this->parents[$key] ?? null;
        if ($parent !== null) {
            $ancestors[] = $parent;
        }

        return $ancestors;
    }

    /**
     * Every declaration that draws from $fqn, breadth first inwards, mapped to whether some
     * path reaching it crossed trait uses only.
     *
     * That flag carries PHP's own scoping rule for the caller to apply: a trait's methods are
     * inlined into the class using it and share its scope, so they read its private
     * properties, while a parent's methods keep the parent's scope and a read of the same name
     * reaches a dynamic property instead. So a path that crosses one extends edge carries that
     * restriction the rest of the way, and a declaration reachable both ways is reported on
     * the trait-only path, since the wider view subsumes the narrower one.
     *
     * Reached first and read second, which is the caller's business: a declaration two paths
     * arrive at is one declaration with one answer, and reading it as each path arrived would
     * leave the blinder path's answer standing beside the fuller one.
     *
     * The visited set makes the walk terminate on a hierarchy that refers back to itself,
     * which an AST can express even though PHP could not load it. The seed is not its own
     * descendant.
     *
     * @return array<string, bool> folded key => whether a trait-only path reached it
     */
    public function descendantsOf(string $fqn): array
    {
        $key = self::key($fqn);
        [$traitUsers, $children] = $this->reverseEdges();

        /** @var array<string, bool> $reached */
        $reached = [];
        /** @var list<array{string, bool}> $queue */
        $queue = [[$key, true]];

        while ($queue !== []) {
            [$current, $viaTraitsOnly] = array_shift($queue);

            $next = [];
            foreach ($traitUsers[$current] ?? [] as $user) {
                $next[] = [$user, $viaTraitsOnly];
            }
            foreach ($children[$current] ?? [] as $child) {
                $next[] = [$child, false];
            }

            foreach ($next as [$descendant, $descendantViaTraitsOnly]) {
                if ($descendant === $key) {
                    continue;
                }

                // Requeued only on a path that grants a view the earlier one did not, which
                // bounds the walk at two visits per declaration.
                if (isset($reached[$descendant])
                    && ($reached[$descendant] || ! $descendantViaTraitsOnly)
                ) {
                    continue;
                }

                $reached[$descendant] = $descendantViaTraitsOnly;
                $queue[] = [$descendant, $descendantViaTraitsOnly];
            }
        }

        return $reached;
    }

    /**
     * The edges read inwards, derived from the forward maps on first use.
     *
     * A declaration the caller's pass will not judge is left out, and only here. It may still
     * be inherited from, because what a class inherits does not depend on where its parent was
     * written; it may not answer for what a class it draws from holds, because that would let
     * a fixture decide whether production code is reported.
     *
     * @return array{array<string, list<string>>, array<string, list<string>>}
     */
    private function reverseEdges(): array
    {
        if ($this->traitUsers === null || $this->children === null) {
            $this->traitUsers = [];
            $this->children = [];

            // Indexed without a fallback: record() writes all three maps together, so a key
            // one holds the others hold too.
            foreach ($this->traitUses as $key => $traits) {
                if (! $this->judged[$key]) {
                    continue;
                }

                foreach ($traits as $trait) {
                    $this->traitUsers[self::key($trait)][] = $key;
                }
            }

            foreach ($this->parents as $key => $parent) {
                if ($parent !== null && $this->judged[$key]) {
                    $this->children[self::key($parent)][] = $key;
                }
            }
        }

        return [$this->traitUsers, $this->children];
    }
}
