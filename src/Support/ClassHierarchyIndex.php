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
 * imports, and records the resulting strings, which is what lets analyzers with different walk
 * shapes share this: one is a NodeVisitor over a full traversal, the other a hand-rolled
 * statement recursion that looks only at namespaces and class-like declarations.
 *
 * What they share is the class, not an instance. Each builds and fills its own, because the
 * analyzers are resolved per run and every test sets its own base path, so one graph serving
 * all of them would have to be keyed by base path, paths and excludes to avoid answering for
 * the wrong project. An instance therefore holds only what its one caller recorded, which is
 * what lets that caller read a payload of its own back by the keys this answers with.
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

    /** @var array<string, list<string>>|null trait key => keys of the declarations using it */
    private ?array $traitUsers = null;

    /** @var array<string, list<string>>|null parent key => keys of the declarations extending it */
    private ?array $children = null;

    /**
     * Which declarations may answer inwards, when the caller does not let all of them. Held
     * rather than taken per call so that the walk can be memoised: an answer depends on it, so
     * a predicate that changed between calls would make a remembered one wrong.
     *
     * @var (\Closure(string): bool)|null
     */
    private ?\Closure $answersInwards = null;

    /** @var array<string, array<string, bool>> seed key => the walk inwards from it */
    private array $descendants = [];

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
    public function record(string $fqn, ?string $parent, array $traits): string
    {
        $key = self::key($fqn);

        $this->parents[$key] = $parent;
        $this->traitUses[$key] = $traits;

        // The reverse edges and the walks over them are derived from these maps rather than
        // recorded beside them, so they have to be discarded whenever the maps change.
        // Appending to them as declarations arrived kept the edges of a name declared twice,
        // and a parent no longer extended went on being answered for by a class that had
        // stopped extending it.
        $this->traitUsers = null;
        $this->children = null;
        $this->descendants = [];

        return $key;
    }

    /**
     * Narrow which declarations may answer inwards, for a caller that reports on some of the
     * files it indexed and not others.
     *
     * The edges themselves are facts and stay whole; this is the caller's policy, so it is
     * supplied rather than recorded. What a class inherits does not depend on where its parent
     * was written, so the walk outwards is never narrowed, but the walk inwards lets one file
     * decide whether another is reported: without this a test double or a seeder would settle
     * a finding against the production class it extends.
     *
     * A declaration the predicate rejects is not reached and is not walked through, so it
     * cannot pass an answer along from behind it either.
     *
     * @param  (\Closure(string): bool)|null  $predicate  keyed as record() returns, or null for all
     */
    public function answeringInwards(?\Closure $predicate): void
    {
        $this->answersInwards = $predicate;
        $this->descendants = [];
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
     * Remembered per seed, and forgotten whenever record() or answeringInwards() changes what
     * the answer would be, so asking twice costs one walk and asking after a redeclaration
     * does not answer from before it.
     *
     * @return array<string, bool> folded key => whether a trait-only path reached it
     */
    public function descendantsOf(string $fqn): array
    {
        return $this->descendants[self::key($fqn)] ??= $this->walkInwards(self::key($fqn));
    }

    /**
     * @return array<string, bool>
     */
    private function walkInwards(string $key): array
    {
        [$traitUsers, $children] = $this->reverseEdges();

        /** @var array<string, bool> $reached */
        $reached = [];
        /** @var list<array{string, bool}> $queue */
        $queue = [[$key, true]];

        // Popped with a cursor rather than array_shift, which reindexes the whole queue on
        // every pop and made the walk quadratic in the size of the subtree.
        for ($read = 0; $read < count($queue); $read++) {
            [$current, $viaTraitsOnly] = $queue[$read];

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

                // Neither reached nor walked through, so a declaration the caller will not
                // report on cannot pass an answer along from the declarations behind it.
                if ($this->answersInwards !== null && ! ($this->answersInwards)($descendant)) {
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
     * Whole, because an edge is a fact about the source. Which of them the caller lets answer
     * is its own policy and is applied by the walk, so these survive a change of predicate.
     *
     * @return array{array<string, list<string>>, array<string, list<string>>}
     */
    private function reverseEdges(): array
    {
        if ($this->traitUsers === null || $this->children === null) {
            $this->traitUsers = [];
            $this->children = [];

            foreach ($this->traitUses as $key => $traits) {
                foreach ($traits as $trait) {
                    $this->traitUsers[self::key($trait)][] = $key;
                }
            }

            foreach ($this->parents as $key => $parent) {
                if ($parent !== null) {
                    $this->children[self::key($parent)][] = $key;
                }
            }
        }

        return [$this->traitUsers, $this->children];
    }
}
