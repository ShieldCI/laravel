<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use PhpParser\Node;
use PhpParser\Node\Stmt;
use PhpParser\Node\Stmt\GroupUse;
use PhpParser\Node\Stmt\Use_;
use PhpParser\Node\UseItem;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;

/**
 * Answers one question: is this class declaration an Eloquent model?
 *
 * Three-valued on purpose. `true` = model, `false` = definitively not (the class
 * extends nothing, or its `extends` chain terminates at a non-model), `null` = unknown
 * (the chain leaves the project into vendor code we cannot read). Callers choose what
 * `unknown` means for their polarity via isModel(..., unknownIs:).
 *
 * Resolves parent class names itself from the declaring file's use statements and
 * namespace, so it is correct whether or not the caller ran NameResolver: an already
 * resolved FullyQualified parent contains a backslash and passes through untouched.
 */
final class EloquentModelDetector
{
    /**
     * Sub-namespaces of a Models namespace that hold helpers rather than models.
     *
     * @var array<int, string>
     */
    private const NON_MODEL_SUBNAMESPACES = [
        'Scopes', 'Observers', 'Casts', 'Collections', 'Traits', 'Concerns', 'Builders', 'Enums',
    ];

    /**
     * Short class names of the Eloquent base classes a model may extend.
     *
     * @var array<int, string>
     */
    private const ELOQUENT_BASE_CLASSES = ['Model', 'Authenticatable', 'Pivot', 'MorphPivot'];

    /**
     * Fully-qualified Eloquent base classes, matched after resolving `extends`
     * through the declaring file's use statements (handles `use Model as Eloquent`).
     *
     * @var array<int, string>
     */
    private const ELOQUENT_BASE_FQNS = [
        'Illuminate\\Database\\Eloquent\\Model',
        'Illuminate\\Foundation\\Auth\\User',
        'Illuminate\\Database\\Eloquent\\Relations\\Pivot',
        'Illuminate\\Database\\Eloquent\\Relations\\MorphPivot',
    ];

    public function __construct(private readonly ParserInterface $parser) {}

    /**
     * Whether a namespace denotes Eloquent models.
     *
     * Accepts any exact `Models` segment — App\Models, App\Models\Admin, and modular
     * layouts such as Modules\Billing\Models — while excluding the helper sub-namespaces
     * that live alongside models. `App\ViewModels` never qualifies: the match is on a
     * whole segment, not a suffix.
     */
    public function namespaceLooksLikeModels(?string $namespace): bool
    {
        if ($namespace === null || $namespace === '') {
            return false;
        }

        $segments = explode('\\', $namespace);
        $index = array_search('Models', $segments, true);

        if (! is_int($index)) {
            return false;
        }

        $next = $segments[$index + 1] ?? null;

        return $next === null || ! in_array($next, self::NON_MODEL_SUBNAMESPACES, true);
    }

    /**
     * Three-valued Eloquent verdict for a class declaration.
     *
     * @param  array<Node>  $fileAst  AST of the file declaring $class
     * @param  string  $basePath  Project root, used to locate app/
     */
    public function verdictFor(Stmt\Class_ $class, array $fileAst, string $basePath): ?bool
    {
        // Step 1: a class that extends nothing is never an Eloquent model.
        if ($class->extends === null) {
            return false;
        }

        $parentName = $class->extends->toString();

        // Step 2: the parent's short name is a known Eloquent base.
        $parentShort = $this->shortName($parentName);
        if (in_array($parentShort, self::ELOQUENT_BASE_CLASSES, true)) {
            return true;
        }

        $useStatements = $this->extractUseStatements($fileAst);
        $namespace = $this->extractNamespace($fileAst);

        $parentFqn = $this->resolveClassName($parentName, $useStatements, $namespace);
        if ($parentFqn === null) {
            return null;
        }

        // Step 3: the resolved parent FQN is a known Eloquent base.
        if (in_array($parentFqn, self::ELOQUENT_BASE_FQNS, true)) {
            return true;
        }

        return null;
    }

    private function shortName(string $fqn): string
    {
        $pos = strrpos($fqn, '\\');

        return $pos !== false ? substr($fqn, $pos + 1) : $fqn;
    }

    /**
     * Resolve a class name to an FQN.
     *
     * A name containing a backslash is already qualified (this covers FullyQualified
     * nodes produced by NameResolver). Otherwise consult the use map, then fall back
     * to the enclosing namespace, matching PHP's own name resolution.
     *
     * @param  array<string, string>  $useStatements
     */
    private function resolveClassName(string $name, array $useStatements, ?string $namespace): ?string
    {
        if (str_contains($name, '\\')) {
            return $name;
        }

        if (isset($useStatements[$name])) {
            return $useStatements[$name];
        }

        return $namespace !== null && $namespace !== '' ? $namespace.'\\'.$name : null;
    }

    /**
     * Short-name => FQN map of the file's imports.
     *
     * @param  array<Node>  $fileAst
     * @return array<string, string>
     */
    private function extractUseStatements(array $fileAst): array
    {
        $map = [];

        /** @var array<Use_> $uses */
        $uses = $this->parser->findNodes($fileAst, Use_::class);
        foreach ($uses as $use) {
            foreach ($use->uses as $useItem) {
                if ($useItem instanceof UseItem) {
                    $map[$useItem->getAlias()->toString()] = $useItem->name->toString();
                }
            }
        }

        /** @var array<GroupUse> $groupUses */
        $groupUses = $this->parser->findNodes($fileAst, GroupUse::class);
        foreach ($groupUses as $groupUse) {
            $prefix = $groupUse->prefix->toString();
            foreach ($groupUse->uses as $useItem) {
                if ($useItem instanceof UseItem) {
                    $map[$useItem->getAlias()->toString()] = $prefix.'\\'.$useItem->name->toString();
                }
            }
        }

        return $map;
    }

    /**
     * The first namespace declared in a file, if any.
     *
     * @param  array<Node>  $fileAst
     */
    private function extractNamespace(array $fileAst): ?string
    {
        /** @var array<Stmt\Namespace_> $namespaces */
        $namespaces = $this->parser->findNodes($fileAst, Stmt\Namespace_::class);

        foreach ($namespaces as $namespace) {
            if ($namespace->name !== null) {
                return $namespace->name->toString();
            }
        }

        return null;
    }
}
