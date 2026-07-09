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

    /** @var array<string, bool|null> File path => Eloquent verdict */
    private array $fileVerdictCache = [];

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
        return $this->classVerdict($class, $fileAst, $basePath);
    }

    /**
     * Two-valued verdict. The caller states what `unknown` means for its polarity.
     *
     * For an analyzer where "is a model" means *analyze this class*, unknown should be
     * false (a missed model beats a bogus finding). For one where it means *suppress*,
     * the caller must still weigh what populates unknown — see the class docblock.
     *
     * @param  array<Node>  $fileAst
     */
    public function isModel(Stmt\Class_ $class, array $fileAst, string $basePath, bool $unknownIs = false): bool
    {
        return $this->verdictFor($class, $fileAst, $basePath) ?? $unknownIs;
    }

    /**
     * Three-valued verdict for the classes declared in a file, memoized by path.
     */
    private function fileVerdict(string $filePath, string $basePath): ?bool
    {
        if (array_key_exists($filePath, $this->fileVerdictCache)) {
            return $this->fileVerdictCache[$filePath];
        }

        // Reserve the slot before recursing so a cyclic chain resolves to null
        // instead of looping. This is the sole termination mechanism: acyclic
        // `extends` chains are finite, and a cycle re-entering a file already
        // in progress hits this reserved cache entry and returns immediately.
        $this->fileVerdictCache[$filePath] = null;

        $fileAst = $this->parser->parseFile($filePath);
        if ($fileAst === []) {
            return null;
        }

        $verdict = false;

        foreach ($this->parser->findClasses($fileAst) as $class) {
            $classVerdict = $this->classVerdict($class, $fileAst, $basePath);

            if ($classVerdict === true) {
                $verdict = true;

                break;
            }

            if ($classVerdict === null) {
                $verdict = null;
            }
        }

        $this->fileVerdictCache[$filePath] = $verdict;

        return $verdict;
    }

    /**
     * The step 1-7 algorithm for one class.
     *
     * @param  array<Node>  $fileAst
     */
    private function classVerdict(Stmt\Class_ $class, array $fileAst, string $basePath): ?bool
    {
        // Step 1: a class that extends nothing is never an Eloquent model.
        if ($class->extends === null) {
            return false;
        }

        $parentName = $class->extends->toString();

        // Step 2: the parent's short name is a known Eloquent base.
        if (in_array($this->shortName($parentName), self::ELOQUENT_BASE_CLASSES, true)) {
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

        // Step 4: the parent itself lives in a Models namespace.
        if ($this->namespaceLooksLikeModels($this->namespaceOf($parentFqn))) {
            return true;
        }

        // Step 5: follow the chain into a project class we can read.
        //         A definite verdict from the chain outranks the convention below.
        $parentPath = $this->fqnToFilePath($parentFqn, $basePath);
        if ($parentPath !== null) {
            $chainVerdict = $this->fileVerdict($parentPath, $basePath);
            if ($chainVerdict !== null) {
                return $chainVerdict;
            }
        }

        // Step 6: the analyzed class's own namespace is a Models namespace.
        if ($this->namespaceLooksLikeModels($namespace)) {
            return true;
        }

        // Step 7: unknown.
        return null;
    }

    /**
     * Map an App\ FQN to a file under app/. Null when outside App\ or the file is absent.
     */
    private function fqnToFilePath(string $fqn, string $basePath): ?string
    {
        if (! str_starts_with($fqn, 'App\\')) {
            return null;
        }

        $relative = substr($fqn, 4);
        $path = rtrim($basePath, '/').'/app/'.str_replace('\\', '/', $relative).'.php';

        return file_exists($path) ? $path : null;
    }

    /**
     * The namespace portion of a fully-qualified class name ('' for a global class).
     */
    private function namespaceOf(string $fqn): string
    {
        $pos = strrpos($fqn, '\\');

        return $pos !== false ? substr($fqn, 0, $pos) : '';
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
