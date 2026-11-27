<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use PhpParser\Node;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Concerns\TracksImportedNames;

/**
 * Answers one question: is this class declaration an Eloquent model?
 *
 * Three-valued on purpose. `true` = model, `false` = definitively not (the class
 * extends nothing, or its `extends` chain terminates at a non-model), `null` = unknown
 * (the chain leaves the project into vendor code we cannot read). Callers choose what
 * `unknown` means for their polarity via isModel(..., unknownIs:).
 *
 * Resolves parent class names itself, through the imports and namespace in effect where
 * the class is declared, so it is correct whether or not the caller ran NameResolver: a
 * FullyQualified parent that NameResolver left behind passes through as written, and any
 * other name is resolved the way PHP would, relative qualified ones included.
 */
final class EloquentModelDetector
{
    use TracksImportedNames;

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

    public function __construct(private readonly AstParser $parser) {}

    /** @var array<string, bool|null> "path::ShortName" => Eloquent verdict */
    private array $verdictCache = [];

    /**
     * Whether a namespace denotes Eloquent models.
     *
     * Accepts any exact `Models` segment — App\Models, App\Models\Admin, and modular
     * layouts such as Modules\Billing\Models — while excluding the helper sub-namespaces
     * that live alongside models. `App\ViewModels` never qualifies: the match is on a
     * whole segment, not a suffix.
     *
     * Pure string predicate, so it is static: callers that only classify a namespace
     * (e.g. MixedQueryVisitor) need no parser-bound instance.
     */
    public static function namespaceLooksLikeModels(?string $namespace): bool
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
     * Three-valued Eloquent verdict for a class name as written at a usage site.
     *
     * Use this where the caller holds a *reference* — `new Order`, a type-hint, a `::class`
     * — rather than the class declaration that verdictFor() takes. A single-segment name is
     * resolved against the referencing file's imports and namespace, the declaring file is
     * located under app/, and that declaration's verdict is returned.
     *
     * A name with a backslash is taken as fully qualified, with or without a leading one. A
     * string carries no sign of whether it was written relative, so the caller resolves a
     * qualified name before passing it, as NameResolver's resolvedName attribute already is.
     *
     * An unreadable declaration stays `null` rather than becoming `false`: vendor code holds
     * real models (Laravel\Cashier\Subscription), so outside a Models namespace we genuinely
     * do not know.
     *
     * @param  array<Node>  $referencingFileAst  AST of the file where $className is written
     */
    public function verdictForClassName(string $className, array $referencingFileAst, string $basePath): ?bool
    {
        $className = ltrim($className, '\\');

        // `self`, `static` and `parent` name the enclosing class, not an import; resolving
        // them against the namespace would fabricate a class like App\Http\Middleware\static.
        if ($className === '' || in_array(strtolower($className), ['self', 'static', 'parent'], true)) {
            return null;
        }

        // A reference string carries no position, so it is resolved against the imports the
        // file has declared by its end.
        $this->startTrackingImports();
        $this->trackImportsUntil($referencingFileAst, null);
        $fqn = $this->resolvedClassFqn(
            str_contains($className, '\\') ? new Name\FullyQualified($className) : new Name($className)
        );

        // A verdict read off the real declaration outranks the convention below,
        // mirroring classVerdict()'s step 5 before step 6.
        $path = $this->fqnToFilePath($fqn, $basePath);
        if ($path !== null) {
            $verdict = $this->classVerdictInFile($path, $this->shortName($fqn), $basePath);
            if ($verdict !== null) {
                return $verdict;
            }
        }

        return self::namespaceLooksLikeModels($this->namespaceOf($fqn)) ? true : null;
    }

    /**
     * Two-valued form of verdictForClassName(). The caller states what `unknown` means for
     * its polarity — see the note on isModel().
     *
     * @param  array<Node>  $referencingFileAst
     */
    public function isModelClassName(string $className, array $referencingFileAst, string $basePath, bool $unknownIs = false): bool
    {
        return $this->verdictForClassName($className, $referencingFileAst, $basePath) ?? $unknownIs;
    }

    /**
     * Whether an App\\ class provably extends an Eloquent base: its declaration under app/ is
     * read and its `extends` chain, resolved through imports, reaches one of the Eloquent base
     * classes by fully qualified name.
     *
     * Stricter than verdictForClassName(): no namespace convention and no short-name match
     * stands in for a link of the chain, so a class in a Models namespace extending another
     * framework's base, or a parent the chain cannot read, answers false.
     */
    public function provablyExtendsModel(string $fqn, string $basePath): bool
    {
        $fqn = ltrim($fqn, '\\');
        $path = $this->fqnToFilePath($fqn, $basePath);

        return $path !== null && $this->classVerdictInFile($path, $this->shortName($fqn), $basePath, $fqn) === true;
    }

    /**
     * Three-valued verdict for one named class declared in a file, memoized by
     * path + short name.
     *
     * The parent is resolved by matching $shortName against the file's named class
     * declarations. A sibling class or an anonymous class in the same file — both
     * returned by findClasses() — is never allowed to stand in for the parent, so a
     * file whose $shortName class is a plain class does not read as a model merely
     * because some other class beside it extends an Eloquent base. Returns null when
     * the file declares no class of that name (parse failure, or a mismatch).
     *
     * @param  string|null  $provenFqn  The class to prove, as provablyExtendsModel() describes:
     *                                  only an `extends` chain resolved to an Eloquent base
     *                                  counts, and the declaration is matched by this fully
     *                                  qualified name rather than its short name
     */
    private function classVerdictInFile(string $filePath, string $shortName, string $basePath, ?string $provenFqn = null): ?bool
    {
        $cacheKey = $provenFqn === null ? $filePath.'::'.$shortName : 'proven::'.$filePath.'::'.strtolower($provenFqn);

        if (array_key_exists($cacheKey, $this->verdictCache)) {
            return $this->verdictCache[$cacheKey];
        }

        // Reserve the slot before recursing so a cyclic chain resolves to null
        // instead of looping. This is the sole termination mechanism: acyclic
        // `extends` chains are finite, and a cycle re-entering a class already
        // in progress hits this reserved cache entry and returns immediately.
        $this->verdictCache[$cacheKey] = null;

        $fileAst = $this->parser->parseFile($filePath);
        if ($fileAst === []) {
            return null;
        }

        foreach ($this->parser->findClasses($fileAst) as $class) {
            if ($class->name?->toString() !== $shortName && $provenFqn === null) {
                continue;
            }

            if ($provenFqn !== null) {
                $this->startTrackingImports();
                $this->trackImportsUntil($fileAst, $class);

                if (strcasecmp((string) $this->declarationFqn($class), $provenFqn) !== 0) {
                    continue;
                }
            }

            return $this->verdictCache[$cacheKey] = $this->classVerdict($class, $fileAst, $basePath, $provenFqn !== null);
        }

        return null;
    }

    /**
     * The step 1-7 algorithm for one class. With $proven, steps 2, 4 and 6 are skipped, since
     * they rest on a short name or a namespace convention rather than the resolved chain.
     *
     * @param  array<Node>  $fileAst
     */
    private function classVerdict(Stmt\Class_ $class, array $fileAst, string $basePath, bool $proven = false): ?bool
    {
        // Step 1: a class that extends nothing is never an Eloquent model.
        if ($class->extends === null) {
            return false;
        }

        $parentName = $class->extends->toString();

        // Step 2: the parent's short name is a known Eloquent base.
        if (! $proven && in_array($this->shortName($parentName), self::ELOQUENT_BASE_CLASSES, true)) {
            return true;
        }

        // Both are read off the table now, before step 5 recurses into the parent's file and
        // rebuilds it for that file instead.
        $this->startTrackingImports();
        $this->trackImportsUntil($fileAst, $class);
        $parentFqn = $this->resolvedClassFqn($class->extends);
        $namespace = $this->importedNames->getNamespace()?->toString();

        // Step 3: the resolved parent FQN is a known Eloquent base. A proven chain compares it
        // as PHP does, without case, and also accepts `Eloquent`, Laravel's global Model alias.
        if (in_array($parentFqn, self::ELOQUENT_BASE_FQNS, true)
            || ($proven && in_array(strtolower($parentFqn), array_map(strtolower(...), [...self::ELOQUENT_BASE_FQNS, 'Eloquent']), true))) {
            return true;
        }

        // Step 4: the parent itself lives in a Models namespace.
        if (! $proven && self::namespaceLooksLikeModels($this->namespaceOf($parentFqn))) {
            return true;
        }

        // Step 5: follow the chain into a project class we can read.
        //         A definite verdict from the chain outranks the convention below.
        $parentPath = $this->fqnToFilePath($parentFqn, $basePath);
        if ($parentPath !== null) {
            $chainVerdict = $this->classVerdictInFile($parentPath, $this->shortName($parentFqn), $basePath, $proven ? $parentFqn : null);
            if ($chainVerdict !== null) {
                return $chainVerdict;
            }
        }

        // Step 6: the analyzed class's own namespace is a Models namespace.
        if (! $proven && self::namespaceLooksLikeModels($namespace)) {
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
     * A name containing a backslash is returned as written, which is only right for a fully
     * qualified one: PHP resolves a relative qualified name such as `Models\Base` through the
     * enclosing namespace or an import of its first segment. Otherwise consult the use map,
     * then fall back to the enclosing namespace.
     *
     * Nothing in this package calls it any more, but it is public API on a published
     * package, so it stays until the next major.
     *
     * @deprecated Resolve the Name node through php-parser's NameContext, as TracksImportedNames does.
     *
     * @param  array<string, string>  $useStatements
     */
    public static function resolveClassName(string $name, array $useStatements, ?string $namespace): ?string
    {
        if (str_contains($name, '\\')) {
            return $name;
        }

        if (isset($useStatements[$name])) {
            return $useStatements[$name];
        }

        return $namespace !== null && $namespace !== '' ? $namespace.'\\'.$name : null;
    }
}
