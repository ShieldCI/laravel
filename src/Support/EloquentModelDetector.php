<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use PhpParser\Node;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
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
     * Three-valued verdict for one named class declared in a file, memoized by
     * path + short name.
     *
     * The parent is resolved by matching $shortName against the file's named class
     * declarations. A sibling class or an anonymous class in the same file — both
     * returned by findClasses() — is never allowed to stand in for the parent, so a
     * file whose $shortName class is a plain class does not read as a model merely
     * because some other class beside it extends an Eloquent base. Returns null when
     * the file declares no class of that name (parse failure, or a mismatch).
     */
    private function classVerdictInFile(string $filePath, string $shortName, string $basePath): ?bool
    {
        $cacheKey = $filePath.'::'.$shortName;

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
            if ($class->name?->toString() === $shortName) {
                return $this->verdictCache[$cacheKey] = $this->classVerdict($class, $fileAst, $basePath);
            }
        }

        return null;
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

        // Both are read off the table now, before step 5 recurses into the parent's file and
        // rebuilds it for that file instead.
        $this->startTrackingImports();
        $this->trackImportsUntil($fileAst, $class);
        $parentFqn = $this->resolvedClassFqn($class->extends);
        $namespace = $this->importedNames->getNamespace()?->toString();

        // Step 3: the resolved parent FQN is a known Eloquent base.
        if (in_array($parentFqn, self::ELOQUENT_BASE_FQNS, true)) {
            return true;
        }

        // Step 4: the parent itself lives in a Models namespace.
        if (self::namespaceLooksLikeModels($this->namespaceOf($parentFqn))) {
            return true;
        }

        // Step 5: follow the chain into a project class we can read.
        //         A definite verdict from the chain outranks the convention below.
        $parentPath = $this->fqnToFilePath($parentFqn, $basePath);
        if ($parentPath !== null) {
            $chainVerdict = $this->classVerdictInFile($parentPath, $this->shortName($parentFqn), $basePath);
            if ($chainVerdict !== null) {
                return $chainVerdict;
            }
        }

        // Step 6: the analyzed class's own namespace is a Models namespace.
        if (self::namespaceLooksLikeModels($namespace)) {
            return true;
        }

        // Step 7: unknown.
        return null;
    }

    /**
     * Fill the import table with what is in effect at $target, walking the statements in
     * the order the file writes them.
     *
     * Imports are only legal at the top level or directly inside a namespace, so those two
     * levels are all the walk visits. It stops at the statement that is $target or contains
     * it, which covers a class nested in a function or a conditional and an anonymous class.
     * With no target, or one the file does not contain, the table ends up holding the imports
     * in effect at the end of the file.
     *
     * @param  array<Node>  $stmts
     * @return bool Whether $target was reached
     */
    private function trackImportsUntil(array $stmts, ?Node $target): bool
    {
        foreach ($stmts as $stmt) {
            $this->trackImports($stmt);

            if ($stmt instanceof Stmt\Namespace_) {
                if ($this->trackImportsUntil($stmt->stmts, $target)) {
                    return true;
                }

                continue;
            }

            if ($target !== null && ($stmt === $target
                || (new NodeFinder)->findFirst($stmt, static fn (Node $node): bool => $node === $target) !== null)) {
                return true;
            }
        }

        return false;
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
