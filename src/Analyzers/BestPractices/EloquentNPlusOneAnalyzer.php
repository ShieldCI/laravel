<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\ParentConnectingVisitor;
use PhpParser\NodeVisitorAbstract;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\Support\BladeCompilerFactory;
use ShieldCI\Support\EloquentModelDetector;
use ShieldCI\Support\ModelVariableScanner;
use ShieldCI\Support\ViewBindingRegistry;
use ShieldCI\Support\ViewRenderScanner;

/**
 * Identifies missing eager loading that causes N+1 query problems.
 *
 * Checks for:
 * - Relationship access inside loops
 * - Missing with() or load() calls
 * - Common patterns like $post->user in foreach
 */
class EloquentNPlusOneAnalyzer extends AbstractFileAnalyzer
{
    /**
     * @param  AstParser  $parser  Narrowed from ParserInterface because the Blade path names
     *                             the template it compiled and translates the failing line
     *                             back to it, and only the concrete parser declares those
     *                             parameters. PHP passes extra arguments to a userland method
     *                             without complaint, so a wider hint would let an
     *                             implementation that ignores both regress this silently.
     */
    public function __construct(
        private AstParser $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'eloquent-n-plus-one',
            name: 'Eloquent N+1 Query Analyzer',
            description: 'Identifies missing eager loading that causes N+1 query performance problems',
            category: Category::BestPractices,
            severity: Severity::High,
            tags: ['performance', 'eloquent', 'database', 'n+1', 'optimization'],
            timeToFix: 30
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $allFiles = $this->getPhpFiles();

        $scanner = new EloquentModelRelationshipScanner($this->parser);
        $scanResult = $scanner->scan($allFiles);

        $viewsBase = rtrim((string) $this->basePath, '/').'/resources/views';
        $bindingRegistry = (new ViewRenderScanner($this->parser))->scan(array_values($allFiles), $viewsBase);

        foreach ($allFiles as $file) {
            // N+1 is a request-path concern. One-time DB scaffolding (seeders, migrations,
            // factories) idiomatically loops upserts/lookups where query count is irrelevant.
            if ($this->shouldSkipFile($file)) {
                continue;
            }

            if (str_ends_with($file, '.blade.php')) {
                $this->analyzeBladeFile($file, $bindingRegistry, $scanResult, $issues);

                continue;
            }

            try {
                $ast = $this->parser->parseFile($file);

                if (empty($ast)) {
                    continue;
                }

                $visitor = new NPlusOneVisitor($scanResult);
                $traverser = new NodeTraverser;
                $traverser->addVisitor(new ParentConnectingVisitor);
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getIssues() as $issue) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: "Potential N+1 query: accessing '{$issue['relationship']}' inside loop",
                        filePath: $file,
                        lineNumber: $issue['line'],
                        severity: $this->metadata()->severity,
                        recommendation: $this->getRecommendation($issue['relationship'], $issue['loop_type']),
                        metadata: [
                            'relationship' => $issue['relationship'],
                            'loop_type' => $issue['loop_type'],
                            'variable' => $issue['variable'],
                            'file' => $file,
                        ]
                    );
                }

                // Process query-inside-loop issues
                foreach ($visitor->getQueryIssues() as $issue) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: "N+1 query: executing '{$issue['query']}' inside loop",
                        filePath: $file,
                        lineNumber: $issue['line'],
                        severity: $this->metadata()->severity,
                        recommendation: $this->getQueryRecommendation($issue['query'], $issue['loop_type']),
                        metadata: [
                            'query' => $issue['query'],
                            'loop_type' => $issue['loop_type'],
                            'file' => $file,
                        ]
                    );
                }
            } catch (\Throwable $e) {
                // Skip files that can't be parsed
                continue;
            }
        }

        if (empty($issues)) {
            return $this->passed('No potential N+1 query issues detected');
        }

        $totalIssues = count($issues);

        return $this->resultBySeverity(
            "Found {$totalIssues} potential N+1 query issue(s)",
            $issues
        );
    }

    /**
     * Skip one-time database scaffolding directories.
     *
     * Seeders, migrations, and factories run off the request path, so query count
     * inside their loops is irrelevant — looping upserts/lookups there is idiomatic.
     */
    private function shouldSkipFile(string $file): bool
    {
        $normalized = strtolower(str_replace('\\', '/', $file));

        foreach (['/database/migrations/', '/database/seeders/', '/database/factories/'] as $dir) {
            if (str_contains($normalized, $dir)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get recommendation for relationship N+1 issue.
     */
    private function getRecommendation(string $relationship, string $loopType): string
    {
        return "Accessing the '{$relationship}' relationship inside a {$loopType} will trigger a separate database query for each iteration, causing an N+1 query problem. ";
    }

    /**
     * Get recommendation for query-inside-loop N+1 issue.
     */
    private function getQueryRecommendation(string $query, string $loopType): string
    {
        return "Executing '{$query}' inside a {$loopType} triggers a separate database query for each iteration. Consider fetching all required data before the loop using whereIn() or eager loading, then filter in-memory.";
    }

    /**
     * Analyze a single Blade view, seeded with the controller-bound variable types and eager
     * loads that a template cannot derive on its own.
     *
     * @param  array<int, Issue>  $issues
     */
    private function analyzeBladeFile(string $file, ViewBindingRegistry $bindingRegistry, ModelScanResult $scanResult, array &$issues): void
    {
        $normalized = strtolower(str_replace('\\', '/', $file));
        if (str_contains($normalized, '/vendor/')) {
            return;
        }

        $bindings = $bindingRegistry->resolve($file);
        if ($bindings === null) {
            return; // no resolvable render site → skip the view
        }

        $content = FileParser::readFile($file);
        if ($content === null) {
            return;
        }
        $compiled = BladeCompilerFactory::compile($content);
        if ($compiled === null) {
            return;
        }

        // The parsed source is compiled output, so name the Blade file it came from and map
        // any failing compiled line back through the same line map the issue loops below
        // use. Without both, a template this analyzer silently skips is logged as an
        // anonymous blob of PHP naming no file, and two such blobs from two templates
        // collapse into one entry under the content-hash key the parser falls back to.
        //
        // The suffix is BladeCompilerFactory's so that logic-in-blade, which compiles the
        // same templates, produces an identical key: one skipped template, one entry.
        //
        // An unmapped line returns 0, which core normalises to a null line. That is
        // deliberately not what the issue loops do with the same lookup: a finding it cannot
        // place is dropped, because a wrong Blade line is worse than none, whereas a failure
        // it cannot place must still be recorded.
        $ast = $this->parser->parseCode(
            $compiled['compiledPhp'],
            $file.BladeCompilerFactory::COMPILED_ORIGIN_SUFFIX,
            fn (int $compiledLine): int => $compiled['lineMap'][$compiledLine] ?? 0,
        );
        if ($ast === []) {
            return;
        }

        $seed = [];
        foreach ($bindings as $var => $binding) {
            $seed[$var] = ['type' => $binding['type'], 'eagerLoads' => $binding['eagerLoads']];
        }

        $visitor = new NPlusOneVisitor($scanResult, $seed);
        $traverser = new NodeTraverser;
        $traverser->addVisitor(new ParentConnectingVisitor);
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        foreach ($visitor->getIssues() as $issue) {
            $bladeLine = $compiled['lineMap'][$issue['line']] ?? null;
            if ($bladeLine === null) {
                continue;
            }
            // The visitor reports the loop variable (e.g. 'city'), but bindings are keyed by
            // the render-bound variable (e.g. 'cities') — trace back through the loop var's
            // origin to find the binding that actually carries a `source`.
            $origin = $visitor->originOf($issue['variable']) ?? $issue['variable'];
            $source = $bindings[$origin]['source'] ?? 'the controller';
            $issues[] = $this->createIssueWithSnippet(
                message: "Potential N+1 query: accessing '{$issue['relationship']}' inside loop",
                filePath: $file,
                lineNumber: $bladeLine,
                severity: $this->metadata()->severity,
                recommendation: "\${$issue['variable']} reaches this view from {$source}. Eager-load the '{$issue['relationship']}' relation there (with()) so the view iterates data already in memory.",
                metadata: [
                    'relationship' => $issue['relationship'],
                    'source' => $source,
                    'file' => $file,
                ],
            );
        }

        // Process query-inside-loop issues (an actual query executed per iteration, as
        // opposed to a lazy relationship access above) — the most severe N+1 shape, and it
        // must be reported from a Blade template exactly like the plain-PHP path does.
        foreach ($visitor->getQueryIssues() as $issue) {
            $bladeLine = $compiled['lineMap'][$issue['line']] ?? null;
            if ($bladeLine === null) {
                continue;
            }
            $issues[] = $this->createIssueWithSnippet(
                message: "N+1 query: executing '{$issue['query']}' inside loop",
                filePath: $file,
                lineNumber: $bladeLine,
                severity: $this->metadata()->severity,
                recommendation: $this->getQueryRecommendation($issue['query'], $issue['loop_type']),
                metadata: [
                    'query' => $issue['query'],
                    'loop_type' => $issue['loop_type'],
                    'file' => $file,
                ]
            );
        }
    }
}

/**
 * Maps model class names to their Eloquent relationship method names, including the ones
 * reached through traits and parent classes.
 */
class RelationshipRegistry
{
    /** @var array<string, array<string>> */
    private array $map = [];

    /** @var array<string, true> */
    private array $selfDeclared = [];

    /** @var array<string, true> */
    private array $fullyResolved = [];

    /** @var array<string, array<string>> */
    private array $members = [];

    public function add(string $model, string $relation): void
    {
        $this->map[$model][] = $relation;
    }

    public function has(string $model, string $relation): bool
    {
        return in_array($relation, $this->map[$model] ?? [], true);
    }

    /**
     * Record that $model states a relationship in its own body.
     *
     * An inherited relationship proves a name IS one, but says nothing about the names
     * that are absent, because the chain may leave the scanned paths. A relationship the
     * class states itself is the narrower signal the analyzer has always used to answer
     * an absent name conclusively, and it keeps exactly the reach it had before.
     */
    public function markSelfDeclared(string $model): void
    {
        $this->selfDeclared[$model] = true;
    }

    public function declaresOwn(string $model): bool
    {
        return isset($this->selfDeclared[$model]);
    }

    /**
     * Record that every class and trait $model reaches was read, so the relationship list
     * above is exhaustive and the method names below are every method it has.
     *
     * Only a model read in full can answer an absent name conclusively. A chain that
     * leaves the scanned paths, a trait alias that renames a method, or a magic __get
     * all leave members the scan cannot see, and such a model keeps guessing.
     */
    public function markFullyResolved(string $model): void
    {
        $this->fullyResolved[$model] = true;
    }

    public function isFullyResolved(string $model): bool
    {
        return isset($this->fullyResolved[$model]);
    }

    /**
     * Every method name declared anywhere in $model's chain, lowercased because
     * method_exists is case insensitive.
     */
    public function addMember(string $model, string $method): void
    {
        $this->members[$model][] = $method;
    }

    public function hasMember(string $model, string $method): bool
    {
        return in_array($method, $this->members[$model] ?? [], true);
    }
}

/**
 * Tracks model attributes (from $fillable, $casts, $appends) per model class.
 *
 * Used to distinguish regular column access from relationship access.
 */
class ModelAttributesRegistry
{
    /** @var array<string, array<string>> */
    private array $map = [];

    public function add(string $model, string $attribute): void
    {
        $this->map[$model][] = $attribute;
    }

    public function has(string $model, string $attribute): bool
    {
        return in_array($attribute, $this->map[$model] ?? [], true);
    }
}

/**
 * Tracks Eloquent accessor names per model class.
 *
 * Derived from getXxxAttribute() method definitions. Accessors expose computed
 * properties and should never be mistaken for relationships.
 */
class AccessorRegistry
{
    /** @var array<string, array<string>> */
    private array $map = [];

    public function add(string $model, string $accessor): void
    {
        $this->map[$model][] = $accessor;
    }

    public function has(string $model, string $accessor): bool
    {
        return in_array($accessor, $this->map[$model] ?? [], true);
    }
}

/**
 * Result of scanning all PHP files — bundles all three model-aware registries.
 */
class ModelScanResult
{
    public function __construct(
        public readonly RelationshipRegistry $relationships,
        public readonly ModelAttributesRegistry $attributes,
        public readonly AccessorRegistry $accessors,
    ) {}
}

/**
 * Scans PHP files to build the registries the analyzer uses to tell a relationship from a
 * column.
 *
 * A model states only part of itself in its own body: the rest arrives through the traits
 * it uses and the class it extends. So the scan runs in two stages. It first indexes every
 * class and trait declaration it meets by fully qualified name, recording the members each
 * states and the names of its parent and its traits. It then walks that graph and flattens
 * what each class actually has.
 *
 * No file lookup is involved. Every file is parsed during the first stage anyway, so a
 * declaration is either already in the table or outside the scanned paths, and the table
 * is released once the registries are built.
 */
class EloquentModelRelationshipScanner
{
    /** @var array<string> */
    private const RELATION_METHODS = [
        'hasOne', 'hasMany', 'hasOneThrough', 'hasManyThrough',
        'belongsTo', 'belongsToMany', 'morphTo', 'morphOne',
        'morphMany', 'morphToMany', 'morphedByMany',
    ];

    /**
     * Return types that declare a method to be a relationship on their own.
     *
     * A model may hand the body off to a helper the shape matching below cannot follow,
     * but the declared type still names the contract.
     *
     * @var array<string>
     */
    private const RELATION_RETURN_TYPES = [
        'Illuminate\Database\Eloquent\Relations\Relation',
        'Illuminate\Database\Eloquent\Relations\HasOne',
        'Illuminate\Database\Eloquent\Relations\HasMany',
        'Illuminate\Database\Eloquent\Relations\HasOneOrMany',
        'Illuminate\Database\Eloquent\Relations\HasOneThrough',
        'Illuminate\Database\Eloquent\Relations\HasManyThrough',
        'Illuminate\Database\Eloquent\Relations\BelongsTo',
        'Illuminate\Database\Eloquent\Relations\BelongsToMany',
        'Illuminate\Database\Eloquent\Relations\MorphTo',
        'Illuminate\Database\Eloquent\Relations\MorphOne',
        'Illuminate\Database\Eloquent\Relations\MorphMany',
        'Illuminate\Database\Eloquent\Relations\MorphOneOrMany',
        'Illuminate\Database\Eloquent\Relations\MorphToMany',
    ];

    /**
     * Classes and traits the scan never reaches, mapped to the relationship methods each
     * declares. An empty list means the entry declares none.
     *
     * Getting an entry wrong is asymmetric. Listing a trait that does declare a
     * relationship silences a real N+1. Omitting one costs nothing: the name simply stays
     * unknown and the naming heuristic answers it, exactly as before. Every entry here was
     * read off the package source.
     *
     * The framework half is exhaustive for Laravel 12: of every trait shipped under
     * Illuminate, only HasDatabaseNotifications returns a relation builder.
     *
     * @var array<string, array<string>>
     */
    private const KNOWN_EXTERNAL_DECLARATIONS = [
        // Eloquent base classes. hasMany() and friends on Model are relation factories,
        // not named relationships.
        'Illuminate\Database\Eloquent\Model' => [],
        'Illuminate\Foundation\Auth\User' => [],
        'Illuminate\Database\Eloquent\Relations\Pivot' => [],
        'Illuminate\Database\Eloquent\Relations\MorphPivot' => [],

        // Framework traits that declare no relationships.
        'Illuminate\Database\Eloquent\Factories\HasFactory' => [],
        'Illuminate\Database\Eloquent\SoftDeletes' => [],
        'Illuminate\Database\Eloquent\Prunable' => [],
        'Illuminate\Database\Eloquent\MassPrunable' => [],
        'Illuminate\Database\Eloquent\BroadcastsEvents' => [],
        'Illuminate\Database\Eloquent\Concerns\HasUuids' => [],
        'Illuminate\Database\Eloquent\Concerns\HasUlids' => [],
        'Illuminate\Auth\Authenticatable' => [],
        'Illuminate\Auth\MustVerifyEmail' => [],
        'Illuminate\Auth\Passwords\CanResetPassword' => [],
        'Illuminate\Foundation\Auth\Access\Authorizable' => [],
        'Illuminate\Notifications\RoutesNotifications' => [],

        // Traits that do. readNotifications() and unreadNotifications() are the
        // notifications() morphMany with a scope applied, so each is a real query.
        'Illuminate\Notifications\Notifiable' => ['notifications', 'readNotifications', 'unreadNotifications'],
        'Illuminate\Notifications\HasDatabaseNotifications' => ['notifications', 'readNotifications', 'unreadNotifications'],
        'Laravel\Sanctum\HasApiTokens' => ['tokens'],
    ];

    /** @var array{relations: array<string>, attributes: array<string>, accessors: array<string>, members: array<string>, fully: bool} */
    private const NO_MEMBERS = ['relations' => [], 'attributes' => [], 'accessors' => [], 'members' => [], 'fully' => false];

    /** @var array<string> Magic methods that answer for members no declaration lists. */
    private const OPAQUE_MAGIC_METHODS = ['__get', '__call', '__callstatic'];

    /**
     * Every class and trait declaration the scan saw, keyed by fully qualified name.
     *
     * `parent` and `traits` hold fully qualified names resolved through the declaring
     * namespace's imports, so the inheritance graph can be walked without touching the
     * filesystem: every file is already parsed by the time this table is complete.
     *
     * @var array<string, array{
     *     kind: string,
     *     short: string,
     *     relations: array<string>,
     *     attributes: array<string>,
     *     accessors: array<string>,
     *     members: array<string>,
     *     parent: ?string,
     *     traits: array<string>,
     *     opaque: bool,
     *     selfDeclared: bool,
     * }>
     */
    private array $declarations = [];

    /**
     * Memoized flattening of $declarations, keyed by fully qualified name.
     *
     * @var array<string, array{relations: array<string>, attributes: array<string>, accessors: array<string>, members: array<string>, fully: bool}>
     */
    private array $resolved = [];

    /**
     * Relationships registered from outside a model's own body, by resolveRelationUsing().
     * Eloquent answers these through __call, so no method of that name is declared
     * anywhere and the member index alone would read the model as not having them.
     *
     * @var array<string, array<string>>
     */
    private array $registeredRelations = [];

    /**
     * Models whose resolveRelationUsing() call names a relationship the scan cannot read,
     * and so cannot be trusted to have been read in full.
     *
     * @var array<string, true>
     */
    private array $registeredRelationsUnreadable = [];

    /**
     * Set when a resolveRelationUsing() call names a model the scan cannot identify, which
     * leaves every model a candidate and so withdraws every conclusive reading.
     */
    private bool $unattributedRegisteredRelation = false;

    public function __construct(private ParserInterface $parser) {}

    /**
     * @param  array<string>  $files
     */
    public function scan(array $files): ModelScanResult
    {
        $this->declarations = [];
        $this->resolved = [];
        $this->registeredRelations = [];
        $this->registeredRelationsUnreadable = [];
        $this->unattributedRegisteredRelation = false;

        foreach ($files as $file) {
            $ast = $this->parser->parseFile($file);
            if (empty($ast)) {
                continue;
            }
            $this->collectStatements($ast, null, []);
        }

        $this->applyRegisteredRelations();

        $result = $this->buildRegistries();

        // The graph has served its purpose. Releasing it keeps nothing but the registries
        // alive for the per-file pass that follows.
        $this->declarations = [];
        $this->resolved = [];
        $this->registeredRelations = [];
        $this->registeredRelationsUnreadable = [];

        return $result;
    }

    /**
     * Fold relationships registered by resolveRelationUsing() into the model they name.
     *
     * They arrive from wherever the call sits, usually a service provider, so they can
     * only be attributed once every declaration has been seen.
     */
    private function applyRegisteredRelations(): void
    {
        foreach ($this->registeredRelations as $fqcn => $names) {
            if (! isset($this->declarations[$fqcn])) {
                continue;
            }

            $this->declarations[$fqcn]['relations'] = [...$this->declarations[$fqcn]['relations'], ...$names];
            $this->declarations[$fqcn]['members'] = [
                ...$this->declarations[$fqcn]['members'],
                ...array_map(strtolower(...), $names),
            ];
        }

        foreach (array_keys($this->registeredRelationsUnreadable) as $fqcn) {
            if (isset($this->declarations[$fqcn])) {
                $this->declarations[$fqcn]['opaque'] = true;
            }
        }
    }

    /**
     * @param  array<Node>  $stmts
     * @param  array<string, string>  $useStatements
     */
    private function collectStatements(array $stmts, ?string $namespace, array $useStatements): void
    {
        $useStatements = [...$useStatements, ...$this->collectImports($stmts)];

        foreach ($stmts as $stmt) {
            if ($stmt instanceof Stmt\Namespace_) {
                $this->collectStatements($stmt->stmts, $stmt->name?->toString(), $useStatements);
            } elseif ($stmt instanceof Stmt\Class_ || $stmt instanceof Stmt\Trait_) {
                $this->collectDeclaration($stmt, $namespace, $useStatements);
            }
        }
    }

    /**
     * Short name to fully qualified name for the class imports declared at this level.
     *
     * Only `use Foo\Bar;` counts. `use function` and `use const` share the statement node
     * but live in separate name contexts, so folding them in would let a function import
     * shadow a class of the same name. A group use reports an unknown type when its items
     * carry their own, so the item wins in that case.
     *
     * @param  array<Node>  $stmts
     * @return array<string, string>
     */
    private function collectImports(array $stmts): array
    {
        $imports = [];

        foreach ($stmts as $stmt) {
            if ($stmt instanceof Stmt\Use_) {
                if ($stmt->type !== Stmt\Use_::TYPE_NORMAL) {
                    continue;
                }

                foreach ($stmt->uses as $use) {
                    $imports[$use->getAlias()->toString()] = $use->name->toString();
                }
            } elseif ($stmt instanceof Stmt\GroupUse) {
                $prefix = $stmt->prefix->toString();

                foreach ($stmt->uses as $use) {
                    $type = $stmt->type === Stmt\Use_::TYPE_UNKNOWN ? $use->type : $stmt->type;
                    if ($type !== Stmt\Use_::TYPE_NORMAL) {
                        continue;
                    }

                    $imports[$use->getAlias()->toString()] = $prefix.'\\'.$use->name->toString();
                }
            }
        }

        return $imports;
    }

    /**
     * Resolve a name written inside a declaration to the fully qualified one PHP would.
     *
     * EloquentModelDetector::resolveClassName answers null for an unqualified name with no
     * import and no enclosing namespace, which for its own callers means "unknown". Here
     * that case is not unknown at all: PHP resolves such a name to the global one. Keeping
     * the distinction matters, because a name that resolves to nothing would be
     * indistinguishable from a class having no parent, and a model whose parent could not
     * be read would then be treated as one with nothing left to read.
     *
     * @param  array<string, string>  $useStatements
     */
    private function resolveDeclarationName(string $name, array $useStatements, ?string $namespace): string
    {
        return EloquentModelDetector::resolveClassName($name, $useStatements, $namespace) ?? $name;
    }

    /**
     * @param  array<string, string>  $useStatements
     */
    private function collectDeclaration(Stmt\ClassLike $decl, ?string $namespace, array $useStatements): void
    {
        if ($decl->name === null) {
            return; // Anonymous class
        }

        $short = $decl->name->toString();
        $fqcn = $namespace !== null && $namespace !== '' ? $namespace.'\\'.$short : $short;

        $parent = null;
        if ($decl instanceof Stmt\Class_ && $decl->extends !== null) {
            $parent = $this->resolveDeclarationName($decl->extends->toString(), $useStatements, $namespace);
        }

        $members = $this->collectMembers($decl, $fqcn, $useStatements, $namespace);
        $used = $this->collectUsedTraits($decl, $useStatements, $namespace);

        $this->declarations[$fqcn] = [
            'kind' => $decl instanceof Stmt\Trait_ ? 'trait' : 'class',
            'short' => $short,
            'relations' => $members['relations'],
            'attributes' => $members['attributes'],
            'accessors' => $members['accessors'],
            'members' => $members['members'],
            'parent' => $parent,
            'traits' => $used['traits'],
            'opaque' => $members['opaque'] || $used['opaque'],
            'selfDeclared' => $members['relations'] !== [],
        ];
    }

    /**
     * Fully qualified names of the traits a declaration uses. Traits use traits, so this
     * is walked recursively during flattening rather than expanded here.
     *
     * An adaptation makes the declaration opaque. `use T { posts as archived; }` gives the
     * class a relationship named archived that appears under that name neither in the
     * trait nor in the class, and `insteadof` picks a winner between two that the
     * flattened lists have no way to represent.
     *
     * @param  array<string, string>  $useStatements
     * @return array{traits: array<string>, opaque: bool}
     */
    private function collectUsedTraits(Stmt\ClassLike $decl, array $useStatements, ?string $namespace): array
    {
        $traits = [];
        $opaque = false;

        foreach ($decl->stmts as $stmt) {
            if (! ($stmt instanceof Stmt\TraitUse)) {
                continue;
            }

            if ($stmt->adaptations !== []) {
                $opaque = true;
            }

            foreach ($stmt->traits as $trait) {
                $traits[] = $this->resolveDeclarationName($trait->toString(), $useStatements, $namespace);
            }
        }

        return ['traits' => $traits, 'opaque' => $opaque];
    }

    /**
     * The relationships, mass-assignable attributes and accessors a declaration states in
     * its own body, before anything it inherits is folded in.
     *
     * @param  array<string, string>  $useStatements
     * @return array{relations: array<string>, attributes: array<string>, accessors: array<string>, members: array<string>, opaque: bool}
     */
    private function collectMembers(Stmt\ClassLike $decl, string $fqcn, array $useStatements, ?string $namespace): array
    {
        $relations = [];
        $attributes = [];
        $accessors = [];
        $members = [];
        $opaque = false;

        foreach ($decl->stmts as $stmt) {
            // Scan class properties: $fillable, $casts, $appends
            if ($stmt instanceof Stmt\Property) {
                foreach ($this->attributeNames($stmt) as $attribute) {
                    $attributes[] = $attribute;
                }

                continue;
            }

            if (! ($stmt instanceof Stmt\ClassMethod)) {
                continue;
            }

            $methodName = $stmt->name->toString();
            $members[] = strtolower($methodName);

            // A declaration that answers for names it does not list can hold a
            // relationship the scan has no way to see.
            if (in_array(strtolower($methodName), self::OPAQUE_MAGIC_METHODS, true)) {
                $opaque = true;
            }

            $body = $this->collectBody($stmt, $fqcn, $useStatements, $namespace);

            // Detect accessor methods: getXxxAttribute()
            if ($this->isAccessorMethod($methodName)) {
                $accessors[] = $this->accessorMethodToPropertyName($methodName);

                continue;
            }

            if ($this->declaresRelationReturnType($stmt, $useStatements, $namespace) ||
                $this->returnsRelationBuilder($body)) {
                $relations[] = $methodName;
            }
        }

        return [
            'relations' => $relations,
            'attributes' => $attributes,
            'accessors' => $accessors,
            'members' => $members,
            'opaque' => $opaque,
        ];
    }

    /**
     * Walk a method body once, collecting the returns that belong to it and any
     * relationship it registers on a model from outside that model's own body.
     *
     * @param  array<string, string>  $useStatements
     * @return array<Stmt\Return_>
     */
    private function collectBody(Stmt\ClassMethod $method, string $fqcn, array $useStatements, ?string $namespace): array
    {
        $collector = new MethodBodyCollector;
        $traverser = new NodeTraverser;
        $traverser->addVisitor($collector);
        $traverser->traverse($method->stmts ?? []);

        foreach ($collector->registeredRelations as $registered) {
            $this->recordRegisteredRelation($registered, $fqcn, $useStatements, $namespace);
        }

        return $collector->returns;
    }

    /**
     * @param  array{class: ?string, relation: ?string}  $registered
     * @param  array<string, string>  $useStatements
     */
    private function recordRegisteredRelation(array $registered, string $fqcn, array $useStatements, ?string $namespace): void
    {
        $class = $registered['class'];

        if ($class === null) {
            // The receiver is a variable or an expression, so the model being extended
            // cannot be named and no model can be called fully read.
            $this->unattributedRegisteredRelation = true;

            return;
        }

        $target = in_array(strtolower($class), ['self', 'static'], true)
            ? $fqcn
            : $this->resolveDeclarationName($class, $useStatements, $namespace);

        if ($registered['relation'] === null) {
            $this->registeredRelationsUnreadable[$target] = true;

            return;
        }

        $this->registeredRelations[$target][] = $registered['relation'];
    }

    /**
     * @param  array<Stmt\Return_>  $returns
     */
    private function returnsRelationBuilder(array $returns): bool
    {
        foreach ($returns as $return) {
            if ($return->expr === null) {
                continue;
            }

            $rootCall = $this->findDeepestMethodCall($return->expr);
            if ($rootCall === null) {
                continue;
            }

            if ($rootCall->var instanceof Expr\Variable &&
                is_string($rootCall->var->name) &&
                $rootCall->var->name === 'this' &&
                $rootCall->name instanceof Node\Identifier &&
                in_array($rootCall->name->toString(), self::RELATION_METHODS, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array<string, string>  $useStatements
     */
    private function declaresRelationReturnType(Stmt\ClassMethod $method, array $useStatements, ?string $namespace): bool
    {
        $type = $method->returnType;

        if ($type instanceof Node\NullableType) {
            $type = $type->type;
        }

        if (! ($type instanceof Node\Name)) {
            return false;
        }

        $fqcn = $this->resolveDeclarationName($type->toString(), $useStatements, $namespace);

        return in_array($fqcn, self::RELATION_RETURN_TYPES, true);
    }

    /**
     * Flatten a declaration's own members with everything it reaches through its trait
     * uses and its parent chain, memoized by fully qualified name.
     *
     * `fully` records whether every edge out of the declaration was accounted for. It is
     * what separates "this name is not a relationship" from "this name is not one of the
     * relationships I could see", and it only survives if every ancestor kept it.
     *
     * @return array{relations: array<string>, attributes: array<string>, accessors: array<string>, members: array<string>, fully: bool}
     */
    private function resolveMembers(string $fqcn): array
    {
        if (array_key_exists($fqcn, $this->resolved)) {
            return $this->resolved[$fqcn];
        }

        // Reserve the slot before recursing. PHP rejects cyclic extends and trait-use
        // graphs, but half-edited source still reaches this scanner, and re-entering a
        // declaration already in progress then resolves to the empty record instead of
        // recursing forever.
        $this->resolved[$fqcn] = self::NO_MEMBERS;

        if (! isset($this->declarations[$fqcn])) {
            // The chain has left the scanned paths. Either it ends at a class or trait
            // whose relationships are known, or nothing more can be said about it.
            $known = self::KNOWN_EXTERNAL_DECLARATIONS[$fqcn] ?? null;

            return $this->resolved[$fqcn] = $known === null
                ? self::NO_MEMBERS
                : [
                    'relations' => $known,
                    'attributes' => [],
                    'accessors' => [],
                    'members' => array_map(strtolower(...), $known),
                    'fully' => true,
                ];
        }

        $own = $this->declarations[$fqcn];
        $relations = $own['relations'];
        $attributes = $own['attributes'];
        $accessors = $own['accessors'];
        $members = $own['members'];
        $fully = ! $own['opaque'];

        $ancestors = $own['traits'];
        if ($own['parent'] !== null) {
            $ancestors[] = $own['parent'];
        }

        foreach ($ancestors as $ancestor) {
            $inherited = $this->resolveMembers($ancestor);
            $relations = [...$relations, ...$inherited['relations']];
            $attributes = [...$attributes, ...$inherited['attributes']];
            $accessors = [...$accessors, ...$inherited['accessors']];
            $members = [...$members, ...$inherited['members']];
            $fully = $fully && $inherited['fully'];
        }

        return $this->resolved[$fqcn] = [
            'relations' => array_values(array_unique($relations)),
            'attributes' => array_values(array_unique($attributes)),
            'accessors' => array_values(array_unique($accessors)),
            'members' => array_values(array_unique($members)),
            'fully' => $fully,
        ];
    }

    private function buildRegistries(): ModelScanResult
    {
        $relationships = new RelationshipRegistry;
        $attributes = new ModelAttributesRegistry;
        $accessors = new AccessorRegistry;

        // The lookup side only ever knows a model by its short name, so two classes
        // sharing one are answered together. Their relationships merge, as they always
        // have, but neither can be spoken for conclusively: an absent name would be
        // judged partly on a class the code never referred to.
        $shortNameCounts = array_count_values(array_column(
            array_filter($this->declarations, fn (array $d): bool => $d['kind'] === 'class'),
            'short'
        ));

        foreach ($this->declarations as $fqcn => $declaration) {
            // A trait reaches the registries through the classes that use it. Keying one
            // by a trait's own short name would let a trait named Post answer for the model.
            if ($declaration['kind'] !== 'class') {
                continue;
            }

            $members = $this->resolveMembers($fqcn);
            $short = $declaration['short'];

            foreach ($members['relations'] as $relation) {
                $relationships->add($short, $relation);
            }

            foreach ($members['attributes'] as $attribute) {
                $attributes->add($short, $attribute);
            }

            foreach ($members['accessors'] as $accessor) {
                $accessors->add($short, $accessor);
            }

            foreach ($members['members'] as $member) {
                $relationships->addMember($short, $member);
            }

            if ($declaration['selfDeclared']) {
                $relationships->markSelfDeclared($short);
            }

            if ($members['fully'] &&
                ! $this->unattributedRegisteredRelation &&
                ($shortNameCounts[$short] ?? 0) === 1) {
                $relationships->markFullyResolved($short);
            }
        }

        return new ModelScanResult($relationships, $attributes, $accessors);
    }

    /**
     * Attribute names stated by a $fillable, $casts or $appends property.
     *
     * @return array<string>
     */
    private function attributeNames(Stmt\Property $property): array
    {
        $names = [];

        foreach ($property->props as $prop) {
            $propName = $prop->name->toString();
            if (! in_array($propName, ['fillable', 'casts', 'appends'], true)) {
                continue;
            }
            if (! ($prop->default instanceof Expr\Array_)) {
                continue;
            }

            foreach ($prop->default->items as $item) {
                if ($item === null) {
                    continue;
                }
                // $fillable / $appends: values are strings (['name', 'email'])
                if ($propName !== 'casts' && $item->value instanceof Node\Scalar\String_) {
                    $names[] = $item->value->value;
                }
                // $casts: keys are attribute names (['name' => 'string'])
                if ($propName === 'casts' && $item->key instanceof Node\Scalar\String_) {
                    $names[] = $item->key->value;
                }
            }
        }

        return $names;
    }

    /**
     * True when a method name matches the getXxxAttribute() accessor convention.
     */
    private function isAccessorMethod(string $methodName): bool
    {
        return str_starts_with($methodName, 'get') &&
               str_ends_with($methodName, 'Attribute') &&
               strlen($methodName) > 12; // longer than "getAttribute"
    }

    /**
     * Convert getFirstNameAttribute to first_name.
     */
    private function accessorMethodToPropertyName(string $methodName): string
    {
        $inner = substr($methodName, 3, -9); // strip 'get' and 'Attribute'
        // CamelCase to snake_case
        $snake = strtolower((string) preg_replace('/[A-Z]/', '_$0', lcfirst($inner)));

        return ltrim($snake, '_');
    }

    /**
     * Walk a MethodCall chain and return the deepest MethodCall node
     * (the one whose var is NOT a MethodCall, typically Variable('this')).
     */
    private function findDeepestMethodCall(Node $expr): ?Expr\MethodCall
    {
        $deepest = null;
        $current = $expr;
        while ($current instanceof Expr\MethodCall) {
            $deepest = $current;
            $current = $current->var;
        }

        return $deepest;
    }
}

/**
 * Reads a method body once for the two things the scanner needs from it: the returns that
 * belong to the method, and any relationship it registers on a model from outside that
 * model's own body.
 *
 * Returns stop at a nested function-like or class declaration, because a closure's
 * `return $this->hasMany(...)` belongs to the closure rather than to the method enclosing
 * it. A registration does not stop there: resolveRelationUsing() takes a closure of its
 * own and is often called from inside one.
 */
class MethodBodyCollector extends NodeVisitorAbstract
{
    /** @var array<Stmt\Return_> */
    public array $returns = [];

    /**
     * Receiver and relationship name of each resolveRelationUsing() call, with null for
     * either part the call does not state literally.
     *
     * @var array<array{class: ?string, relation: ?string}>
     */
    public array $registeredRelations = [];

    private int $nestedDepth = 0;

    public function enterNode(Node $node)
    {
        if ($node instanceof Expr\Closure ||
            $node instanceof Expr\ArrowFunction ||
            $node instanceof Stmt\ClassLike ||
            $node instanceof Stmt\Function_) {
            $this->nestedDepth++;

            return null;
        }

        if ($this->nestedDepth === 0 && $node instanceof Stmt\Return_) {
            $this->returns[] = $node;
        }

        if ($node instanceof Expr\StaticCall &&
            $node->name instanceof Node\Identifier &&
            $node->name->toString() === 'resolveRelationUsing') {
            $argument = $node->args[0] ?? null;

            $this->registeredRelations[] = [
                'class' => $node->class instanceof Node\Name ? $node->class->toString() : null,
                'relation' => $argument instanceof Node\Arg && $argument->value instanceof Node\Scalar\String_
                    ? $argument->value->value
                    : null,
            ];
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        if ($node instanceof Expr\Closure ||
            $node instanceof Expr\ArrowFunction ||
            $node instanceof Stmt\ClassLike ||
            $node instanceof Stmt\Function_) {
            $this->nestedDepth--;
        }

        return null;
    }
}

/**
 * Visitor to detect N+1 query patterns.
 */
class NPlusOneVisitor extends NodeVisitorAbstract
{
    /** @var string Loop type constants */
    private const LOOP_TYPE_FOREACH = 'foreach';

    private const LOOP_TYPE_FOR = 'for';

    private const LOOP_TYPE_WHILE = 'while';

    private const LOOP_TYPE_DO_WHILE = 'do-while';

    /** @var array<string> Common model properties that are not relationships */
    private const EXCLUDED_PROPERTIES = [
        // Primary keys and identifiers
        'id', 'uuid', 'key', 'code', 'token', 'hash', 'reference',
        // Timestamps
        'created_at', 'updated_at', 'deleted_at', 'published_at', 'expires_at',
        'verified_at', 'email_verified_at', 'started_at', 'ended_at', 'sent_at',
        // Authentication
        'password', 'remember_token', 'api_token', 'secret',
        // Common string fields
        'name', 'title', 'label', 'slug', 'email', 'username', 'nickname',
        'description', 'content', 'body', 'text', 'summary', 'excerpt', 'message',
        // URLs and paths
        'url', 'path', 'link', 'href', 'src', 'route',
        // Media
        'image', 'avatar', 'photo', 'picture', 'icon', 'thumbnail', 'logo', 'file',
        // Contact info
        'phone', 'address', 'street', 'city', 'state', 'country', 'zip', 'postal_code',
        // Localization
        'locale', 'timezone', 'currency', 'lang', 'language',
        // Numeric values
        'count', 'total', 'amount', 'price', 'quantity', 'balance', 'score', 'rating',
        'order', 'position', 'sort', 'rank', 'level', 'priority', 'weight', 'size',
        // Status and flags (values, not prefixed booleans)
        'status', 'state', 'type', 'kind', 'category', 'role', 'group',
        'active', 'enabled', 'visible', 'published', 'approved', 'verified',
        // JSON/array fields
        'data', 'meta', 'metadata', 'settings', 'options', 'config', 'attributes',
        'properties', 'payload', 'extra', 'info', 'details', 'preferences',
        // Miscellaneous
        'value', 'result', 'output', 'input', 'response', 'request',
        'color', 'format', 'version', 'note', 'notes', 'comment', 'reason',
    ];

    /** @var array<string> Common methods that are not relationship accessors */
    private const EXCLUDED_METHODS = [
        // Eloquent model methods
        'save', 'delete', 'update', 'refresh', 'replicate', 'touch',
        'toarray', 'tojson', 'tobase', 'jsonserialize',
        'getkey', 'getkeyname', 'getkeytype', 'getqualifiedkeyname',
        'getattribute', 'setattribute', 'getattributes', 'getoriginal',
        'getdirty', 'getchanges', 'getrelations', 'getrelation',
        'isdirty', 'isclean', 'waschanged', 'getraworiginal',
        'only', 'except', 'makevisible', 'makehidden',
        'append', 'setappends', 'getappends',
        'fill', 'forcefill', 'qualify', 'qualifycolumn',
        'relationloaded', // Checks if relation is loaded (not a relationship itself)
        // Common accessors/mutators patterns
        'getformattedattribute', 'format', 'formatted',
        // Collection/array methods
        'first', 'last', 'get', 'all', 'pluck', 'map', 'filter', 'each',
        'count', 'sum', 'avg', 'min', 'max', 'isempty', 'isnotempty',
        // Validation and checks
        'validate', 'isvalid', 'exists',
        // String representation
        'tostring', '__tostring', 'render', 'display',
    ];

    /** @var array<string> Facades/classes that have query-like methods but are NOT database queries */
    private const NON_QUERY_CLASSES = [
        // Laravel facades
        'cache', 'config', 'session', 'storage', 'cookie', 'auth',
        'log', 'mail', 'event', 'queue', 'broadcast', 'notification',
        'gate', 'validator', 'view', 'response', 'request', 'redirect',
        'url', 'file', 'hash', 'crypt', 'artisan', 'bus', 'http', 'redis',
        'guzzle', 'soap', 'curl',
        // Common non-Eloquent classes
        'arr', 'str', 'collection', 'carbon', 'datetime',
    ];

    /** @var array<string> Methods that are batch operations (solutions, not N+1 problems) */
    private const BATCH_OPERATION_METHODS = [
        'chunk', 'chunkbyid', 'each', 'eachbyid', 'cursor', 'lazy', 'lazybychunksof',
    ];

    /**
     * @var array<string> Pessimistic-lock builder methods. A query acquiring one is
     *                    inherently per-row and can neither be eager-loaded nor batched.
     */
    private const LOCK_METHODS = ['lockforupdate', 'sharedlock'];

    /**
     * @var array<int, array{relationship: string, line: int, loop_type: string, variable: string}>
     */
    private array $issues = [];

    /**
     * @var array<int, array{query: string, line: int, loop_type: string}>
     */
    private array $queryIssues = [];

    /**
     * Stack of loop contexts (for nested loop support).
     *
     * @var array<int, array{variables: array<string>, type: string}>
     */
    private array $loopStack = [];

    /**
     * spl_object_id() of exists()/doesntExist() query nodes that form a uniqueness-probe
     * loop condition (generate-until-unique idiom) and must not be flagged as N+1.
     *
     * @var array<int, true>
     */
    private array $uniquenessProbeNodes = [];

    /**
     * Track relationships checked with relationLoaded() per loop variable.
     * Key format: "loopVariable:relationship"
     *
     * @var array<string, bool>
     */
    private array $relationLoadedChecks = [];

    private ModelVariableScanner $modelVars;

    private RelationshipRegistry $relationshipRegistry;

    private ModelAttributesRegistry $modelAttributesRegistry;

    private AccessorRegistry $accessorRegistry;

    /**
     * Pre-known variable bindings (e.g. controller context carried into a Blade view) are
     * applied to the model-variable scanner before traversal begins.
     *
     * @param  array<string, array{type: ?string, eagerLoads: list<string>}>  $seedBindings
     */
    public function __construct(ModelScanResult $scanResult, array $seedBindings = [])
    {
        $this->relationshipRegistry = $scanResult->relationships;
        $this->modelAttributesRegistry = $scanResult->attributes;
        $this->accessorRegistry = $scanResult->accessors;
        $this->modelVars = new ModelVariableScanner;

        foreach ($seedBindings as $var => $binding) {
            $this->modelVars->seed($var, $binding['type'], $binding['eagerLoads']);
        }
    }

    public function enterNode(Node $node)
    {
        // Feed every node to the model-variable scanner so it can infer variable
        // types (e.g. $posts → Collection<Post>) and eager-loaded relationships.
        $this->modelVars->enterNode($node);

        // Track loop entry
        if ($node instanceof Stmt\Foreach_) {
            // Infer loop variable type and copy eager loaded relationships
            $this->inferLoopVariableType($node);

            $loopVariable = null;
            if ($node->valueVar instanceof Expr\Variable && is_string($node->valueVar->name)) {
                $loopVariable = $node->valueVar->name;
            }

            $this->loopStack[] = [
                'variables' => $loopVariable !== null ? [$loopVariable] : [],
                'type' => self::LOOP_TYPE_FOREACH,
            ];

            return null;
        }

        if ($node instanceof Stmt\For_) {
            $loopVar = $this->extractForLoopVariable($node);
            $this->loopStack[] = [
                'variables' => $loopVar !== null ? [$loopVar] : [],
                'type' => self::LOOP_TYPE_FOR,
            ];

            return null;
        }

        if ($node instanceof Stmt\While_) {
            $condVars = $this->extractConditionVariables($node->cond);
            $this->registerUniquenessProbes($node->cond, $node->stmts);
            $this->loopStack[] = [
                'variables' => $condVars,
                'type' => self::LOOP_TYPE_WHILE,
            ];

            return null;
        }

        if ($node instanceof Stmt\Do_) {
            $condVars = $this->extractConditionVariables($node->cond);
            $this->registerUniquenessProbes($node->cond, $node->stmts);
            $this->loopStack[] = [
                'variables' => $condVars,
                'type' => self::LOOP_TYPE_DO_WHILE,
            ];

            return null;
        }

        // Detect relationship access inside loops (only foreach loops track relationship access)
        $currentLoop = $this->getCurrentLoop();
        if ($currentLoop !== null && ! empty($currentLoop['variables']) && $currentLoop['type'] === self::LOOP_TYPE_FOREACH) {
            $loopVariable = $currentLoop['variables'][0];
            $loopType = $currentLoop['type'];

            // Track relationLoaded() calls as defensive patterns
            if ($node instanceof Expr\MethodCall &&
                $node->var instanceof Expr\Variable &&
                is_string($node->var->name) &&
                $node->var->name === $loopVariable &&
                $node->name instanceof Node\Identifier &&
                $node->name->toString() === 'relationLoaded' &&
                ($node->args[0] ?? null) instanceof Node\Arg &&
                $node->args[0]->value instanceof Node\Scalar\String_) {

                $relationship = $node->args[0]->value->value;
                $this->relationLoadedChecks[$loopVariable.':'.$relationship] = true;
            }

            // Look for property access like $post->user, $post->comments, or $post->user->team
            if ($node instanceof Expr\PropertyFetch) {
                // Build full relationship chain (e.g., ['user', 'team'] for $post->user->team)
                $chain = $this->buildRelationshipChain($node, $loopVariable);

                if ($chain !== null && count($chain) > 0) {
                    // Build dot notation path: 'user.team'
                    $relationshipPath = implode('.', $chain);
                    /** @var string $lastProperty */
                    $lastProperty = end($chain);

                    // Check if the last property looks like a relationship. Only the tail
                    // is judged against the loop variable's model, so a chain whose head is
                    // a plain column on that model has to be rejected separately: reading
                    // $user->settings->notifications walks into a JSON column, and eager
                    // loading the reported path would raise RelationNotFoundException.
                    if ($this->isActualOrProbableRelationship($loopVariable, $lastProperty) &&
                        $this->isActualOrProbableRelationship($loopVariable, $chain[0])) {
                        // Get the first relationship in the chain (e.g., 'user' from 'user.team')
                        $firstRelationship = $chain[0];

                        // Only flag if NOT eager loaded AND NOT checked with relationLoaded()
                        if (! $this->isEagerLoaded($loopVariable, $relationshipPath) &&
                            ! $this->isRelationLoadedChecked($loopVariable, $firstRelationship)) {
                            $this->issues[] = [
                                'relationship' => $relationshipPath,
                                'line' => $node->getStartLine(),
                                'loop_type' => $loopType,
                                'variable' => $loopVariable,
                            ];
                        }
                    }
                }
            }

            // Look for method calls like $post->user() or $post->comments()
            if ($node instanceof Expr\MethodCall) {
                if ($node->var instanceof Expr\Variable &&
                    is_string($node->var->name) &&
                    $node->var->name === $loopVariable &&
                    $node->name instanceof Node\Identifier) {

                    $methodName = $node->name->toString();

                    // Check if this looks like a relationship method
                    if ($this->isActualOrProbableRelationship($loopVariable, $methodName, true)) {
                        // Only flag if NOT eager loaded AND NOT checked with relationLoaded()
                        if (! $this->isEagerLoaded($loopVariable, $methodName) &&
                            ! $this->isRelationLoadedChecked($loopVariable, $methodName)) {
                            $this->issues[] = [
                                'relationship' => $methodName,
                                'line' => $node->getStartLine(),
                                'loop_type' => $loopType,
                                'variable' => $loopVariable,
                            ];
                        }
                    }
                }
            }

            // Detect $loopVar->relationship()->queryMethod() pattern (e.g. $post->comments()->count())
            if ($node instanceof Expr\MethodCall &&
                $node->name instanceof Node\Identifier &&
                $this->isQueryExecutionMethod($node->name->toString())) {

                $inner = $node->var;
                if ($inner instanceof Expr\MethodCall &&
                    $inner->var instanceof Expr\Variable &&
                    is_string($inner->var->name) &&
                    $inner->var->name === $loopVariable &&
                    $inner->name instanceof Node\Identifier) {

                    $relationName = $inner->name->toString();
                    if ($this->isActualOrProbableRelationship($loopVariable, $relationName, true) &&
                        ! $this->isEagerLoaded($loopVariable, $relationName)) {
                        $this->queryIssues[] = [
                            'query' => "\${$loopVariable}->{$relationName}()->{$node->name->toString()}()",
                            'line' => $node->getStartLine(),
                            'loop_type' => $loopType,
                        ];
                    }
                }
            }
        }

        // Detect queries inside loops (classic N+1 pattern)
        if (! empty($this->loopStack)) {
            $currentLoop = $this->getCurrentLoop();
            $loopType = $currentLoop !== null ? $currentLoop['type'] : 'loop';

            // Check for static method calls that execute queries: Model::where()->get(), Model::find(), etc.
            if ($node instanceof Expr\StaticCall && $node->class instanceof Node\Name) {
                $className = $node->class->getLast();

                // Skip DB facade - handled separately
                if ($className !== 'DB' && $node->name instanceof Node\Identifier) {
                    // Skip non-query facades (Cache, Config, Session, etc.)
                    if (in_array(strtolower($className), self::NON_QUERY_CLASSES, true)) {
                        return null;
                    }

                    $methodName = $node->name->toString();

                    // Direct query execution methods
                    if ($this->isQueryExecutionMethod($methodName)) {
                        // Only flag if query depends on loop variable (true N+1 pattern)
                        // and the loop can actually iterate again after the query runs.
                        if ($this->queryDependsOnLoop($node, $currentLoop)
                            && ! $this->loopExitsAfterQuery($node)) {
                            $this->queryIssues[] = [
                                'query' => "{$className}::{$methodName}()",
                                'line' => $node->getStartLine(),
                                'loop_type' => $loopType,
                            ];
                        }
                    }
                }
            }

            // Check for method chains ending in query execution: Model::where()->get()
            if ($node instanceof Expr\MethodCall && $node->name instanceof Node\Identifier) {
                $methodName = $node->name->toString();

                if ($this->isQueryExecutionMethod($methodName)) {
                    // Walk up the chain to find if it starts with a static call (Model::)
                    $queryDescription = $this->getQueryChainDescription($node);
                    if ($queryDescription !== null) {
                        // Only flag if query depends on loop variable (true N+1 pattern), is
                        // not a uniqueness-probe loop condition (generate-until-unique idiom),
                        // does not acquire a pessimistic lock (inherently per-row), and the
                        // loop can actually iterate again after the query runs.
                        if ($this->queryDependsOnLoop($node, $currentLoop)
                            && ! isset($this->uniquenessProbeNodes[spl_object_id($node)])
                            && ! $this->chainAcquiresLock($node)
                            && ! $this->loopExitsAfterQuery($node)) {
                            $this->queryIssues[] = [
                                'query' => $queryDescription,
                                'line' => $node->getStartLine(),
                                'loop_type' => $loopType,
                            ];
                        }
                    }
                }
            }
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Track loop exit - pop from stack and clear relationLoaded checks
        if ($node instanceof Stmt\Foreach_ || $node instanceof Stmt\For_ ||
            $node instanceof Stmt\While_ || $node instanceof Stmt\Do_) {

            // Clear relationLoaded checks for the loop variable being exited
            if ($node instanceof Stmt\Foreach_ &&
                $node->valueVar instanceof Expr\Variable &&
                is_string($node->valueVar->name)) {
                $loopVar = $node->valueVar->name;
                $this->clearRelationLoadedChecks($loopVar);
            }

            array_pop($this->loopStack);
        }

        return null;
    }

    /**
     * Clear relationLoaded checks for a specific loop variable.
     */
    private function clearRelationLoadedChecks(string $varName): void
    {
        $prefix = $varName.':';
        foreach (array_keys($this->relationLoadedChecks) as $key) {
            if (str_starts_with($key, $prefix)) {
                unset($this->relationLoadedChecks[$key]);
            }
        }
    }

    /**
     * Infer loop variable type from source collection type, and copy eager loading context.
     */
    private function inferLoopVariableType(Stmt\Foreach_ $node): void
    {
        if (! ($node->valueVar instanceof Expr\Variable) || ! is_string($node->valueVar->name)) {
            return;
        }
        $loopVar = $node->valueVar->name;

        if (! ($node->expr instanceof Expr\Variable) || ! is_string($node->expr->name)) {
            return;
        }
        $sourceVar = $node->expr->name;

        $this->modelVars->copyContext($sourceVar, $loopVar);
    }

    /**
     * Determine if a property/method name is a real or probable relationship.
     *
     * An accessor or declared model attribute is never a relationship, so that check
     * applies regardless of whether the model defines any relationships at all: it runs
     * before the registry is consulted, on both the precise-lookup and heuristic paths.
     *
     * A name the scanner saw declared as a relationship is one, whether the model states
     * it, uses a trait that does, or inherits it from a parent.
     *
     * A name that is absent is answered conclusively in two cases. The model states
     * relationships of its own, which is the reading the analyzer has always trusted. Or
     * every class and trait it reaches was read, and no method of that name exists
     * anywhere in it: Model::isRelation resolves $model->foo through method_exists, so a
     * name that is not a method cannot be a relationship however the body was written.
     * That second case is deliberately about proving absence rather than about failing to
     * classify: a relationship the scanner did not recognise is still a method, so its
     * name is in the index and the reading stays a guess.
     *
     * Method-call context uses looksLikeRelationshipMethod (stricter exclusions) to avoid
     * false positives on helpers like relationLoaded(), count(), etc.
     */
    private function isActualOrProbableRelationship(string $loopVariable, string $name, bool $isMethodCall = false): bool
    {
        $model = $this->modelVars->typeOf($loopVariable);

        // Variable type completely unknown (flatMap, complex chains, etc.), so don't flag.
        // Conservative default: false negatives are preferable to false positives.
        if ($model === null || str_starts_with($model, 'Collection<')) {
            return false;
        }

        // An accessor or declared attribute is never a relationship. Check this
        // regardless of whether the model defines any relationships at all.
        if ($this->modelAttributesRegistry->has($model, $name)) {
            return false;
        }

        if ($this->accessorRegistry->has($model, $name)) {
            return false;
        }

        if ($this->relationshipRegistry->has($model, $name)) {
            return true;
        }

        if ($this->relationshipRegistry->declaresOwn($model)) {
            return false;
        }

        if ($this->relationshipRegistry->isFullyResolved($model) &&
            ! $this->relationshipRegistry->hasMember($model, strtolower($name)) &&
            ! $this->namesRelationReachedThrough($model, $name)) {
            return false;
        }

        // Model outside the scanned paths, or one the scanner could not read in full.
        // Fall back to heuristic so existing code without model files still works.
        return $isMethodCall
            ? $this->looksLikeRelationshipMethod($name)
            : $this->looksLikeRelationship($name);
    }

    /**
     * Eloquent answers $model->throughComments() by resolving comments and hopping through
     * it, so the name is never declared as a method and proving its absence proves
     * nothing. Recognised here only to withhold a conclusive no, never to produce a yes.
     */
    private function namesRelationReachedThrough(string $model, string $name): bool
    {
        if (! str_starts_with($name, 'through') || strlen($name) <= 7 || ! ctype_upper($name[7])) {
            return false;
        }

        return $this->relationshipRegistry->has($model, lcfirst(substr($name, 7)));
    }

    /**
     * Extract loop variable from for loop init expression.
     *
     * e.g., for ($i = 0; ...) returns 'i'
     */
    private function extractForLoopVariable(Stmt\For_ $node): ?string
    {
        if (empty($node->init)) {
            return null;
        }

        // Look for: $i = 0 or $i = ...
        foreach ($node->init as $init) {
            if ($init instanceof Expr\Assign &&
                $init->var instanceof Expr\Variable &&
                is_string($init->var->name)) {
                return $init->var->name;
            }
        }

        return null;
    }

    /**
     * Extract variables from while/do-while condition.
     *
     * e.g., while ($page < $total) returns ['page', 'total']
     *
     * @return array<string>
     */
    private function extractConditionVariables(Node $condition): array
    {
        $variables = [];
        $this->collectVariables($condition, $variables);

        return array_unique($variables);
    }

    /**
     * Register uniqueness-probe queries in a while/do-while condition.
     *
     * The "generate-until-unique" idiom probes for a free value:
     *   while (Model::where('code', $code)->exists()) { $code = ...; }
     * Each iteration tests a DIFFERENT candidate, so the query drives loop termination
     * rather than running per row — it is a bounded uniqueness search, not an N+1, and the
     * eager-loading remediation does not apply. We treat an exists()/doesntExist() call in
     * the loop condition as a probe only when a variable it filters by is reassigned in the
     * loop body (the signal that each iteration checks a new candidate). Poll loops with a
     * constant condition have no loop-dependent variable and are already not flagged.
     *
     * @param  array<Stmt>  $stmts
     */
    private function registerUniquenessProbes(Node $cond, array $stmts): void
    {
        $assigned = $this->collectAssignedVariables($stmts);
        if ($assigned === []) {
            return;
        }

        $finder = new NodeFinder;
        $existsCalls = $finder->find([$cond], fn (Node $n): bool => $n instanceof Expr\MethodCall
            && $n->name instanceof Node\Identifier
            && in_array(strtolower($n->name->toString()), ['exists', 'doesntexist'], true));

        foreach ($existsCalls as $existsCall) {
            $queryVars = [];
            $this->collectVariables($existsCall, $queryVars);
            if (array_intersect($queryVars, $assigned) !== []) {
                $this->uniquenessProbeNodes[spl_object_id($existsCall)] = true;
            }
        }
    }

    /**
     * Collect names of variables assigned (or in/decremented) anywhere within statements.
     *
     * @param  array<Stmt>  $stmts
     * @return array<string>
     */
    private function collectAssignedVariables(array $stmts): array
    {
        $names = [];
        $finder = new NodeFinder;

        $assignments = $finder->find($stmts, fn (Node $n): bool => $n instanceof Expr\Assign
            || $n instanceof Expr\AssignOp
            || $n instanceof Expr\PreInc
            || $n instanceof Expr\PostInc
            || $n instanceof Expr\PreDec
            || $n instanceof Expr\PostDec);

        foreach ($assignments as $assignment) {
            /** @var Expr\Assign|Expr\AssignOp|Expr\PreInc|Expr\PostInc|Expr\PreDec|Expr\PostDec $assignment */
            $target = $assignment->var;
            if ($target instanceof Expr\Variable && is_string($target->name)) {
                $names[] = $target->name;
            }
        }

        return array_values(array_unique($names));
    }

    /**
     * Recursively collect variable names from an AST node.
     *
     * @param  array<string>  $variables
     */
    private function collectVariables(Node $node, array &$variables): void
    {
        if ($node instanceof Expr\Variable && is_string($node->name)) {
            $variables[] = $node->name;
        }

        foreach ($node->getSubNodeNames() as $name) {
            $subNode = $node->{$name};
            if ($subNode instanceof Node) {
                $this->collectVariables($subNode, $variables);
            } elseif (is_array($subNode)) {
                foreach ($subNode as $item) {
                    if ($item instanceof Node) {
                        $this->collectVariables($item, $variables);
                    }
                }
            }
        }
    }

    /**
     * Check if a query chain depends on loop iteration.
     *
     * @param  array{variables: array<string>, type: string}|null  $loop
     */
    private function queryDependsOnLoop(Node $node, ?array $loop): bool
    {
        if ($loop === null) {
            return false;
        }

        $loopVariables = $loop['variables'];

        // If no loop variables tracked, can't determine dependency - don't flag
        if (empty($loopVariables)) {
            return false;
        }

        // Check if query references any loop variable
        foreach ($loopVariables as $varName) {
            if ($this->chainReferencesVariable($node, $varName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the current loop context (innermost loop).
     *
     * @return array{variables: array<string>, type: string}|null
     */
    private function getCurrentLoop(): ?array
    {
        if (empty($this->loopStack)) {
            return null;
        }

        return end($this->loopStack);
    }

    /**
     * Check if a relationship is eager loaded for a variable.
     *
     * Also matches prefix: if 'user.team' is loaded, then 'user' is considered covered.
     */
    private function isEagerLoaded(string $varName, string $relationship): bool
    {
        foreach ($this->modelVars->eagerLoadsOf($varName) as $loaded) {
            if ($relationship === $loaded || str_starts_with($loaded, $relationship.'.')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a relationship was checked with relationLoaded() for a variable.
     *
     * This indicates the developer is aware of the potential N+1 issue
     * and has implemented defensive checking.
     */
    private function isRelationLoadedChecked(string $varName, string $relationship): bool
    {
        return isset($this->relationLoadedChecks[$varName.':'.$relationship]);
    }

    /**
     * Build relationship chain from nested PropertyFetch nodes.
     *
     * Example: $post->user->team returns ['user', 'team']
     *
     * @return array<string>|null Array of property names in order, or null if not starting with loop variable
     */
    private function buildRelationshipChain(Expr\PropertyFetch $node, string $loopVariable): ?array
    {
        $chain = [];
        $current = $node;

        // Walk up the PropertyFetch chain
        while ($current instanceof Expr\PropertyFetch) {
            if ($current->name instanceof Node\Identifier) {
                array_unshift($chain, $current->name->toString());
            } else {
                return null; // Dynamic property access, can't analyze
            }
            $current = $current->var;
        }

        // Check if chain starts with loop variable
        if ($current instanceof Expr\Variable &&
            is_string($current->name) &&
            $current->name === $loopVariable) {
            return $chain;
        }

        return null;
    }

    /**
     * Check if property name looks like an Eloquent relationship.
     */
    private function looksLikeRelationship(string $name): bool
    {
        $lowerName = strtolower($name);

        // Exclude common non-relationship properties
        if (in_array($lowerName, self::EXCLUDED_PROPERTIES, true)) {
            return false;
        }

        // Snake_case names are database columns, not relationships. Eloquent resolves
        // $model->foo as a relationship only when a method named exactly foo() exists
        // (Model::isRelation uses method_exists, with no case conversion), and relation
        // methods follow PHP's camelCase convention while columns follow Laravel's
        // snake_case one. So an underscore marks a column: subject_type and causer_type
        // (the type half of a morphTo pair, whose relation is named subject/causer),
        // log_name, batch_uuid. This subsumes the *_id, *_at, *_hash, total_*, is_* and
        // *_count patterns that were previously listed one rule at a time.
        if (str_contains($name, '_')) {
            return false;
        }

        // Single character names are unlikely to be relationships
        if (strlen($name) === 1) {
            return false;
        }

        // Relationships are typically nouns - this is a heuristic
        return true;
    }

    /**
     * Check if method name looks like a relationship accessor method.
     */
    private function looksLikeRelationshipMethod(string $name): bool
    {
        $lowerName = strtolower($name);

        // Exclude known non-relationship methods
        if (in_array($lowerName, self::EXCLUDED_METHODS, true)) {
            return false;
        }

        // Exclude getter/setter patterns: get*, set*
        if (preg_match('/^(get|set)[A-Z]/', $name)) {
            return false;
        }

        // Exclude accessor attribute pattern: *Attribute (Laravel accessor convention)
        if (str_ends_with($name, 'Attribute')) {
            return false;
        }

        // Exclude scope methods: scope*
        if (str_starts_with($lowerName, 'scope')) {
            return false;
        }

        // Exclude boot/booted methods
        if (str_starts_with($lowerName, 'boot')) {
            return false;
        }

        // Apply same property heuristics
        return $this->looksLikeRelationship($name);
    }

    /**
     * Check if a method name executes a database query.
     */
    private function isQueryExecutionMethod(string $methodName): bool
    {
        $lowerMethodName = strtolower($methodName);

        // Batch operations are intentional solutions to N+1, not problems
        if (in_array($lowerMethodName, self::BATCH_OPERATION_METHODS, true)) {
            return false;
        }

        // Note: write-upserts (updateOrCreate, firstOrCreate, upsert) are deliberately
        // excluded. A per-row write inside a loop must reference the loop variable, so the
        // loop-dependency guard would always fire — but persisting N items inherently needs
        // N writes; there is no eager-load to add. Reserve N+1 for read-per-iteration.
        $executionMethods = [
            // Retrieval methods
            'get', 'first', 'find', 'findorfail', 'findormany', 'findornew',
            'firstor', 'firstorfail', 'firstornew', 'firstwhere',
            'sole', 'all', 'value', 'pluck',
            // Aggregates
            'count', 'sum', 'avg', 'average', 'min', 'max', 'exists', 'doesntexist',
        ];

        return in_array($lowerMethodName, $executionMethods, true);
    }

    /**
     * Get a description of a query chain starting from a static call.
     *
     * Walks up the method chain to find if it starts with Model::query() or Model::where() etc.
     */
    private function getQueryChainDescription(Expr\MethodCall $node): ?string
    {
        $current = $node->var;

        // Walk up the chain
        while ($current instanceof Expr\MethodCall) {
            $current = $current->var;
        }

        // Check if chain starts with a static call (Model::where, Model::query, etc.)
        if ($current instanceof Expr\StaticCall && $current->class instanceof Node\Name) {
            $className = $current->class->getLast();

            // Skip DB facade
            if ($className === 'DB') {
                return null;
            }

            // Skip non-query facades (Cache, Config, Session, etc.)
            if (in_array(strtolower($className), self::NON_QUERY_CLASSES, true)) {
                return null;
            }

            if ($current->name instanceof Node\Identifier) {
                $startMethod = $current->name->toString();
                $endMethod = $node->name instanceof Node\Identifier ? $node->name->toString() : 'unknown';

                return "{$className}::{$startMethod}()->...{$endMethod}()";
            }
        }

        return null;
    }

    /**
     * Check if any call in a method chain acquires a pessimistic row lock.
     */
    private function chainAcquiresLock(Expr\MethodCall $node): bool
    {
        $current = $node;

        while ($current instanceof Expr\MethodCall) {
            if ($current->name instanceof Node\Identifier
                && in_array(strtolower($current->name->toString()), self::LOCK_METHODS, true)) {
                return true;
            }
            $current = $current->var;
        }

        return $current instanceof Expr\StaticCall
            && $current->name instanceof Node\Identifier
            && in_array(strtolower($current->name->toString()), self::LOCK_METHODS, true);
    }

    /**
     * True if control unconditionally leaves every enclosing loop once the query
     * statement finishes, so the query executes at most once per method call.
     *
     * Walks parent links (set by ParentConnectingVisitor) from the query up to the
     * innermost loop: the statements following the query — climbing out of
     * if/elseif/else blocks — must exit via return, throw, or a break when only a
     * single loop encloses the query. Anything else (conditional exits, try/catch,
     * switch, closures) is treated as repeatable.
     */
    private function loopExitsAfterQuery(Node $queryNode): bool
    {
        // Climb from the query expression to its enclosing statement.
        $current = $queryNode->getAttribute('parent');

        while ($current instanceof Node && ! $current instanceof Stmt) {
            if ($current instanceof Expr\Closure || $current instanceof Expr\ArrowFunction) {
                return false; // deferred execution — control flow is unknowable
            }
            $current = $current->getAttribute('parent');
        }

        if ($this->isLoopNode($current)) {
            // The query sits in a loop header (while/for condition, foreach
            // iterable) and re-runs as that loop iterates.
            return false;
        }

        while ($current instanceof Stmt) {
            $parent = $current->getAttribute('parent');

            if (! $parent instanceof Node) {
                return false;
            }

            $siblings = $this->stmtListContaining($parent, $current);

            if ($siblings === null) {
                // Unsupported construct (try/catch, switch, ...): a throw may be
                // caught and the loop resumed, so treat the query as repeatable.
                return false;
            }

            $index = array_search($current, $siblings, true);

            if (! is_int($index)) {
                return false;
            }

            $suffix = array_slice($siblings, $index + 1);

            if ($suffix !== []) {
                return $this->stmtsExitEveryLoop($suffix);
            }

            if ($this->isLoopNode($parent)) {
                // End of the loop body without an unconditional exit: the next
                // iteration begins.
                return false;
            }

            // Nothing follows at this level: control flows out of the enclosing
            // construct. Else/elseif branches rejoin after their If_ statement.
            $current = $parent instanceof Stmt\ElseIf_ || $parent instanceof Stmt\Else_
                ? $parent->getAttribute('parent')
                : $parent;
        }

        return false;
    }

    /**
     * True if the node is one of the loop constructs this visitor tracks.
     */
    private function isLoopNode(mixed $node): bool
    {
        return $node instanceof Stmt\Foreach_ || $node instanceof Stmt\For_
            || $node instanceof Stmt\While_ || $node instanceof Stmt\Do_;
    }

    /**
     * The statement list of $parent that directly contains $child, for constructs
     * this heuristic can reason about; null for anything else.
     *
     * @return array<int, Stmt>|null
     */
    private function stmtListContaining(Node $parent, Stmt $child): ?array
    {
        $stmts = match (true) {
            $parent instanceof Stmt\If_,
            $parent instanceof Stmt\ElseIf_,
            $parent instanceof Stmt\Else_,
            $parent instanceof Stmt\Block,
            $parent instanceof Stmt\Foreach_,
            $parent instanceof Stmt\For_,
            $parent instanceof Stmt\While_,
            $parent instanceof Stmt\Do_ => $parent->stmts,
            default => null,
        };

        return $stmts !== null && in_array($child, $stmts, true) ? $stmts : null;
    }

    /**
     * True if this statement run unconditionally exits every enclosing loop before
     * any construct that could let the loop iterate again.
     *
     * @param  array<int, Stmt>  $stmts
     */
    private function stmtsExitEveryLoop(array $stmts): bool
    {
        foreach ($stmts as $stmt) {
            if ($stmt instanceof Stmt\Return_) {
                return true;
            }

            if ($stmt instanceof Stmt\Break_) {
                // break exits only the innermost loop, so it proves at-most-once
                // execution only when a single loop encloses the query.
                return $stmt->num === null && count($this->loopStack) === 1;
            }

            if ($stmt instanceof Stmt\Expression) {
                if ($stmt->expr instanceof Expr\Throw_) {
                    return true;
                }

                continue; // plain expressions cannot re-enter the loop
            }

            return false;
        }

        return false;
    }

    /**
     * Check if a method call chain references a specific variable in its arguments.
     */
    private function chainReferencesVariable(Node $node, string $varName): bool
    {
        // Walk the entire method chain checking all arguments
        $current = $node;

        while ($current instanceof Expr\MethodCall) {
            foreach ($current->args as $arg) {
                if ($arg instanceof Node\Arg && $this->expressionReferencesVariable($arg->value, $varName)) {
                    return true;
                }
            }
            $current = $current->var;
        }

        // Check static call arguments at the root
        if ($current instanceof Expr\StaticCall) {
            foreach ($current->args as $arg) {
                if ($arg instanceof Node\Arg && $this->expressionReferencesVariable($arg->value, $varName)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Recursively check if an expression references a variable.
     */
    private function expressionReferencesVariable(Node $expr, string $varName): bool
    {
        // Direct variable reference: $user
        if ($expr instanceof Expr\Variable && is_string($expr->name) && $expr->name === $varName) {
            return true;
        }

        // Property fetch: $user->id, $user->name
        if ($expr instanceof Expr\PropertyFetch) {
            return $this->expressionReferencesVariable($expr->var, $varName);
        }

        // Method call: $user->getId()
        if ($expr instanceof Expr\MethodCall) {
            if ($this->expressionReferencesVariable($expr->var, $varName)) {
                return true;
            }
            // Check method arguments too
            foreach ($expr->args as $arg) {
                if ($arg instanceof Node\Arg && $this->expressionReferencesVariable($arg->value, $varName)) {
                    return true;
                }
            }
        }

        // Array access: $user['id'] or $array[$user->id]
        if ($expr instanceof Expr\ArrayDimFetch) {
            if ($this->expressionReferencesVariable($expr->var, $varName)) {
                return true;
            }

            return $expr->dim !== null && $this->expressionReferencesVariable($expr->dim, $varName);
        }

        // Ternary: $user ? $user->id : null
        if ($expr instanceof Expr\Ternary) {
            return $this->expressionReferencesVariable($expr->cond, $varName) ||
                   ($expr->if !== null && $this->expressionReferencesVariable($expr->if, $varName)) ||
                   $this->expressionReferencesVariable($expr->else, $varName);
        }

        // Binary operations: $user->id === 1
        if ($expr instanceof Expr\BinaryOp) {
            return $this->expressionReferencesVariable($expr->left, $varName) ||
                   $this->expressionReferencesVariable($expr->right, $varName);
        }

        // Array items: [$user->id, $user->name]
        if ($expr instanceof Expr\Array_) {
            foreach ($expr->items as $item) {
                if ($item !== null && $this->expressionReferencesVariable($item->value, $varName)) {
                    return true;
                }
            }
        }

        // Closure: function() use ($user) { ... }
        if ($expr instanceof Expr\Closure) {
            // Check if the variable is actually used in the closure body,
            // not just captured in use(). Capture alone doesn't mean the query
            // depends on the variable.
            foreach ($expr->stmts as $stmt) {
                if ($this->nodeContainsVariableReference($stmt, $varName)) {
                    return true;
                }
            }
        }

        // Arrow function: fn() => $user->id
        if ($expr instanceof Expr\ArrowFunction) {
            return $this->expressionReferencesVariable($expr->expr, $varName);
        }

        return false;
    }

    /**
     * Recursively check if any node in the subtree references a variable.
     */
    private function nodeContainsVariableReference(Node $node, string $varName): bool
    {
        // Direct variable reference
        if ($node instanceof Expr\Variable && is_string($node->name) && $node->name === $varName) {
            return true;
        }

        // Recursively check all sub-nodes
        foreach ($node->getSubNodeNames() as $subNodeName) {
            $subNode = $node->{$subNodeName};

            if ($subNode instanceof Node) {
                if ($this->nodeContainsVariableReference($subNode, $varName)) {
                    return true;
                }
            } elseif (is_array($subNode)) {
                foreach ($subNode as $item) {
                    if ($item instanceof Node && $this->nodeContainsVariableReference($item, $varName)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{relationship: string, line: int, loop_type: string, variable: string}>
     */
    public function getIssues(): array
    {
        // Deduplicate issues (same variable accessing same relationship)
        $unique = [];
        $seen = [];

        foreach ($this->issues as $issue) {
            // Include variable name to prevent false deduplication across different variables
            // Don't include line to deduplicate same relationship accessed multiple times
            $key = $issue['variable'].'_'.$issue['relationship'];
            if (! isset($seen[$key])) {
                $unique[] = $issue;
                $seen[$key] = true;
            }
        }

        return $unique;
    }

    /**
     * Get collected query issues (queries executed inside loops).
     *
     * @return array<int, array{query: string, line: int, loop_type: string}>
     */
    public function getQueryIssues(): array
    {
        // Deduplicate by query description and line
        $unique = [];
        $seen = [];

        foreach ($this->queryIssues as $issue) {
            $key = $issue['query'].'_'.$issue['line'];
            if (! isset($seen[$key])) {
                $unique[] = $issue;
                $seen[$key] = true;
            }
        }

        return $unique;
    }

    /**
     * The render-bound variable name a variable ultimately derives from (e.g. a Blade loop
     * variable traced back to the controller-passed variable it was seeded from), or `null` if
     * it was never seeded or aliased from a seeded variable.
     */
    public function originOf(string $var): ?string
    {
        return $this->modelVars->originOf($var);
    }
}
