<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use Illuminate\Support\Str;
use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ShieldCI\AnalyzersCore\Support\AstParser;
use SplFileInfo;

/**
 * Scans database/seeders/ to identify "reference catalogue" tables — small, fixed lookup
 * tables populated by literal seeding (plans, pillars, business_stages …) that never grow
 * with real usage. A full scan of such a table beats an index, so per-column index hints
 * on them are noise.
 *
 * A table qualifies as a catalogue when it is written by literal seeding and never via a
 * factory:
 * - literal: DB::table('x')->insert(...), or Model::create()/updateOrCreate()/
 *   firstOrCreate()/insert()/forceCreate() resolved to its table.
 * - factory usage (Model::factory()->create()) disqualifies the table — factories generate
 *   volume, the opposite of a fixed catalogue.
 *
 * Returns null when database/seeders/ does not exist, so callers skip the catalogue check
 * rather than treat "no seeders" as "no catalogues."
 *
 * Tradeoff (accepted): a seeded-but-growing table could lose a legitimate low-severity
 * index hint. Given the Low severity and the false-positive volume these catalogues
 * generate, that is the right trade.
 */
final class SeededTableScanner
{
    /**
     * Eloquent persistence methods that write literal catalogue rows.
     *
     * @var array<int, string>
     */
    private const LITERAL_WRITE_METHODS = [
        'create', 'updateOrCreate', 'firstOrCreate', 'insert', 'forceCreate',
    ];

    /**
     * Query-builder write terminals used against DB::table('x') in seeders.
     *
     * @var array<int, string>
     */
    private const BUILDER_WRITE_METHODS = [
        'insert', 'insertOrIgnore', 'updateOrInsert', 'upsert',
    ];

    private readonly NodeFinder $nodeFinder;

    private readonly ModelTableResolver $modelTableResolver;

    /**
     * Per-basePath cache of catalogue table names (null when no seeders directory).
     *
     * @var array<string, array<int, string>|null>
     */
    private array $cache = [];

    public function __construct(private readonly AstParser $parser)
    {
        $this->nodeFinder = new NodeFinder;
        $this->modelTableResolver = new ModelTableResolver($parser);
    }

    /**
     * Tables populated only by literal seeding (catalogues), or null when there is no
     * database/seeders/ directory.
     *
     * @return array<int, string>|null
     */
    public function catalogueTables(string $basePath): ?array
    {
        return $this->scan($basePath);
    }

    /**
     * Scan (and cache) database/seeders/ for catalogue tables.
     *
     * @return array<int, string>|null
     */
    private function scan(string $basePath): ?array
    {
        if (array_key_exists($basePath, $this->cache)) {
            return $this->cache[$basePath];
        }

        $seedersPath = rtrim($basePath, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.'database'.DIRECTORY_SEPARATOR.'seeders';

        if (! is_dir($seedersPath)) {
            return $this->cache[$basePath] = null;
        }

        /** @var array<string, true> $literal */
        $literal = [];
        /** @var array<string, true> $factory */
        $factory = [];

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($seedersPath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );

        /** @var SplFileInfo $file */
        foreach ($iterator as $file) {
            if (! $file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            $ast = $this->parser->parseFile($file->getPathname());
            if ($ast === []) {
                continue;
            }

            $this->collectLiteralModelWrites($ast, $basePath, $literal);
            $this->collectBuilderWrites($ast, $literal);
            $this->collectFactoryUses($ast, $basePath, $factory);
        }

        // array_keys can narrow numeric-looking table names to int; normalise to string.
        $catalogue = array_values(array_map(
            'strval',
            array_diff(array_keys($literal), array_keys($factory))
        ));

        return $this->cache[$basePath] = $catalogue;
    }

    /**
     * Record tables written via Model::create()/updateOrCreate()/firstOrCreate()/insert().
     *
     * @param  array<Node>  $ast
     * @param  array<string, true>  $literal
     */
    private function collectLiteralModelWrites(array $ast, string $basePath, array &$literal): void
    {
        /** @var array<int, StaticCall> $staticCalls */
        $staticCalls = $this->nodeFinder->findInstanceOf($ast, StaticCall::class);

        foreach ($staticCalls as $call) {
            if (! $call->name instanceof Identifier
                || ! in_array($call->name->name, self::LITERAL_WRITE_METHODS, true)
                || ! $call->class instanceof Node\Name
            ) {
                continue;
            }

            $table = $this->tableForModel($basePath, $call->class->getLast());
            $literal[$table] = true;
        }
    }

    /**
     * Record tables written via DB::table('x')->insert()/upsert()/updateOrInsert().
     *
     * @param  array<Node>  $ast
     * @param  array<string, true>  $literal
     */
    private function collectBuilderWrites(array $ast, array &$literal): void
    {
        /** @var array<int, MethodCall> $methodCalls */
        $methodCalls = $this->nodeFinder->findInstanceOf($ast, MethodCall::class);

        foreach ($methodCalls as $call) {
            if (! $call->name instanceof Identifier
                || ! in_array($call->name->name, self::BUILDER_WRITE_METHODS, true)
            ) {
                continue;
            }

            $table = $this->dbTableLiteral($call->var);
            if ($table !== null) {
                $literal[$table] = true;
            }
        }
    }

    /**
     * Record tables seeded via Model::factory(), which disqualifies them as catalogues.
     *
     * @param  array<Node>  $ast
     * @param  array<string, true>  $factory
     */
    private function collectFactoryUses(array $ast, string $basePath, array &$factory): void
    {
        /** @var array<int, StaticCall> $staticCalls */
        $staticCalls = $this->nodeFinder->findInstanceOf($ast, StaticCall::class);

        foreach ($staticCalls as $call) {
            if (! $call->name instanceof Identifier
                || $call->name->name !== 'factory'
                || ! $call->class instanceof Node\Name
            ) {
                continue;
            }

            $table = $this->tableForModel($basePath, $call->class->getLast());
            $factory[$table] = true;
        }
    }

    /**
     * Walk a method-call chain to a DB::table('x') root and return 'x', or null.
     */
    private function dbTableLiteral(Node $node): ?string
    {
        $current = $node;
        while ($current instanceof MethodCall) {
            $current = $current->var;
        }

        if ($current instanceof StaticCall
            && $current->class instanceof Node\Name
            && $current->class->getLast() === 'DB'
            && $current->name instanceof Identifier
            && $current->name->name === 'table'
            && count($current->args) >= 1
            && $current->args[0] instanceof Node\Arg
            && $current->args[0]->value instanceof Node\Scalar\String_
        ) {
            return $current->args[0]->value->value;
        }

        return null;
    }

    /**
     * Resolve a model short name to its table — explicit $table override else convention.
     */
    private function tableForModel(string $basePath, string $shortClass): string
    {
        return $this->modelTableResolver->tableFor($basePath, $shortClass)
            ?? Str::snake(Str::pluralStudly($shortClass));
    }
}
