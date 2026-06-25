<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use PhpParser\Node;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ShieldCI\AnalyzersCore\Support\AstParser;
use SplFileInfo;

/**
 * Resolves the database table behind an Eloquent model class by reading explicit
 * `protected $table = '...'` overrides from app/Models.
 *
 * The conventional Eloquent name (Str::snake(Str::pluralStudly($class))) is wrong
 * whenever a model sets $table by hand — e.g. GitHubInstallation lives in
 * github_installations, not git_hub_installations. Callers consult this resolver
 * before falling back to the naming convention so per-table index reasoning attributes
 * queries to the right table.
 *
 * Keyed by short class name. Two models sharing a short name in different namespaces
 * are ambiguous (last-wins); that is acceptable for the FP-reduction this serves.
 */
final class ModelTableResolver
{
    /**
     * Per-basePath cache of short class name => explicit table name.
     *
     * @var array<string, array<string, string>>
     */
    private array $cache = [];

    public function __construct(private readonly AstParser $parser) {}

    /**
     * The explicit `protected $table` for $shortClassName, or null when the model
     * declares no override (caller keeps the conventional table name).
     */
    public function tableFor(string $basePath, string $shortClassName): ?string
    {
        return $this->scan($basePath)[$shortClassName] ?? null;
    }

    /**
     * Scan (and cache) app/Models under $basePath for explicit $table overrides.
     *
     * @return array<string, string>
     */
    private function scan(string $basePath): array
    {
        if (array_key_exists($basePath, $this->cache)) {
            return $this->cache[$basePath];
        }

        $modelsPath = rtrim($basePath, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Models';

        if (! is_dir($modelsPath)) {
            return $this->cache[$basePath] = [];
        }

        /** @var array<string, string> $map */
        $map = [];

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($modelsPath, RecursiveDirectoryIterator::SKIP_DOTS),
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

            foreach ($this->parser->findClasses($ast) as $class) {
                if ($class->name === null) {
                    continue;
                }

                $table = $this->extractTableOverride($class);
                if ($table !== null) {
                    $map[$class->name->toString()] = $table;
                }
            }
        }

        return $this->cache[$basePath] = $map;
    }

    /**
     * Return the string value of a class's `protected $table = '...'` property, or
     * null when the class declares no such literal override.
     */
    private function extractTableOverride(Node\Stmt\Class_ $class): ?string
    {
        foreach ($class->stmts as $stmt) {
            if (! $stmt instanceof Node\Stmt\Property) {
                continue;
            }

            foreach ($stmt->props as $prop) {
                if ($prop->name->toString() === 'table' && $prop->default instanceof Node\Scalar\String_) {
                    return $prop->default->value;
                }
            }
        }

        return null;
    }
}
