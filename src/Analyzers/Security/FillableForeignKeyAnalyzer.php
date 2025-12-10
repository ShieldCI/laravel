<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use PhpParser\Node;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects foreign keys in fillable arrays.
 *
 * Checks for:
 * - Fields ending in _id in $fillable arrays
 * - Foreign key columns exposed to mass assignment
 * - Potential relationship manipulation attacks
 * - Critical patterns like user_id, owner_id that allow impersonation
 */
class FillableForeignKeyAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'fillable-foreign-key',
            name: 'Fillable Foreign Key Analyzer',
            description: 'Detects foreign keys in fillable arrays that may allow unauthorized relationship manipulation',
            category: Category::Security,
            severity: Severity::High,
            tags: ['mass-assignment', 'foreign-keys', 'eloquent', 'security', 'relationships'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/fillable-foreign-key',
            timeToFix: 15
        );
    }

    public function shouldRun(): bool
    {
        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);
            if (empty($ast)) {
                continue;
            }

            $classes = $this->parser->findClasses($ast);
            foreach ($classes as $class) {
                if ($this->isEloquentModel($file, $class)) {
                    return true;
                }
            }
        }

        return false;
    }

    public function getSkipReason(): string
    {
        return 'No Eloquent models found in the codebase';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);
            if (empty($ast)) {
                continue;
            }

            $classes = $this->parser->findClasses($ast);
            foreach ($classes as $class) {
                if ($this->isEloquentModel($file, $class)) {
                    $this->checkFillableProperty($file, $class, $issues);
                }
            }
        }

        $summary = empty($issues)
            ? 'No foreign keys found in fillable arrays'
            : sprintf('Found %d foreign key%s in fillable arrays', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Check if a class is an Eloquent model.
     */
    private function isEloquentModel(string $file, Node\Stmt\Class_ $class): bool
    {
        if ($class->extends === null) {
            return false;
        }

        $parentClass = $class->extends->toString();

        // Check for direct Model class or namespaced Model
        if ($parentClass === 'Model' || str_ends_with($parentClass, '\\Model')) {
            return true;
        }

        // Check for common Laravel model base classes
        $commonModelClasses = [
            'Authenticatable',
            'Pivot',
            'MorphPivot',
        ];

        foreach ($commonModelClasses as $modelClass) {
            if ($parentClass === $modelClass || str_ends_with($parentClass, '\\'.$modelClass)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check fillable property for foreign keys.
     */
    private function checkFillableProperty(string $file, Node\Stmt\Class_ $class, array &$issues): void
    {
        $modelName = $class->name ? $class->name->toString() : 'Unknown';

        foreach ($class->stmts as $stmt) {
            if (! $stmt instanceof Node\Stmt\Property) {
                continue;
            }

            foreach ($stmt->props as $prop) {
                if ($prop->name->toString() !== 'fillable') {
                    continue;
                }

                if (! $prop->default instanceof Node\Expr\Array_) {
                    continue;
                }

                // Check each item in the fillable array
                foreach ($prop->default->items as $item) {
                    if ($item === null) {
                        continue;
                    }

                    if (! $item instanceof Node\Expr\ArrayItem) {
                        continue;
                    }

                    if ($item->value instanceof Node\Scalar\String_) {
                        $fieldName = $item->value->value;
                        $this->checkField($file, $stmt, $modelName, $fieldName, $issues);
                    }
                }
            }
        }
    }

    /**
     * Check a single field for foreign key patterns.
     */
    private function checkField(string $file, Node\Stmt\Property $stmt, string $modelName, string $fieldName, array &$issues): void
    {
        // Get dangerous patterns (configurable)
        $dangerousPatterns = $this->getDangerousPatterns();

        // Check dangerous patterns FIRST (prevents duplicates)
        if (array_key_exists($fieldName, $dangerousPatterns)) {
            $relationship = $dangerousPatterns[$fieldName];

            $issues[] = $this->createIssue(
                message: sprintf(
                    'Critical: "%s" (%s) is fillable in model "%s" - this allows users to impersonate others',
                    $fieldName,
                    $relationship,
                    $modelName
                ),
                location: new Location(
                    $this->getRelativePath($file),
                    $stmt->getLine()
                ),
                severity: Severity::Critical,
                recommendation: sprintf(
                    'IMMEDIATELY remove "%s" from $fillable. Set it manually: $model->%s = auth()->id();',
                    $fieldName,
                    $fieldName
                ),
                code: FileParser::getCodeSnippet($file, $stmt->getLine()),
                metadata: [
                    'field_name' => $fieldName,
                    'model_name' => $modelName,
                    'model_file' => $this->getRelativePath($file),
                    'is_dangerous_pattern' => true,
                    'pattern_type' => $relationship,
                    'line' => $stmt->getLine(),
                ]
            );

            return; // Early return - don't create second issue
        }

        // Check for generic _id pattern (only if not a dangerous pattern)
        if (str_ends_with($fieldName, '_id')) {
            $issues[] = $this->createIssue(
                message: sprintf(
                    'Potential foreign key "%s" is fillable in model "%s"',
                    $fieldName,
                    $modelName
                ),
                location: new Location(
                    $this->getRelativePath($file),
                    $stmt->getLine()
                ),
                severity: Severity::High,
                recommendation: sprintf(
                    'Remove "%s" from $fillable or validate that users should be able to set this relationship. '.
                    'Consider using $guarded or manual assignment for foreign keys.',
                    $fieldName
                ),
                code: FileParser::getCodeSnippet($file, $stmt->getLine()),
                metadata: [
                    'field_name' => $fieldName,
                    'model_name' => $modelName,
                    'model_file' => $this->getRelativePath($file),
                    'is_dangerous_pattern' => false,
                    'pattern_type' => 'foreign_key',
                    'line' => $stmt->getLine(),
                ]
            );
        }
    }

    /**
     * Get dangerous foreign key patterns (configurable).
     *
     * @return array<string, string>
     */
    private function getDangerousPatterns(): array
    {
        $defaults = [
            'user_id' => 'user ownership',
            'author_id' => 'author relationship',
            'owner_id' => 'owner relationship',
            'creator_id' => 'creator relationship',
            'parent_id' => 'hierarchical relationship',
            'tenant_id' => 'tenant isolation',
            'organization_id' => 'organization ownership',
            'company_id' => 'company ownership',
            'team_id' => 'team membership',
            'account_id' => 'account ownership',
        ];

        // Allow configuration override
        /** @var array<string, string> $custom */
        $custom = config('shieldci.fillable_foreign_key.dangerous_patterns', []);

        return array_merge($defaults, $custom);
    }
}
