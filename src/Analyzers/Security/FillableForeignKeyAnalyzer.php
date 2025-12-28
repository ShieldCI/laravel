<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\Node;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
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
    /**
     * @var array<string, string>
     */
    private array $dangerousPatterns = [];

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

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
                if ($this->isEloquentModel($class)) {
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
        $this->loadDangerousPatterns();

        $issues = [];

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);
            if (empty($ast)) {
                continue;
            }

            $classes = $this->parser->findClasses($ast);
            foreach ($classes as $class) {
                if ($this->isEloquentModel($class)) {
                    if (! $this->hasLocalFillable($class) && ! $this->hasLocalGuarded($class)) {
                        $issues[] = $this->createIssue(
                            message: sprintf('Model "%s" does not define a local $fillable property; inherited fillable fields cannot be analyzed', $class->name?->toString() ?? 'Unknown'),
                            location: new Location($this->getRelativePath($file)),
                            severity: Severity::Medium,
                            recommendation: 'Review inherited $fillable definitions for foreign keys.',
                            metadata: [
                                'model_name' => $class->name?->toString(),
                                'fillable_inherited' => true,
                            ]
                        );
                    }

                    $this->checkFillableProperty($file, $class, $issues);
                    $this->checkGuardedProperty($file, $class, $issues);
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
    private function isEloquentModel(Node\Stmt\Class_ $class): bool
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
     * Check if fillable is declared in an Eloquent model.
     */
    private function hasLocalFillable(Node\Stmt\Class_ $class): bool
    {
        foreach ($class->stmts as $stmt) {
            if (! $stmt instanceof Node\Stmt\Property) {
                continue;
            }

            foreach ($stmt->props as $prop) {
                if ($prop->name->toString() === 'fillable') {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if guarded is declared in an Eloquent model.
     */
    private function hasLocalGuarded(Node\Stmt\Class_ $class): bool
    {
        foreach ($class->stmts as $stmt) {
            if (! $stmt instanceof Node\Stmt\Property) {
                continue;
            }

            foreach ($stmt->props as $prop) {
                if ($prop->name->toString() === 'guarded') {
                    return true;
                }
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
                    $issues[] = $this->createIssueWithSnippet(
                        message: sprintf(
                            'Model "%s" defines $fillable dynamically; foreign key exposure cannot be statically analyzed',
                            $modelName
                        ),
                        filePath: $file,
                        lineNumber: $stmt->getLine(),
                        severity: Severity::Medium,
                        recommendation: 'Prefer a static $fillable array or manually review foreign key exposure.',
                        metadata: [
                            'model_name' => $modelName,
                            'dynamic_fillable' => true,
                        ]
                    );

                    return;
                }

                // Check each item in the fillable array
                foreach ($prop->default->items as $item) {
                    if ($item->value instanceof Node\Scalar\String_) {
                        $fieldName = $item->value->value;
                        $this->checkField($file, $stmt, $modelName, $fieldName, $issues);
                    }
                }
            }
        }
    }

    /**
     * Check guarded property for full mass assignment.
     */
    private function checkGuardedProperty(string $file, Node\Stmt\Class_ $class, array &$issues): void
    {
        $modelName = $class->name ? $class->name->toString() : 'Unknown';

        foreach ($class->stmts as $stmt) {
            if (! $stmt instanceof Node\Stmt\Property) {
                continue;
            }

            foreach ($stmt->props as $prop) {
                if ($prop->name->toString() !== 'guarded') {
                    continue;
                }

                if (! $prop->default instanceof Node\Expr\Array_) {
                    continue;
                }

                if (count($prop->default->items) !== 0) {
                    continue;
                }

                // guarded = []
                $issues[] = $this->createIssueWithSnippet(
                    message: sprintf(
                        'Critical: Model "%s" uses $guarded = [] which allows unrestricted mass assignment',
                        $modelName
                    ),
                    filePath: $file,
                    lineNumber: $stmt->getLine(),
                    severity: Severity::Critical,
                    recommendation: 'Define an explicit $fillable array and avoid $guarded = [].',
                    metadata: [
                        'model_name' => $modelName,
                        'model_file' => $this->getRelativePath($file),
                        'guarded_empty' => true,
                        'line' => $stmt->getLine(),
                    ]
                );
            }
        }
    }

    /**
     * Check a single field for foreign key patterns.
     */
    private function checkField(string $file, Node\Stmt\Property $stmt, string $modelName, string $fieldName, array &$issues): void
    {
        // Check dangerous patterns FIRST (prevents duplicates)
        if (array_key_exists($fieldName, $this->dangerousPatterns)) {
            $relationship = $this->dangerousPatterns[$fieldName];

            $issues[] = $this->createIssueWithSnippet(
                message: sprintf(
                    'Critical: "%s" (%s) is fillable in model "%s" - this allows users to impersonate others',
                    $fieldName,
                    $relationship,
                    $modelName
                ),
                filePath: $file,
                lineNumber: $stmt->getLine(),
                severity: Severity::Critical,
                recommendation: sprintf(
                    'IMMEDIATELY remove "%s" from $fillable. Set this value server-side based on the authenticated context.',
                    $fieldName
                ),
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
            $issues[] = $this->createIssueWithSnippet(
                message: sprintf(
                    'Potential foreign key "%s" is fillable in model "%s"',
                    $fieldName,
                    $modelName
                ),
                filePath: $file,
                lineNumber: $stmt->getLine(),
                severity: Severity::High,
                recommendation: sprintf(
                    'Remove "%s" from $fillable or validate that users should be able to set this relationship. '.
                    'Consider using $guarded or manual assignment for foreign keys.',
                    $fieldName
                ),
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
     * Load dangerous foreign key patterns from configuration.
     */
    private function loadDangerousPatterns(): void
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

        $configPatterns = $this->config->get('shieldci.analyzers.security.fillable-foreign-key.dangerous_patterns', []);

        // Ensure configPatterns is an array
        if (! is_array($configPatterns)) {
            $configPatterns = [];
        }

        // Merge config patterns with defaults
        // Config patterns take precedence (can override the relationship description)
        $this->dangerousPatterns = array_merge($defaults, $configPatterns);
    }
}
