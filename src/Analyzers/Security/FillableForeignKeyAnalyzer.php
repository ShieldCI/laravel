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
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Support\EloquentModelDetector;
use ShieldCI\Support\EloquentModelHelper;

/**
 * Detects ownership/impersonation foreign keys exposed to mass assignment.
 *
 * Flags curated ownership/impersonation keys in $fillable (user_id, owner_id, tenant_id,
 * ...) that allow users to reassign records to other principals.
 *
 * Out of scope by design (owned by MassAssignmentAnalyzer): $guarded = [] and untrusted
 * create()/update()/fill() sinks. Generic *_id fields are likewise not flagged — whether
 * a fillable foreign key is exploitable is a data-flow property, not a field-name one.
 */
class FillableForeignKeyAnalyzer extends AbstractFileAnalyzer
{
    /**
     * @var array<string, string>
     */
    private array $dangerousPatterns = [];

    private ?EloquentModelDetector $modelDetector = null;

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

    /**
     * Shared across shouldRun() and runAnalysis() so the model scan in shouldRun()
     * warms the per-file parse cache that runAnalysis() then reuses.
     */
    private function modelDetector(): EloquentModelDetector
    {
        return $this->modelDetector ??= new EloquentModelDetector($this->parser);
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'fillable-foreign-key',
            name: 'Fillable Foreign Key Analyzer',
            description: 'Detects ownership/impersonation foreign keys exposed to mass assignment in Eloquent model $fillable arrays',
            category: Category::Security,
            severity: Severity::High,
            tags: ['mass-assignment', 'foreign-keys', 'eloquent', 'security', 'relationships'],
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
                if ($this->modelDetector()->isModel($class, $ast, $this->getBasePath())) {
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
                if ($this->modelDetector()->isModel($class, $ast, $this->getBasePath())) {
                    if (! $this->hasLocalFillable($class) && ! $this->hasLocalGuarded($class)) {
                        $issues[] = $this->createIssue(
                            message: sprintf('Model "%s" does not define a local $fillable property; inherited fillable fields cannot be analyzed', $class->name?->toString() ?? 'Unknown'),
                            location: new Location($this->getRelativePath($file)),
                            severity: Severity::Medium,
                            recommendation: 'Review inherited fillable definitions to ensure foreign key fields are not inadvertently exposed to mass assignment.',
                            metadata: [
                                'model_name' => $class->name?->toString(),
                                'fillable_inherited' => true,
                            ]
                        );
                    }

                    $this->checkFillableProperty($file, $class, $issues);
                    $this->checkFillableAttribute($file, $class, $issues);
                }
            }
        }

        $summary = empty($issues)
            ? 'No foreign keys found in fillable arrays'
            : sprintf('Found %d foreign key%s in fillable arrays', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Check if fillable is declared locally, via a $fillable property or a #[Fillable] attribute.
     */
    private function hasLocalFillable(Node\Stmt\Class_ $class): bool
    {
        return EloquentModelHelper::hasFillable($class);
    }

    /**
     * Check if guarded is declared locally, via a $guarded property or a #[Guarded]/#[Unguarded] attribute.
     */
    private function hasLocalGuarded(Node\Stmt\Class_ $class): bool
    {
        return EloquentModelHelper::hasGuarded($class);
    }

    /**
     * Check fillable property for foreign keys.
     *
     * @param  array<int, Issue>  &$issues
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
                        recommendation: 'Prefer a static fillable property or manually review which fields are exposed to mass assignment.',
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
                        $this->checkField($file, $item->getLine(), $modelName, $fieldName, $issues);
                    }
                }
            }
        }
    }

    /**
     * Check fields declared via a #[Fillable(...)] attribute for foreign keys.
     *
     * Reuses the same curated-pattern detection (checkField) as the property path so an
     * attribute-based model is analyzed identically to a property-based one.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function checkFillableAttribute(string $file, Node\Stmt\Class_ $class, array &$issues): void
    {
        $fields = EloquentModelHelper::extractFillableFieldsFromAttribute($class);
        if ($fields === []) {
            return;
        }

        $modelName = $class->name ? $class->name->toString() : 'Unknown';
        $line = $this->fillableAttributeLine($class);

        foreach ($fields as $fieldName) {
            $this->checkField($file, $line, $modelName, $fieldName, $issues);
        }
    }

    /**
     * Line of the #[Fillable] attribute, falling back to the class line.
     */
    private function fillableAttributeLine(Node\Stmt\Class_ $class): int
    {
        foreach ($class->attrGroups as $group) {
            foreach ($group->attrs as $attr) {
                $name = $attr->name->toString();
                $short = ($pos = strrpos($name, '\\')) !== false ? substr($name, $pos + 1) : $name;
                if ($short === 'Fillable') {
                    return $attr->getLine();
                }
            }
        }

        return $class->getLine();
    }

    /**
     * Check a single field for foreign key patterns.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function checkField(string $file, int $itemLine, string $modelName, string $fieldName, array &$issues): void
    {
        // Report only curated impersonation/ownership keys (user_id, owner_id, ...).
        if (array_key_exists($fieldName, $this->dangerousPatterns)) {
            $relationship = $this->dangerousPatterns[$fieldName];

            $issues[] = $this->createIssueWithSnippet(
                message: sprintf(
                    '"%s" (%s) is fillable in model "%s" - this allows users to impersonate others',
                    $fieldName,
                    $relationship,
                    $modelName
                ),
                filePath: $file,
                lineNumber: $itemLine,
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
                    'line' => $itemLine,
                ]
            );
        }

        // Generic *_id foreign keys are intentionally NOT reported here. Whether a
        // fillable foreign key is exploitable depends on data flow (an untrusted
        // create()/update()/fill() sink with no allowlist), not on the field name —
        // and that is already detected by MassAssignmentAnalyzer. Flagging every *_id
        // field lexically produces evidence-free noise, so this analyzer reports only
        // the curated impersonation/ownership patterns above.
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
        $merged = array_merge($defaults, $configPatterns);
        /** @var array<string, string> $merged */
        $this->dangerousPatterns = $merged;
    }
}
