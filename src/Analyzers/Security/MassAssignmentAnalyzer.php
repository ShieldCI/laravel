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
 * Detects mass assignment vulnerabilities in Eloquent models.
 *
 * Checks for:
 * - Models without $fillable or $guarded
 * - Models with empty $guarded = []
 * - create() or update() with request()->all()
 * - fill() with unfiltered request data
 * - Query builder operations with request data
 */
class MassAssignmentAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Dangerous Eloquent model static methods.
     */
    private const MODEL_STATIC_METHODS = [
        'create',
        'forceCreate',
        'firstOrCreate',
        'updateOrCreate',
        'firstOrNew',
        'make',
        'insert',
        'upsert',
        'insertOrIgnore',
    ];

    /**
     * Dangerous Eloquent model instance methods.
     */
    private const MODEL_INSTANCE_METHODS = [
        'fill',
        'forceFill',
        'update',
    ];

    /**
     * Dangerous query builder methods.
     */
    private const BUILDER_METHODS = [
        'update',
        'insert',
        'upsert',
        'insertOrIgnore',
        'insertUsing',
        'insertGetId',
        'updateOrInsert',
    ];

    /**
     * Request data retrieval methods that are dangerous.
     */
    private const REQUEST_DATA_METHODS = [
        'all',
        'input',
        'post',
        'get',
        'query',
        'except',
        'json',
    ];

    public function __construct(
        private ParserInterface $parser
    ) {
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'mass-assignment-vulnerabilities',
            name: 'Mass Assignment Vulnerabilities Analyzer',
            description: 'Detects mass assignment vulnerabilities in Eloquent models and query builders',
            category: Category::Security,
            severity: Severity::High,
            tags: ['mass-assignment', 'eloquent', 'security', 'models', 'sql-injection'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/mass-assignment-vulnerabilities',
            timeToFix: 25
        );
    }

    public function shouldRun(): bool
    {
        $modelsPath = $this->getBasePath().DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Models';

        return is_dir($modelsPath);
    }

    public function getSkipReason(): string
    {
        return 'No app/Models directory found';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);
            if (empty($ast)) {
                continue;
            }

            // Check models for proper protection
            $classes = $this->parser->findClasses($ast);
            foreach ($classes as $class) {
                if ($this->isEloquentModel($file, $class)) {
                    $this->checkModelProtection($file, $class, $issues);
                }
            }

            // Check for dangerous method calls with request data
            $this->checkDangerousMethodCalls($file, $ast, $issues);

            // Check for dangerous query builder calls
            $this->checkQueryBuilderCalls($file, $ast, $issues);
        }

        $summary = empty($issues)
            ? 'No mass assignment vulnerabilities detected'
            : sprintf('Found %d potential mass assignment vulnerabilit%s', count($issues), count($issues) === 1 ? 'y' : 'ies');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Check if a class is an Eloquent model.
     */
    private function isEloquentModel(string $file, Node\Stmt\Class_ $class): bool
    {
        // First check if extends Model (most reliable)
        if ($class->extends !== null) {
            $parentClass = $class->extends->toString();
            if ($parentClass === 'Model' || str_ends_with($parentClass, '\\Model')) {
                return true;
            }
        }

        // Secondary check: namespace
        $content = FileParser::readFile($file);
        if ($content === null) {
            return false;
        }

        if (str_contains($content, 'namespace App\\Models')) {
            return true;
        }

        return false;
    }

    /**
     * Check if model has proper mass assignment protection.
     */
    private function checkModelProtection(string $file, Node\Stmt\Class_ $class, array &$issues): void
    {
        $hasFillable = false;
        $hasGuarded = false;
        $hasEmptyGuarded = false;

        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\Property) {
                foreach ($stmt->props as $prop) {
                    if ($prop->name->toString() === 'fillable') {
                        $hasFillable = true;
                    }

                    if ($prop->name->toString() === 'guarded') {
                        $hasGuarded = true;

                        // Check if $guarded = []
                        if ($prop->default instanceof Node\Expr\Array_ && empty($prop->default->items)) {
                            $hasEmptyGuarded = true;
                        }
                    }
                }
            }
        }

        $modelName = $class->name ? $class->name->toString() : 'Unknown';

        // Issue if neither fillable nor guarded is set
        if (! $hasFillable && ! $hasGuarded) {
            $issues[] = $this->createIssue(
                message: "Model '{$modelName}' lacks mass assignment protection (\$fillable or \$guarded)",
                location: new Location(
                    $this->getRelativePath($file),
                    $class->getLine()
                ),
                severity: Severity::High,
                recommendation: 'Add protected $fillable = [...] or protected $guarded = ["*"] to the model',
                code: FileParser::getCodeSnippet($file, $class->getLine()),
                metadata: [
                    'model' => $modelName,
                    'issue_type' => 'missing_model_protection',
                ]
            );
        }

        // Issue if guarded is empty array (allows all)
        if ($hasEmptyGuarded) {
            $issues[] = $this->createIssue(
                message: "Model '{$modelName}' has \$guarded = [] which allows mass assignment of all attributes",
                location: new Location(
                    $this->getRelativePath($file),
                    $class->getLine()
                ),
                severity: Severity::Critical,
                recommendation: 'Either specify fillable attributes or use $guarded = ["*"] to protect all',
                code: FileParser::getCodeSnippet($file, $class->getLine()),
                metadata: [
                    'model' => $modelName,
                    'issue_type' => 'empty_guarded_array',
                ]
            );
        }
    }

    /**
     * Check for dangerous Eloquent method calls with request data.
     */
    private function checkDangerousMethodCalls(string $file, array $ast, array &$issues): void
    {
        // Check static method calls (e.g., User::create())
        foreach (self::MODEL_STATIC_METHODS as $method) {
            $calls = $this->findStaticMethodCalls($ast, $method);

            foreach ($calls as $call) {
                $this->checkCallForRequestData($call, $method, 'static', $file, $issues);
            }
        }

        // Check instance method calls (e.g., $model->update())
        foreach (self::MODEL_INSTANCE_METHODS as $method) {
            $calls = $this->parser->findMethodCalls($ast, $method);

            foreach ($calls as $call) {
                if ($call instanceof Node\Expr\MethodCall) {
                    $this->checkCallForRequestData($call, $method, 'instance', $file, $issues);
                }
            }
        }
    }

    /**
     * Check for dangerous query builder calls with request data.
     */
    private function checkQueryBuilderCalls(string $file, array $ast, array &$issues): void
    {
        foreach (self::BUILDER_METHODS as $method) {
            // Find all method calls with this name
            $calls = $this->parser->findMethodCalls($ast, $method);

            foreach ($calls as $call) {
                // Check if it's called on a query builder
                if ($call instanceof Node\Expr\MethodCall && $this->isQueryBuilderCall($call)) {
                    $this->checkCallForRequestData($call, $method, 'builder', $file, $issues);
                }
            }
        }
    }

    /**
     * Find static method calls in AST.
     */
    private function findStaticMethodCalls(array $ast, string $methodName): array
    {
        $calls = [];

        $traverse = function (array $nodes) use (&$traverse, &$calls, $methodName): void {
            foreach ($nodes as $node) {
                if ($node instanceof Node\Expr\StaticCall) {
                    if ($node->name instanceof Node\Identifier && $node->name->toString() === $methodName) {
                        $calls[] = $node;
                    }
                }

                // Recursively traverse child nodes
                foreach ($node->getSubNodeNames() as $subNodeName) {
                    $subNode = $node->$subNodeName;
                    if (is_array($subNode)) {
                        $traverse($subNode);
                    } elseif ($subNode instanceof Node) {
                        $traverse([$subNode]);
                    }
                }
            }
        };

        $traverse($ast);

        return $calls;
    }

    /**
     * Check if a method call is on a query builder.
     */
    private function isQueryBuilderCall(Node\Expr\MethodCall $call): bool
    {
        // Check if called on DB facade
        if ($call->var instanceof Node\Expr\StaticCall) {
            if ($call->var->class instanceof Node\Name) {
                $className = $call->var->class->toString();
                if ($className === 'DB' || str_ends_with($className, '\\DB')) {
                    return true;
                }
            }
        }

        // Check if called on ->query() result
        if ($call->var instanceof Node\Expr\MethodCall) {
            if ($call->var->name instanceof Node\Identifier && $call->var->name->toString() === 'query') {
                return true;
            }
        }

        // Check if called on table() result
        if ($call->var instanceof Node\Expr\MethodCall) {
            if ($call->var->name instanceof Node\Identifier && $call->var->name->toString() === 'table') {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a call contains request data in its arguments.
     */
    private function checkCallForRequestData(
        Node\Expr\MethodCall|Node\Expr\StaticCall $call,
        string $method,
        string $callType,
        string $file,
        array &$issues
    ): void {
        if (empty($call->args)) {
            return;
        }

        foreach ($call->args as $arg) {
            if ($this->isRequestData($arg->value)) {
                $callTypeLabel = match ($callType) {
                    'static' => 'Static call to',
                    'instance' => 'Instance call to',
                    'builder' => 'Query builder call to',
                    default => 'Call to',
                };

                $issues[] = $this->createIssue(
                    message: "{$callTypeLabel} {$method}() with unfiltered request data may result in mass assignment vulnerability",
                    location: new Location(
                        $this->getRelativePath($file),
                        $call->getLine()
                    ),
                    severity: Severity::Critical,
                    recommendation: 'Use request()->only([...]) or request()->validated() to specify allowed fields explicitly',
                    code: FileParser::getCodeSnippet($file, $call->getLine()),
                    metadata: [
                        'method' => $method,
                        'call_type' => $callType,
                        'issue_type' => 'dangerous_method_with_request_data',
                    ]
                );

                // Only report once per method call
                break;
            }
        }
    }

    /**
     * Check if a node represents request data (all dangerous forms).
     */
    private function isRequestData(Node $node): bool
    {
        // Check for request()->method() patterns
        if ($node instanceof Node\Expr\MethodCall) {
            if ($node->name instanceof Node\Identifier) {
                $methodName = $node->name->toString();

                // Check if it's a dangerous request method
                if (in_array($methodName, self::REQUEST_DATA_METHODS, true)) {
                    // Called on request() function
                    if ($node->var instanceof Node\Expr\FuncCall) {
                        if ($node->var->name instanceof Node\Name && $node->var->name->toString() === 'request') {
                            // Check if no arguments (e.g., request()->input() with no args = all input)
                            if (in_array($methodName, ['input', 'get', 'post', 'query'], true)) {
                                // If has args, it's filtering - OK
                                if (! empty($node->args)) {
                                    return false;
                                }
                            }

                            return true;
                        }
                    }

                    // Called on $request variable
                    if ($node->var instanceof Node\Expr\Variable && $node->var->name === 'request') {
                        // Same logic for instance methods
                        if (in_array($methodName, ['input', 'get', 'post', 'query'], true)) {
                            if (! empty($node->args)) {
                                return false;
                            }
                        }

                        return true;
                    }
                }

                // Check for ->only() or ->validated() - these are safe
                if (in_array($methodName, ['only', 'validated', 'safe'], true)) {
                    return false;
                }
            }
        }

        // Check for Request::all() static calls
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->name instanceof Node\Identifier) {
                $methodName = $node->name->toString();

                if (in_array($methodName, self::REQUEST_DATA_METHODS, true)) {
                    if ($node->class instanceof Node\Name) {
                        $className = $node->class->toString();
                        if (str_contains($className, 'Request')) {
                            return true;
                        }
                    }
                }
            }
        }

        // Check for Input::all() facade (legacy)
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->class instanceof Node\Name) {
                $className = $node->class->toString();
                if ($className === 'Input' || str_ends_with($className, '\\Input')) {
                    if ($node->name instanceof Node\Identifier) {
                        if (in_array($node->name->toString(), self::REQUEST_DATA_METHODS, true)) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }
}
