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
 */
class MassAssignmentAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'mass-assignment',
            name: 'Mass Assignment Vulnerability Detector',
            description: 'Detects mass assignment vulnerabilities in Eloquent models',
            category: Category::Security,
            severity: Severity::High,
            tags: ['mass-assignment', 'eloquent', 'security', 'models'],
            docsUrl: 'https://laravel.com/docs/eloquent#mass-assignment'
        );
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

            // Check for dangerous method calls
            $this->checkDangerousMethodCalls($file, $ast, $issues);
        }

        if (empty($issues)) {
            return $this->passed('No mass assignment vulnerabilities detected');
        }

        return $this->failed(
            sprintf('Found %d potential mass assignment vulnerabilities', count($issues)),
            $issues
        );
    }

    /**
     * Check if a class is an Eloquent model.
     */
    private function isEloquentModel(string $file, Node\Stmt\Class_ $class): bool
    {
        // Check if it's in app/Models or extends Model
        $content = FileParser::readFile($file);
        if ($content === null) {
            return false;
        }

        // Check namespace
        if (str_contains($content, 'namespace App\\Models')) {
            return true;
        }

        // Check if extends Model
        if ($class->extends !== null) {
            $parentClass = $class->extends->toString();
            if ($parentClass === 'Model' || str_ends_with($parentClass, '\\Model')) {
                return true;
            }
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
                code: $this->getCodeSnippet($file, $class->getLine())
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
                code: $this->getCodeSnippet($file, $class->getLine())
            );
        }
    }

    /**
     * Check for dangerous method calls with request()->all().
     */
    private function checkDangerousMethodCalls(string $file, array $ast, array &$issues): void
    {
        $dangerousMethods = ['create', 'update', 'fill', 'forceFill'];

        foreach ($dangerousMethods as $method) {
            // Check instance method calls like $model->create()
            $calls = $this->parser->findMethodCalls($ast, $method);

            foreach ($calls as $call) {
                if ($call instanceof Node\Expr\MethodCall) {
                    $this->checkCallForRequestAll($call, $method, $file, $issues);
                }
            }

            // Also check static method calls like User::create()
            $staticCalls = $this->findStaticMethodCalls($ast, $method);
            foreach ($staticCalls as $call) {
                if ($call instanceof Node\Expr\StaticCall) {
                    $this->checkCallForRequestAll($call, $method, $file, $issues);
                }
            }
        }
    }

    /**
     * Find static method calls in AST using the parser's node finder.
     */
    private function findStaticMethodCalls(array $ast, string $methodName): array
    {
        // Use reflection to access the nodeFinder from parser
        $reflection = new \ReflectionClass($this->parser);
        $nodeFinderProperty = $reflection->getProperty('nodeFinder');
        $nodeFinderProperty->setAccessible(true);
        $nodeFinder = $nodeFinderProperty->getValue($this->parser);

        // Find static calls
        $calls = $nodeFinder->find($ast, function (Node $node) use ($methodName) {
            if (! $node instanceof Node\Expr\StaticCall) {
                return false;
            }

            if (! $node->name instanceof Node\Identifier) {
                return false;
            }

            return $node->name->toString() === $methodName;
        });

        return $calls;
    }

    /**
     * Check if a call contains request()->all() in its arguments.
     */
    private function checkCallForRequestAll(Node\Expr\MethodCall|Node\Expr\StaticCall $call, string $method, string $file, array &$issues): void
    {
        // Check if arguments contain request()->all() or $request->all()
        if (! empty($call->args)) {
            foreach ($call->args as $arg) {
                if ($this->isRequestAll($arg->value)) {
                    $issues[] = $this->createIssue(
                        message: "Dangerous: {$method}() called with request()->all() or \$request->all()",
                        location: new Location(
                            $this->getRelativePath($file),
                            $call->getLine()
                        ),
                        severity: Severity::Critical,
                        recommendation: 'Use request()->only([...]) or request()->validated() to specify allowed fields explicitly',
                        code: $this->getCodeSnippet($file, $call->getLine())
                    );
                }
            }
        }
    }

    /**
     * Check if a node represents request()->all() or $request->all() or Request::all().
     */
    private function isRequestAll(Node $node): bool
    {
        // Check for request()->all() or $request->all()
        if ($node instanceof Node\Expr\MethodCall) {
            if ($node->name instanceof Node\Identifier && $node->name->toString() === 'all') {
                // Check if called on request() function
                if ($node->var instanceof Node\Expr\FuncCall) {
                    if ($node->var->name instanceof Node\Name && $node->var->name->toString() === 'request') {
                        return true;
                    }
                }

                // Check if called on $request variable
                if ($node->var instanceof Node\Expr\Variable && $node->var->name === 'request') {
                    return true;
                }
            }
        }

        // Check for Request::all()
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->name instanceof Node\Identifier && $node->name->toString() === 'all') {
                if ($node->class instanceof Node\Name && str_contains($node->class->toString(), 'Request')) {
                    return true;
                }
            }
        }

        return false;
    }
}
