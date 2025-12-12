<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Identifies violations of MVC pattern.
 *
 * Checks for:
 * - Models with rendering logic
 * - Views with DB queries or model creates
 * - Controllers with excessive business logic
 */
class MvcStructureViolationAnalyzer extends AbstractFileAnalyzer
{
    public const MAX_CONTROLLER_METHOD_LINES = 50;

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'mvc-structure-violation',
            name: 'MVC Structure Violation Analyzer',
            description: 'Detects violations of Model-View-Controller architectural pattern',
            category: Category::BestPractices,
            severity: Severity::High,
            tags: ['laravel', 'mvc', 'architecture', 'separation-of-concerns'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/mvc-structure-violation',
            timeToFix: 30
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Store the test-provided base path (if any) before each check
        $testBasePath = $this->basePath ?? null;

        // Check Models
        $this->checkModels($issues, $testBasePath);

        // Check Controllers
        $this->checkControllers($issues, $testBasePath);

        // Check Views (Blade templates)
        $this->checkViews($issues, $testBasePath);

        if (empty($issues)) {
            return $this->passed('MVC pattern is properly followed');
        }

        return $this->failed(
            sprintf('Found %d MVC violation(s)', count($issues)),
            $issues
        );
    }

    private function checkModels(array &$issues, ?string $testBasePath): void
    {
        $this->setBasePath($testBasePath ?? base_path());
        if (empty($this->paths)) {
            $this->setPaths(['app/Models', 'app']);
        }

        $modelFiles = $this->getPhpFiles();

        foreach ($modelFiles as $file) {
            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new ModelMvcViolationVisitor;
                $traverser = new NodeTraverser;
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getIssues() as $issue) {
                    $issues[] = $this->createIssue(
                        message: $issue['message'],
                        location: new Location($this->getRelativePath($file), $issue['line']),
                        severity: $issue['severity'],
                        recommendation: $issue['recommendation'],
                        code: $issue['code'] ?? null,
                    );
                }
            } catch (\Throwable $e) {
                continue;
            }
        }
    }

    private function checkControllers(array &$issues, ?string $testBasePath): void
    {
        $this->setBasePath($testBasePath ?? base_path());
        if (empty($this->paths)) {
            $this->setPaths(['app/Http/Controllers']);
        }

        $controllerFiles = $this->getPhpFiles();

        foreach ($controllerFiles as $file) {
            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new ControllerMvcViolationVisitor;
                $traverser = new NodeTraverser;
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getIssues() as $issue) {
                    $issues[] = $this->createIssue(
                        message: $issue['message'],
                        location: new Location($this->getRelativePath($file), $issue['line']),
                        severity: $issue['severity'],
                        recommendation: $issue['recommendation'],
                        code: $issue['code'] ?? null,
                    );
                }
            } catch (\Throwable $e) {
                continue;
            }
        }
    }

    private function checkViews(array &$issues, ?string $testBasePath): void
    {
        $this->setBasePath($testBasePath ?? base_path());
        if (empty($this->paths)) {
            $this->setPaths(['resources/views']);
        }

        $viewFiles = $this->getBladeFiles();

        foreach ($viewFiles as $file) {
            try {
                $content = FileParser::readFile($file);
                if ($content === null) {
                    continue;
                }

                $lines = FileParser::getLines($file);

                foreach ($lines as $lineNumber => $line) {
                    // Check for DB queries in views
                    if ($this->hasDbQuery($line)) {
                        $issues[] = $this->createIssue(
                            message: 'View contains database query (MVC violation)',
                            location: new Location($this->getRelativePath($file), $lineNumber + 1),
                            severity: Severity::Critical,
                            recommendation: 'Views should never contain database queries. Load all data in the controller and pass to the view. Views are for presentation only',
                            code: trim($line),
                        );
                    }

                    // Check for model creates in views
                    if ($this->hasModelCreate($line)) {
                        $issues[] = $this->createIssue(
                            message: 'View contains model creation (MVC violation)',
                            location: new Location($this->getRelativePath($file), $lineNumber + 1),
                            severity: Severity::Critical,
                            recommendation: 'Views should never create or modify models. All data manipulation belongs in controllers or services',
                            code: trim($line),
                        );
                    }
                }
            } catch (\Throwable $e) {
                continue;
            }
        }
    }

    /**
     * Get all blade files to analyze.
     *
     * @return array<string>
     */
    private function getBladeFiles(): array
    {
        $files = [];

        foreach ($this->getFilesToAnalyze() as $file) {
            $filename = $file->getFilename();
            if (str_ends_with($filename, '.blade.php')) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    private function hasDbQuery(string $line): bool
    {
        $patterns = [
            '/\bDB::/',
            '/::where\s*\(/',
            '/::find\s*\(/',
            '/::all\s*\(/',
            '/::get\s*\(/',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $line)) {
                return true;
            }
        }

        return false;
    }

    private function hasModelCreate(string $line): bool
    {
        return preg_match('/::create\s*\(/', $line) || preg_match('/->save\s*\(/', $line);
    }
}

/**
 * Visitor to detect MVC violations in Models.
 */
class ModelMvcViolationVisitor extends NodeVisitorAbstract
{
    private array $issues = [];

    private ?string $currentClassName = null;

    public function enterNode(Node $node): ?Node
    {
        // Track current class
        if ($node instanceof Node\Stmt\Class_) {
            $this->currentClassName = $node->name?->toString();

            // Check if it extends Model
            if ($this->extendsModel($node)) {
                $this->checkModelMethods($node);
            }
        }

        return null;
    }

    private function extendsModel(Node\Stmt\Class_ $class): bool
    {
        if ($class->extends === null) {
            return false;
        }

        $parentClass = $class->extends->toString();

        return $parentClass === 'Model'
            || str_ends_with($parentClass, '\\Model')
            || $parentClass === 'Illuminate\\Database\\Eloquent\\Model';
    }

    private function checkModelMethods(Node\Stmt\Class_ $class): void
    {
        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\ClassMethod) {
                $methodName = $stmt->name->toString();

                // Check for rendering methods (view-related logic in models)
                $renderingMethods = ['render', 'toHtml', 'toView', 'renderView'];
                if (in_array($methodName, $renderingMethods, true)) {
                    $this->issues[] = [
                        'message' => sprintf('Model "%s" has rendering method "%s()" (MVC violation)', $this->currentClassName, $methodName),
                        'line' => $stmt->getLine(),
                        'severity' => Severity::High,
                        'recommendation' => 'Models should not contain view rendering logic. Move this to a controller or view composer. Models are for data and relationships only',
                        'code' => null,
                    ];
                }

                // Check if method body calls view()
                if ($this->callsViewHelper($stmt)) {
                    $this->issues[] = [
                        'message' => sprintf('Model "%s" method "%s()" calls view() helper (MVC violation)', $this->currentClassName, $methodName),
                        'line' => $stmt->getLine(),
                        'severity' => Severity::High,
                        'recommendation' => 'Models should not render views. This belongs in controllers. Models should focus on data representation',
                        'code' => null,
                    ];
                }
            }
        }
    }

    private function callsViewHelper(Node\Stmt\ClassMethod $method): bool
    {
        $visitor = new ViewHelperDetectorVisitor;

        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($method->stmts ?? []);

        return $visitor->hasViewCall();
    }

    public function getIssues(): array
    {
        return $this->issues;
    }
}

/**
 * Helper visitor to detect view() calls.
 */
class ViewHelperDetectorVisitor extends NodeVisitorAbstract
{
    private bool $callsView = false;

    public function enterNode(Node $node): ?Node
    {
        if ($node instanceof Node\Expr\FuncCall) {
            if ($node->name instanceof Node\Name && $node->name->toString() === 'view') {
                $this->callsView = true;
            }
        }

        return null;
    }

    public function hasViewCall(): bool
    {
        return $this->callsView;
    }
}

/**
 * Visitor to detect MVC violations in Controllers.
 */
class ControllerMvcViolationVisitor extends NodeVisitorAbstract
{
    private array $issues = [];

    private ?string $currentClassName = null;

    public function enterNode(Node $node): ?Node
    {
        // Track current class
        if ($node instanceof Node\Stmt\Class_) {
            $this->currentClassName = $node->name?->toString();
        }

        // Check controller methods
        if ($node instanceof Node\Stmt\ClassMethod) {
            $this->checkControllerMethod($node);
        }

        return null;
    }

    private function checkControllerMethod(Node\Stmt\ClassMethod $method): void
    {
        // Check method length (long methods indicate business logic)
        $lineCount = $method->getEndLine() - $method->getStartLine();

        if ($lineCount > MvcStructureViolationAnalyzer::MAX_CONTROLLER_METHOD_LINES) {
            $this->issues[] = [
                'message' => sprintf(
                    'Controller method "%s::%s()" has %d lines (max: %d). Large methods indicate business logic in controller',
                    $this->currentClassName ?? 'Unknown',
                    $method->name->toString(),
                    $lineCount,
                    MvcStructureViolationAnalyzer::MAX_CONTROLLER_METHOD_LINES
                ),
                'line' => $method->getStartLine(),
                'severity' => Severity::High,
                'recommendation' => 'Controllers should be thin, focusing on HTTP request/response handling. Extract business logic to service classes. Controllers should coordinate, not implement',
                'code' => null,
            ];
        }
    }

    public function getIssues(): array
    {
        return $this->issues;
    }
}
