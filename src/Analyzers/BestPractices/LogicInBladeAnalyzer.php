<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Support\BladeCompilerFactory;

/**
 * Detects business logic in Blade templates using a hybrid regex + AST approach.
 *
 * Pass 1 (regex on raw Blade): Structural checks — @php block size, inline PHP, unclosed blocks.
 * Pass 2 (AST on compiled PHP): Logic detection — DB queries, API calls, business logic,
 *         complex calculations, expensive computation, nested @foreach, collection manipulation.
 *
 * The AST pass compiles Blade → PHP via BladeCompiler, then parses the compiled PHP with
 * nikic/php-parser. This gives structural access to static calls, method chains, and function
 * calls — eliminating multi-line scanning and string/comment false-positive logic entirely.
 */
class LogicInBladeAnalyzer extends AbstractFileAnalyzer
{
    public const DEFAULT_MAX_PHP_BLOCK_LINES = 10;

    public const DEFAULT_MIN_ARITHMETIC_OPERATORS = 2;

    private int $maxPhpBlockLines;

    private int $minArithmeticOperators;

    /** @var array<int, true> Track reported lines to avoid duplicates */
    private array $reportedLines = [];

    public function __construct(
        private Config $config,
        private AstParser $astParser = new AstParser,
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'logic-in-blade',
            name: 'Logic in Blade Analyzer',
            description: 'Finds business logic in Blade templates that should be moved to controllers or view composers',
            category: Category::BestPractices,
            severity: Severity::Medium,
            tags: ['laravel', 'blade', 'mvc', 'views', 'architecture'],
            timeToFix: 30
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration
        $analyzerConfig = $this->config->get('shieldci.analyzers.best-practices.logic-in-blade', []);
        $analyzerConfig = is_array($analyzerConfig) ? $analyzerConfig : [];

        $this->maxPhpBlockLines = $analyzerConfig['max_php_block_lines'] ?? self::DEFAULT_MAX_PHP_BLOCK_LINES;
        $this->minArithmeticOperators = $analyzerConfig['min_arithmetic_operators'] ?? self::DEFAULT_MIN_ARITHMETIC_OPERATORS;

        $issues = [];

        // Only set default paths if not already set (allows tests to override)
        if (empty($this->paths)) {
            $this->setBasePath(base_path());
            $this->setPaths(['resources/views']);
        }

        $bladeFiles = $this->getBladeFiles();

        foreach ($bladeFiles as $file) {
            try {
                // Reset reported lines for each file
                $this->reportedLines = [];
                $this->analyzeBladeFile($file, $issues);
            } catch (\Throwable $e) {
                // Skip files with read errors
                continue;
            }
        }

        if (empty($issues)) {
            return $this->passed('No business logic found in Blade templates');
        }

        return $this->resultBySeverity(
            sprintf('Found %d Blade template(s) with business logic', count($issues)),
            $issues
        );
    }

    private function getBladeFiles(): array
    {
        $files = [];

        foreach ($this->getFilesToAnalyze() as $file) {
            if (str_ends_with($file->getFilename(), '.blade.php')) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    /**
     * Two-pass analysis: structural regex checks + AST logic detection.
     *
     * @param  array<int, array{message: string, filePath: string, lineNumber: int, severity: Severity, recommendation: string, code: string, metadata: array<string, mixed>}>  $issues
     */
    private function analyzeBladeFile(string $file, array &$issues): void
    {
        $content = FileParser::readFile($file);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($file);

        // Pass 1: Structural checks on raw Blade (PHP block size, inline PHP, unclosed blocks)
        $this->analyzeBladeStructure($file, $lines, $issues);

        // Pass 2: Logic detection via compiled PHP AST
        $this->analyzeBladeLogic($file, $content, $issues);
    }

    /**
     * Pass 1: Structural checks using regex on raw Blade source.
     *
     * Detects:
     * - @php blocks exceeding max line threshold
     * - Inline <?php tags
     * - Unclosed @php blocks
     *
     * @param  array<int, string>  $lines
     * @param  array<int, array{message: string, filePath: string, lineNumber: int, severity: Severity, recommendation: string, code: string, metadata: array<string, mixed>}>  $issues
     */
    private function analyzeBladeStructure(string $file, array $lines, array &$issues): void
    {
        $inPhpBlock = false;
        $phpBlockStart = 0;
        $phpBlockLines = 0;

        foreach ($lines as $lineNumber => $line) {
            $trimmed = trim($line);

            // Check for @php block start
            if (preg_match('/@php\b/', $trimmed)) {
                $inPhpBlock = true;
                $phpBlockStart = $lineNumber + 1;
                $phpBlockLines = 0;

                continue;
            }

            // Check for @php block end
            if (preg_match('/@endphp\b/', $trimmed)) {
                if ($phpBlockLines > $this->maxPhpBlockLines) {
                    $this->reportedLines[$phpBlockStart - 1] = true;

                    $issues[] = $this->createIssueWithSnippet(
                        message: sprintf(
                            'PHP block has %d lines (max recommended: %d)',
                            $phpBlockLines,
                            $this->maxPhpBlockLines
                        ),
                        filePath: $file,
                        lineNumber: $phpBlockStart,
                        severity: Severity::Medium,
                        recommendation: 'Move complex PHP logic to controllers, view composers, or presenter classes. Blade templates should focus on presentation only',
                        code: 'blade-php-block-too-long',
                        metadata: [
                            'block_lines' => $phpBlockLines,
                            'max_lines' => $this->maxPhpBlockLines,
                            'block_start' => $phpBlockStart,
                        ]
                    );
                }
                $inPhpBlock = false;

                continue;
            }

            // Count lines in PHP block
            if ($inPhpBlock) {
                $phpBlockLines++;
            }

            // Detect inline <?php tags
            if (preg_match('/<\?php/', $line)) {
                $this->reportedLines[$lineNumber] = true;

                $issues[] = $this->createIssueWithSnippet(
                    message: 'Inline PHP found in Blade template',
                    filePath: $file,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::Medium,
                    recommendation: 'Use Blade directives (@php...@endphp) instead of inline PHP for consistency',
                    code: 'blade-inline-php',
                    metadata: ['line' => $lineNumber + 1]
                );
            }
        }

        // Unclosed @php block
        if ($inPhpBlock) {
            $issues[] = $this->createIssueWithSnippet(
                message: 'Unclosed @php block detected',
                filePath: $file,
                lineNumber: $phpBlockStart,
                severity: Severity::High,
                recommendation: 'Every @php directive must have a matching @endphp',
                code: 'blade-unclosed-php-block',
                metadata: [
                    'block_start' => $phpBlockStart,
                    'lines_counted' => $phpBlockLines,
                ]
            );
        }
    }

    /**
     * Pass 2: Logic detection via compiled PHP AST.
     *
     * Compiles Blade → PHP, parses with nikic/php-parser, traverses the AST
     * with BladeLogicVisitor to detect business logic patterns, then maps
     * compiled-PHP line numbers back to original Blade lines.
     *
     * @param  array<int, array{message: string, filePath: string, lineNumber: int, severity: Severity, recommendation: string, code: string, metadata: array<string, mixed>}>  $issues
     */
    private function analyzeBladeLogic(string $file, string $content, array &$issues): void
    {
        $result = BladeCompilerFactory::compile($content);
        if ($result === null) {
            return;
        }

        $ast = $this->astParser->parseCode($result['compiledPhp']);
        if (empty($ast)) {
            return;
        }

        $visitor = new BladeLogicVisitor($this->minArithmeticOperators);
        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        $lineMap = $result['lineMap'];

        foreach ($visitor->getIssues() as $astIssue) {
            $compiledLine = $astIssue['line'];
            $originalLine = $lineMap[$compiledLine] ?? null;

            if ($originalLine === null) {
                continue;
            }

            // Use 0-indexed key for reportedLines (consistent with Pass 1)
            $lineKey = $originalLine - 1;
            if (isset($this->reportedLines[$lineKey])) {
                continue;
            }

            $this->reportedLines[$lineKey] = true;

            $metadata = array_merge(['line' => $originalLine], $astIssue['metadata'] ?? []);

            $issues[] = $this->createIssueWithSnippet(
                message: $astIssue['message'],
                filePath: $file,
                lineNumber: $originalLine,
                severity: $astIssue['severity'],
                recommendation: $astIssue['recommendation'],
                code: $astIssue['code'],
                metadata: $metadata
            );
        }
    }
}

/**
 * AST visitor that detects business logic patterns in compiled Blade PHP.
 *
 * Traverses the AST once, collecting issues for:
 * - DB queries (static calls, method chains, model save)
 * - API calls (Http facade, curl, file_get_contents)
 * - Business logic functions (array_filter, array_map, etc.)
 * - Complex @if conditions (4+ boolean operators)
 * - Expensive computation (toArray, toJson, regex in loops)
 * - Complex calculations (multiple arithmetic operators, compound assignment)
 * - Nested @foreach loops
 * - Collection manipulation in @foreach expressions
 */
class BladeLogicVisitor extends NodeVisitorAbstract
{
    private int $foreachDepth = 0;

    /** @var list<array{message: string, severity: Severity, recommendation: string, code: string, line: int, metadata: array<string, mixed>}> */
    private array $issues = [];

    public function __construct(
        private int $minArithmeticOperators = LogicInBladeAnalyzer::DEFAULT_MIN_ARITHMETIC_OPERATORS,
    ) {}

    /** @var array<string> Non-Eloquent classes with DB-like method names */
    private const NON_ELOQUENT_CLASSES = [
        'Collection',
        'Arr',
        'Carbon',
        'CarbonImmutable',
        'DateTime',
        'DateTimeImmutable',
        'Factory',
        'Str',
        'Validator',
    ];

    /** @var array<string> Class name suffixes that are NEVER Eloquent models */
    private const DEFINITE_NON_MODEL_SUFFIXES = [
        'Service', 'Repository', 'Helper', 'Handler', 'Provider', 'Facade',
        'Controller', 'Middleware', 'Policy', 'Event', 'Listener', 'Job',
        'Mail', 'Notification', 'Command', 'Request', 'Rule', 'Exception',
        'Trait', 'Interface', 'Contract', 'Test', 'Seeder', 'Migration',
        'Observer', 'Scope', 'Cast', 'Enum', 'Factory', 'Action',
    ];

    /** @var array<string> Ambiguous suffixes — only flag with terminal + Models namespace */
    private const AMBIGUOUS_SUFFIXES = [
        'Resource',
        'Manager',
        'Builder',
    ];

    /** @var array<string> Variable name patterns that suggest collections, not models */
    private const COLLECTION_VARIABLE_PATTERNS = [
        'collection', 'items', 'list', 'array', 'data',
        'results', 'rows', 'records', 'entries',
    ];

    /** @var array<string> Variables whose ->save() is not a DB operation */
    private const NON_DB_SAVE_VARIABLES = [
        'file', 'upload', 'image', 'photo', 'document', 'attachment',
        'pdf', 'excel', 'csv', 'export', 'cache', 'temp', 'storage',
    ];

    /** @var array<string> */
    private const BUSINESS_LOGIC_FUNCTIONS = [
        'array_filter', 'array_map', 'array_reduce', 'array_walk',
        'array_merge', 'array_combine', 'array_diff',
    ];

    /** @var array<string> */
    private const EXPENSIVE_STRING_FUNCTIONS = [
        'preg_match', 'preg_replace', 'preg_match_all', 'preg_split',
        'str_replace', 'str_ireplace', 'substr_replace', 'mb_ereg_replace',
    ];

    /** @var array<string> Expensive collection methods */
    private const EXPENSIVE_COLLECTION_METHODS = [
        'toArray', 'all', 'toJson', 'jsonSerialize',
    ];

    /** @var array<string> Terminal methods that confirm a DB query chain */
    private const TERMINAL_QUERY_METHODS = [
        'get', 'first', 'find', 'count', 'exists',
        'pluck', 'sum', 'avg', 'min', 'max', 'paginate',
    ];

    /** @var array<string> Self-terminal static methods (the call IS the operation) */
    private const SELF_TERMINAL_METHODS = [
        'find', 'all', 'first', 'create', 'update',
        'delete', 'insert', 'upsert',
    ];

    /** @var array<string> API-related function names */
    private const API_FUNCTIONS = ['curl_init', 'curl_exec', 'file_get_contents'];

    /** @var array<string> Collection manipulation methods flagged in @foreach */
    private const COLLECTION_MANIPULATION_METHODS = [
        'filter', 'map', 'transform', 'sortBy',
        'pluck', 'unique', 'chunk', 'groupBy', 'keyBy',
        'reverse', 'shuffle', 'values', 'keys',
    ];

    /**
     * @return list<array{message: string, severity: Severity, recommendation: string, code: string, line: int, metadata: array<string, mixed>}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }

    public function enterNode(Node $node): ?int
    {
        // Track foreach depth
        if ($node instanceof Stmt\Foreach_) {
            $this->foreachDepth++;

            // Check for nested @foreach (depth >= 2)
            if ($this->foreachDepth >= 2) {
                $this->addIssue(
                    line: $node->getStartLine(),
                    message: sprintf('Nested @foreach detected (depth: %d) - potential performance issue', $this->foreachDepth),
                    severity: Severity::Medium,
                    recommendation: 'Flatten nested data in the controller using eager loading or collection methods. Deeply nested loops in Blade can cause O(n²) or worse rendering performance',
                    code: 'blade-nested-foreach',
                    metadata: ['depth' => $this->foreachDepth],
                );
            }

            // Check for collection manipulation in foreach expression
            $this->checkForeachExpression($node);
        }

        // Detect $__currentLoopData = $expr->collectionMethod() pattern
        // (Blade compiles @foreach($items->filter() as $item) to this)
        if ($node instanceof Expr\Assign) {
            $this->checkCurrentLoopDataAssignment($node);
        }

        // DB query detection — static calls
        if ($node instanceof Expr\StaticCall) {
            $this->checkDbStaticCall($node);
            $this->checkApiStaticCall($node);
        }

        // DB query detection — method chains
        if ($node instanceof Expr\MethodCall) {
            $this->checkDbMethodChain($node);
            $this->checkModelSave($node);
            $this->checkExpensiveCollectionMethod($node);
        }

        // API call and business logic — function calls
        if ($node instanceof Expr\FuncCall) {
            $this->checkApiFuncCall($node);
            $this->checkBusinessLogicFunction($node);
            if ($this->foreachDepth >= 1) {
                $this->checkExpensiveStringFunction($node);
            }
        }

        // Complex @if conditions
        if ($node instanceof Stmt\If_) {
            $this->checkComplexCondition($node);
        }

        // Complex calculations — compound assignment operators
        if ($node instanceof Expr\AssignOp) {
            $this->checkCompoundAssignment($node);
        }

        // Complex calculations in echo expressions (Blade {{ }} compiles to echo e(...))
        if ($node instanceof Stmt\Echo_) {
            $this->checkEchoCalculation($node);
        }

        return null;
    }

    public function leaveNode(Node $node): ?int
    {
        if ($node instanceof Stmt\Foreach_) {
            $this->foreachDepth = max(0, $this->foreachDepth - 1);
        }

        return null;
    }

    private function checkDbStaticCall(Expr\StaticCall $node): void
    {
        if (! $node->class instanceof Name || ! $node->name instanceof Identifier) {
            return;
        }

        $fullClassName = $node->class->toString();
        $shortName = $this->getShortClassName($fullClassName);
        $methodName = $node->name->name;

        // DB facade — always flag
        if ($shortName === 'DB') {
            $this->addDbIssue($node->getStartLine());

            return;
        }

        // ->query() method — always flag
        if ($methodName === 'query') {
            $this->addDbIssue($node->getStartLine());

            return;
        }

        // Skip known non-Eloquent classes
        if (in_array($shortName, self::NON_ELOQUENT_CLASSES, true)) {
            return;
        }

        // Skip definite non-model suffixes
        if ($this->hasDefiniteNonModelSuffix($shortName)) {
            return;
        }

        // Self-terminal methods (::find(), ::all(), ::first(), ::create(), etc.)
        // Ambiguous suffixes (Resource, Manager, Builder) need Models namespace to flag
        if (in_array($methodName, self::SELF_TERMINAL_METHODS, true)) {
            if ($this->hasAmbiguousSuffix($shortName)) {
                if (str_contains($fullClassName, '\\Models\\') || str_contains($fullClassName, '\\Model\\')) {
                    $this->addDbIssue($node->getStartLine());
                }

                return;
            }

            $this->addDbIssue($node->getStartLine());

            return;
        }

        // Chain-start methods (::where()) — need terminal or FQCN to confirm
        if ($methodName === 'where') {
            // FQCN with \Models\ → definitely a model
            if (str_contains($fullClassName, '\\Models\\') || str_contains($fullClassName, '\\Model\\')) {
                $this->addDbIssue($node->getStartLine());

                return;
            }

            // Ambiguous suffix without terminal — skip
            // Unknown class without terminal — skip (avoid false positives)
            // Terminal detection is handled by checkDbMethodChain when it
            // encounters the terminal MethodCall and walks down to this StaticCall root.
        }
    }

    private function checkDbMethodChain(Expr\MethodCall $node): void
    {
        if (! $node->name instanceof Identifier) {
            return;
        }

        $methodName = $node->name->name;

        // Only check terminal methods
        if (! in_array($methodName, self::TERMINAL_QUERY_METHODS, true)) {
            return;
        }

        // Walk the chain down to the root
        $root = $node->var;
        while ($root instanceof Expr\MethodCall) {
            $root = $root->var;
        }

        // Root is a static call — check if it's a DB query
        if ($root instanceof Expr\StaticCall) {
            if (! $root->class instanceof Name) {
                return;
            }

            $fullClassName = $root->class->toString();
            $shortName = $this->getShortClassName($fullClassName);

            // DB facade
            if ($shortName === 'DB') {
                $this->addDbIssue($root->getStartLine());

                return;
            }

            // Skip known non-Eloquent classes
            if (in_array($shortName, self::NON_ELOQUENT_CLASSES, true)) {
                return;
            }

            // Skip definite non-model suffixes
            if ($this->hasDefiniteNonModelSuffix($shortName)) {
                return;
            }

            // FQCN with Models namespace
            if (str_contains($fullClassName, '\\Models\\') || str_contains($fullClassName, '\\Model\\')) {
                $this->addDbIssue($root->getStartLine());

                return;
            }

            // Has terminal method (we're here because it does) — flag it
            // This includes ambiguous suffixes: terminal confirms query intent
            $this->addDbIssue($root->getStartLine());

            return;
        }

        // Root is a FuncCall (collect() helper) — not a DB call
        if ($root instanceof Expr\FuncCall) {
            return;
        }

        // Check for relationship pattern: $var->method()->terminal()
        // The chain is: MethodCall(terminal) -> MethodCall(relationship) -> Variable
        if ($node->var instanceof Expr\MethodCall
            && $node->var->var instanceof Expr\Variable
            && is_string($node->var->var->name)) {
            $variableName = strtolower($node->var->var->name);

            // Check if variable name suggests a collection
            foreach (self::COLLECTION_VARIABLE_PATTERNS as $pattern) {
                if (str_contains($variableName, $pattern)) {
                    return;
                }
            }

            // Likely a relationship query: $user->posts()->get()
            $this->addDbIssue($node->getStartLine());
        }
    }

    private function checkModelSave(Expr\MethodCall $node): void
    {
        if (! $node->name instanceof Identifier) {
            return;
        }

        if ($node->name->name !== 'save') {
            return;
        }

        if (! $node->var instanceof Expr\Variable || ! is_string($node->var->name)) {
            return;
        }

        $variableName = $node->var->name;

        // Exclude non-database save patterns
        if (in_array($variableName, self::NON_DB_SAVE_VARIABLES, true)) {
            return;
        }

        $this->addDbIssue($node->getStartLine());
    }

    private function checkApiStaticCall(Expr\StaticCall $node): void
    {
        if (! $node->class instanceof Name) {
            return;
        }

        $className = $this->getShortClassName($node->class->toString());

        if ($className === 'Http') {
            $this->addIssue(
                line: $node->getStartLine(),
                message: 'API call found in Blade template',
                severity: Severity::High,
                recommendation: 'Make API calls in controllers or services, not in views. Views should only display pre-fetched data',
                code: 'blade-has-api-call',
            );
        }
    }

    private function checkApiFuncCall(Expr\FuncCall $node): void
    {
        if (! $node->name instanceof Name) {
            return;
        }

        $funcName = $node->name->toString();

        if (in_array($funcName, self::API_FUNCTIONS, true)) {
            $this->addIssue(
                line: $node->getStartLine(),
                message: 'API call found in Blade template',
                severity: Severity::High,
                recommendation: 'Make API calls in controllers or services, not in views. Views should only display pre-fetched data',
                code: 'blade-has-api-call',
            );
        }
    }

    private function checkBusinessLogicFunction(Expr\FuncCall $node): void
    {
        if (! $node->name instanceof Name) {
            return;
        }

        $funcName = $node->name->toString();

        if (in_array($funcName, self::BUSINESS_LOGIC_FUNCTIONS, true)) {
            $this->addIssue(
                line: $node->getStartLine(),
                message: 'Business logic found in Blade directive',
                severity: Severity::Medium,
                recommendation: 'Extract business logic to controllers or services. Use simple conditionals in views for presentation logic only',
                code: 'blade-has-business-logic',
            );
        }
    }

    private function checkComplexCondition(Stmt\If_ $node): void
    {
        $booleanCount = $this->countBooleanOperators($node->cond);

        if ($booleanCount >= 3) {
            $this->addIssue(
                line: $node->getStartLine(),
                message: 'Business logic found in Blade directive',
                severity: Severity::Medium,
                recommendation: 'Extract business logic to controllers or services. Use simple conditionals in views for presentation logic only',
                code: 'blade-has-business-logic',
            );
        }
    }

    private function countBooleanOperators(Node $node): int
    {
        $count = 0;

        if ($node instanceof Expr\BinaryOp\BooleanAnd || $node instanceof Expr\BinaryOp\BooleanOr) {
            $count = 1;
            $count += $this->countBooleanOperators($node->left);
            $count += $this->countBooleanOperators($node->right);
        }

        return $count;
    }

    private function checkExpensiveCollectionMethod(Expr\MethodCall $node): void
    {
        if (! $node->name instanceof Identifier) {
            return;
        }

        if (in_array($node->name->name, self::EXPENSIVE_COLLECTION_METHODS, true)) {
            // Skip if this is part of a DB chain (root is StaticCall) — handled elsewhere
            $root = $node->var;
            while ($root instanceof Expr\MethodCall) {
                $root = $root->var;
            }
            if ($root instanceof Expr\StaticCall) {
                return;
            }

            $this->addIssue(
                line: $node->getStartLine(),
                message: 'Expensive computation found in Blade template',
                severity: Severity::Medium,
                recommendation: 'Move expensive operations to controllers or services. Use computed properties or view composers for complex transformations',
                code: 'blade-expensive-computation',
            );
        }
    }

    private function checkExpensiveStringFunction(Expr\FuncCall $node): void
    {
        if (! $node->name instanceof Name) {
            return;
        }

        $funcName = $node->name->toString();

        if (in_array($funcName, self::EXPENSIVE_STRING_FUNCTIONS, true)) {
            $this->addIssue(
                line: $node->getStartLine(),
                message: 'Expensive computation found in Blade template',
                severity: Severity::Medium,
                recommendation: 'Move expensive operations to controllers or services. Use computed properties or view composers for complex transformations',
                code: 'blade-expensive-computation',
            );
        }
    }

    private function checkForeachExpression(Stmt\Foreach_ $node): void
    {
        $expr = $node->expr;

        if (! $expr instanceof Expr\MethodCall || ! $expr->name instanceof Identifier) {
            return;
        }

        $methodName = $expr->name->name;

        if (in_array($methodName, self::COLLECTION_MANIPULATION_METHODS, true)) {
            $this->addIssue(
                line: $node->getStartLine(),
                message: 'Business logic found in Blade directive',
                severity: Severity::Medium,
                recommendation: 'Extract business logic to controllers or services. Use simple conditionals in views for presentation logic only',
                code: 'blade-has-business-logic',
            );
        }
    }

    /**
     * Detect collection manipulation in Blade's compiled @foreach pattern.
     *
     * Blade compiles @foreach($items->filter() as $item) to:
     *   $__currentLoopData = $items->filter();
     *   foreach($__currentLoopData as $item) { ... }
     *
     * The collection method is in the assignment, not the foreach expression.
     */
    private function checkCurrentLoopDataAssignment(Expr\Assign $node): void
    {
        // Check if LHS is $__currentLoopData
        if (! $node->var instanceof Expr\Variable
            || $node->var->name !== '__currentLoopData') {
            return;
        }

        // Check if RHS is a method call with a collection manipulation method
        $rhs = $node->expr;
        if (! $rhs instanceof Expr\MethodCall || ! $rhs->name instanceof Identifier) {
            return;
        }

        $methodName = $rhs->name->name;

        if (in_array($methodName, self::COLLECTION_MANIPULATION_METHODS, true)) {
            $this->addIssue(
                line: $node->getStartLine(),
                message: 'Business logic found in Blade directive',
                severity: Severity::Medium,
                recommendation: 'Extract business logic to controllers or services. Use simple conditionals in views for presentation logic only',
                code: 'blade-has-business-logic',
            );
        }
    }

    /**
     * Detect complex calculations in Blade echo expressions.
     *
     * Blade compiles {{ expr }} to echo e(expr). Flag when the expression
     * contains 2+ arithmetic operators (e.g., {{ ($a * $b) + ($c * $d) }}).
     */
    private function checkEchoCalculation(Stmt\Echo_ $node): void
    {
        foreach ($node->exprs as $expr) {
            // Unwrap e() call: echo e(innerExpr)
            $inner = $expr;
            if ($expr instanceof Expr\FuncCall
                && $expr->name instanceof Name
                && $expr->name->toString() === 'e'
                && count($expr->args) >= 1) {
                $inner = $expr->args[0]->value;
            }

            $arithmeticCount = $this->countArithmeticOperators($inner);
            if ($arithmeticCount >= $this->minArithmeticOperators) {
                $this->addIssue(
                    line: $node->getStartLine(),
                    message: 'Complex calculation found in Blade template',
                    severity: Severity::Low,
                    recommendation: 'Move calculations to controller, view composer, or model accessor. Blade should only display pre-calculated values',
                    code: 'blade-has-calculation',
                );
            }
        }
    }

    /**
     * Recursively count arithmetic BinaryOp nodes in an expression tree.
     */
    private function countArithmeticOperators(Node $node): int
    {
        $count = 0;

        if ($node instanceof Expr\BinaryOp\Plus
            || $node instanceof Expr\BinaryOp\Minus
            || $node instanceof Expr\BinaryOp\Mul
            || $node instanceof Expr\BinaryOp\Div
            || $node instanceof Expr\BinaryOp\Mod) {
            $count = 1;
        }

        foreach ($node->getSubNodeNames() as $name) {
            $subNode = $node->$name;
            if ($subNode instanceof Node) {
                $count += $this->countArithmeticOperators($subNode);
            } elseif (is_array($subNode)) {
                foreach ($subNode as $item) {
                    if ($item instanceof Node) {
                        $count += $this->countArithmeticOperators($item);
                    }
                }
            }
        }

        return $count;
    }

    /**
     * Detect compound assignment operators ($x += $y, $x *= $y, etc.).
     */
    private function checkCompoundAssignment(Expr\AssignOp $node): void
    {
        // Any compound arithmetic assignment is a calculation in Blade
        if ($node instanceof Expr\AssignOp\Plus
            || $node instanceof Expr\AssignOp\Minus
            || $node instanceof Expr\AssignOp\Mul
            || $node instanceof Expr\AssignOp\Div
            || $node instanceof Expr\AssignOp\Mod) {
            $this->addIssue(
                line: $node->getStartLine(),
                message: 'Complex calculation found in Blade template',
                severity: Severity::Low,
                recommendation: 'Move calculations to controller, view composer, or model accessor. Blade should only display pre-calculated values',
                code: 'blade-has-calculation',
            );
        }
    }

    private function getShortClassName(string $fullName): string
    {
        $parts = explode('\\', $fullName);

        return end($parts);
    }

    private function hasDefiniteNonModelSuffix(string $className): bool
    {
        foreach (self::DEFINITE_NON_MODEL_SUFFIXES as $suffix) {
            if (str_ends_with($className, $suffix)) {
                return true;
            }
        }

        return false;
    }

    private function hasAmbiguousSuffix(string $className): bool
    {
        foreach (self::AMBIGUOUS_SUFFIXES as $suffix) {
            if (str_ends_with($className, $suffix)) {
                return true;
            }
        }

        return false;
    }

    private function addDbIssue(int $line): void
    {
        $this->addIssue(
            line: $line,
            message: 'Database query found in Blade template',
            severity: Severity::Critical,
            recommendation: 'Never query the database from Blade templates. Load all required data in the controller and pass it to the view',
            code: 'blade-has-db-query',
        );
    }

    /**
     * @param  array<string, mixed>  $metadata
     */
    private function addIssue(int $line, string $message, Severity $severity, string $recommendation, string $code, array $metadata = []): void
    {
        $this->issues[] = [
            'message' => $message,
            'severity' => $severity,
            'recommendation' => $recommendation,
            'code' => $code,
            'line' => $line,
            'metadata' => $metadata,
        ];
    }
}
