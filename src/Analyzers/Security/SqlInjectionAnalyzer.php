<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PhpParser\Node;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;

/**
 * Detects potential SQL injection vulnerabilities.
 *
 * Checks for:
 * - Raw DB::raw() usage with user input
 * - Direct SQL queries with concatenation
 * - whereRaw() with user input
 * - DB::select/insert/update/delete with concatenated strings
 */
class SqlInjectionAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Database methods to check for SQL injection.
     *
     * Configuration:
     * - alwaysFlag: If true, always flag (no vulnerability check needed)
     * - checkStatic: Check static calls like DB::method()
     * - checkInstance: Check instance calls like ->method()
     * - severity: Severity level (Critical for full query control, High for fragments)
     * - recommendation: Custom recommendation message (optional)
     */
    private array $dbMethods = [
        'raw' => [
            'alwaysFlag' => false,
            'checkStatic' => true,
            'checkInstance' => false,
            'severity' => Severity::Critical,  // Full query construction
            'recommendation' => 'Use parameter binding instead of string concatenation. Example: DB::raw("SELECT * FROM users WHERE id = ?", [$id])',
        ],
        'unprepared' => [
            'alwaysFlag' => true,
            'checkStatic' => true,
            'checkInstance' => false,
            'severity' => Severity::Critical,  // Inherently unsafe
            'recommendation' => 'Avoid DB::unprepared() - use prepared statements with DB::select(), DB::insert(), etc. with parameter binding',
        ],
        'whereRaw' => [
            'alwaysFlag' => false,
            'checkStatic' => false,
            'checkInstance' => true,
            'severity' => Severity::High,  // Query fragment only
            'recommendation' => 'Use parameter binding: ->whereRaw(\'column = ?\', [$value]) instead of concatenation',
        ],
        'havingRaw' => [
            'alwaysFlag' => false,
            'checkStatic' => false,
            'checkInstance' => true,
            'severity' => Severity::High,  // Query fragment only
            'recommendation' => 'Use parameter binding: ->havingRaw(\'column = ?\', [$value]) instead of concatenation',
        ],
        'orderByRaw' => [
            'alwaysFlag' => false,
            'checkStatic' => false,
            'checkInstance' => true,
            'severity' => Severity::High,  // Query fragment only
            'recommendation' => 'Use parameter binding: ->orderByRaw(\'column = ?\', [$value]) instead of concatenation',
        ],
        'selectRaw' => [
            'alwaysFlag' => false,
            'checkStatic' => false,
            'checkInstance' => true,
            'severity' => Severity::High,  // Query fragment only
            'recommendation' => 'Use parameter binding: ->selectRaw(\'column = ?\', [$value]) instead of concatenation',
        ],
        'select' => [
            'alwaysFlag' => false,
            'checkStatic' => true,
            'checkInstance' => false,
            'severity' => Severity::Critical,  // Full query construction
            'recommendation' => 'Use parameter binding with placeholders',
        ],
        'insert' => [
            'alwaysFlag' => false,
            'checkStatic' => true,
            'checkInstance' => false,
            'severity' => Severity::Critical,  // Full query construction
            'recommendation' => 'Use parameter binding with placeholders',
        ],
        'update' => [
            'alwaysFlag' => false,
            'checkStatic' => true,
            'checkInstance' => false,
            'severity' => Severity::Critical,  // Full query construction
            'recommendation' => 'Use parameter binding with placeholders',
        ],
        'delete' => [
            'alwaysFlag' => false,
            'checkStatic' => true,
            'checkInstance' => false,
            'severity' => Severity::Critical,  // Full query construction
            'recommendation' => 'Use parameter binding with placeholders',
        ],
    ];

    /**
     * Native MySQLi functions that execute queries (not connection, prepare, or fetch).
     * Only these can have SQL injection vulnerabilities through concatenation.
     */
    private array $nativeMysqliFunctions = [
        'mysqli_query',       // Executes a query (most common)
        'mysqli_real_query',  // Executes a query without buffering
        'mysqli_multi_query', // Executes multiple queries
    ];

    /**
     * Native PostgreSQL functions that execute queries.
     * Only these can have SQL injection vulnerabilities through concatenation.
     */
    private array $nativePostgresFunctions = [
        'pg_query',       // Executes a query
        'pg_send_query',  // Sends async query
    ];

    /**
     * Cache for node vulnerability checks to avoid redundant subtree traversals.
     * Key: spl_object_id($node) . ':' . check_type
     * Value: boolean result
     *
     * @var array<string, bool>
     */
    private array $nodeCheckCache = [];

    public function __construct(
        private ParserInterface $parser,
        private ?ConfigRepository $config = null
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'sql-injection',
            name: 'SQL Injection Analyzer',
            description: 'Detects potential SQL injection vulnerabilities in database queries',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['sql', 'injection', 'database', 'security'],
            timeToFix: 30
        );
    }

    public function shouldRun(): bool
    {
        $files = $this->getPhpFiles();

        return ! empty($files);
    }

    public function getSkipReason(): string
    {
        return 'No PHP files found to analyze';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        foreach ($this->getPhpFiles() as $file) {
            $this->nodeCheckCache = [];

            $ast = $this->parser->parseFile($file);
            if (empty($ast)) {
                continue;
            }

            // Check all configured database methods in a single unified loop
            foreach ($this->dbMethods as $method => $config) {
                // Check static calls (DB::method)
                if ($config['checkStatic']) {
                    $staticCalls = $this->parser->findStaticCalls($ast, 'DB', $method);
                    foreach ($staticCalls as $call) {
                        // Always flag if configured, otherwise check for vulnerabilities
                        if ($config['alwaysFlag']) {
                            $issues[] = $this->createSqlInjectionIssue(
                                $file,
                                $call,
                                "DB::{$method}()",
                                $config['recommendation'],
                                $config['severity']
                            );
                        } else {
                            $result = $this->isVulnerable($call);
                            if ($result['vulnerable']) {
                                $issues[] = $this->createSqlInjectionIssue(
                                    $file,
                                    $call,
                                    "DB::{$method}()",
                                    $config['recommendation'],
                                    $config['severity'],
                                    $result['node']
                                );
                            }
                        }
                    }
                }

                // Check instance calls (->method)
                if ($config['checkInstance']) {
                    $methodCalls = $this->parser->findMethodCalls($ast, $method);
                    foreach ($methodCalls as $call) {
                        // Always flag if configured, otherwise check for vulnerabilities
                        if ($config['alwaysFlag']) {
                            $issues[] = $this->createSqlInjectionIssue(
                                $file,
                                $call,
                                "{$method}()",
                                $config['recommendation'],
                                $config['severity']
                            );
                        } else {
                            $result = $this->isVulnerable($call);
                            if ($result['vulnerable']) {
                                $issues[] = $this->createSqlInjectionIssue(
                                    $file,
                                    $call,
                                    "{$method}()",
                                    $config['recommendation'],
                                    $config['severity'],
                                    $result['node']
                                );
                            }
                        }
                    }
                }
            }

            // Check for native PHP database query functions (only actual query execution)
            $nativeFunctions = array_merge(
                $this->getNativeMysqliFunctions(),
                $this->getNativePostgresFunctions()
            );

            $functionCalls = $this->parser->findNodes($ast, Node\Expr\FuncCall::class);
            foreach ($functionCalls as $call) {
                if ($call instanceof Node\Expr\FuncCall && $call->name instanceof Node\Name) {
                    $functionName = $call->name->toString();
                    if (in_array($functionName, $nativeFunctions, true)) {
                        // Only flag if the query has concatenation/interpolation (like Laravel methods)
                        $result = $this->isVulnerable($call);
                        if ($result['vulnerable']) {
                            $issues[] = $this->createSqlInjectionIssue(
                                $file,
                                $call,
                                "{$functionName}()",
                                'Use prepared statements with parameter binding instead of string concatenation. Better yet, use Laravel\'s DB facade or Eloquent ORM',
                                Severity::High,  // Native functions less common in Laravel, rated High
                                $result['node']
                            );
                        }
                    }
                }
            }
        }

        if (empty($issues)) {
            return $this->passed('No SQL injection vulnerabilities detected');
        }

        return $this->resultBySeverity(
            sprintf('Found %d potential SQL injection vulnerabilities', count($issues)),
            $issues
        );
    }

    /**
     * Create an SQL injection issue with standardized format.
     *
     * @param  Node|null  $vulnerableNode  The specific node where the vulnerability occurs (concatenation, interpolation, etc.)
     *                                     If provided, uses this node's line number for precise reporting.
     *                                     If null, falls back to the call node's line number.
     */
    private function createSqlInjectionIssue(
        string $file,
        Node $node,
        string $method,
        string $recommendation,
        Severity $severity = Severity::Critical,
        ?Node $vulnerableNode = null
    ): Issue {
        // Use the vulnerable node's line if available for precise reporting
        // Otherwise fall back to the call node's line
        $lineNumber = $vulnerableNode?->getLine() ?? $node->getLine();

        return $this->createIssueWithSnippet(
            message: "Potential SQL injection: {$method} with string concatenation or user input",
            filePath: $file,
            lineNumber: $lineNumber,
            severity: $severity,
            recommendation: $recommendation
        );
    }

    /**
     * Check if a node is vulnerable and return the vulnerable node for precise line reporting.
     *
     * IMPORTANT: For methods that support parameter binding (e.g., DB::select, whereRaw),
     * we only check the SQL query argument (first arg), NOT the bindings array (second arg).
     * User input in bindings is safe.
     *
     * @return array{vulnerable: bool, node: ?Node} Returns vulnerability status and the specific vulnerable node
     */
    private function isVulnerable(Node $node): array
    {
        // For method calls and static calls, check if they support parameter binding
        if ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall) {
            return $this->isVulnerableCall($node);
        }

        // For function calls (mysqli_query, pg_query, etc.), check only the SQL argument
        if ($node instanceof Node\Expr\FuncCall) {
            return $this->isVulnerableFuncCall($node);
        }

        // For other nodes, use the basic checks
        $vulnerableNode = $this->findVulnerableNode($node);

        return [
            'vulnerable' => $vulnerableNode !== null,
            'node' => $vulnerableNode,
        ];
    }

    /**
     * Check if a method/static call is vulnerable and return the vulnerable node.
     *
     * For methods that support parameter binding, only flag when SQL is constructed
     * unsafely (concatenation/interpolation) or when bindings are missing.
     *
     * Strategy:
     * - With bindings (2+ args): Only flag concatenation/interpolation in SQL string
     * - Without bindings (1 arg): Flag concatenation/interpolation/user input
     *
     * @return array{vulnerable: bool, node: ?Node}
     */
    private function isVulnerableCall(Node\Expr\MethodCall|Node\Expr\StaticCall $call): array
    {
        // Get the first argument (SQL query)
        if (empty($call->args)) {
            return ['vulnerable' => false, 'node' => null];
        }

        $firstArg = $call->args[0]->value;

        // Always flag concatenation or interpolation in SQL - these are construction issues
        $vulnerableNode = $this->findVulnerableNode($firstArg);
        if ($vulnerableNode !== null) {
            return ['vulnerable' => true, 'node' => $vulnerableNode];
        }

        // If bindings are present (2+ arguments), trust the parameter binding
        // Don't flag user input in bindings - that's the correct, safe pattern
        if (count($call->args) >= 2) {
            return ['vulnerable' => false, 'node' => null];
        }

        // Single argument without bindings: check for user input
        // Example: DB::select($userControlledVar) with no bindings is dangerous
        $userInputNode = $this->findUserInputNode($firstArg);
        if ($userInputNode !== null) {
            return ['vulnerable' => true, 'node' => $userInputNode];
        }

        return ['vulnerable' => false, 'node' => null];
    }

    /**
     * Check if a native function call is vulnerable and return the vulnerable node.
     *
     * For native database functions (mysqli_query, pg_query, etc.), the SQL query
     * is typically the second argument (after the connection). We only check that
     * specific argument for interpolation/concatenation.
     *
     * Examples:
     * - mysqli_query($conn, $query) - SQL is arg[1]
     * - pg_query($conn, $query) - SQL is arg[1]
     *
     * @return array{vulnerable: bool, node: ?Node}
     */
    private function isVulnerableFuncCall(Node\Expr\FuncCall $call): array
    {
        // For native mysqli/pg functions, SQL is typically the second argument (index 1)
        // mysqli_query($conn, $query)
        // pg_query($conn, $query)
        if (count($call->args) < 2) {
            return ['vulnerable' => false, 'node' => null];
        }

        $sqlArg = $call->args[1]->value;

        // Check for vulnerable patterns and return the specific node
        $vulnerableNode = $this->findVulnerableNode($sqlArg);
        if ($vulnerableNode !== null) {
            return ['vulnerable' => true, 'node' => $vulnerableNode];
        }

        $userInputNode = $this->findUserInputNode($sqlArg);
        if ($userInputNode !== null) {
            return ['vulnerable' => true, 'node' => $userInputNode];
        }

        return ['vulnerable' => false, 'node' => null];
    }

    /**
     * Get native mysqli functions from config or defaults.
     *
     * @return array<string>
     */
    private function getNativeMysqliFunctions(): array
    {
        if ($this->config) {
            $custom = $this->config->get('shieldci.analyzers.security.sql-injection.mysqli_functions');
            if (is_array($custom) && ! empty($custom)) {
                return $custom;
            }
        }

        return $this->nativeMysqliFunctions;
    }

    /**
     * Get native postgres functions from config or defaults.
     *
     * @return array<string>
     */
    private function getNativePostgresFunctions(): array
    {
        if ($this->config) {
            $custom = $this->config->get('shieldci.analyzers.security.sql-injection.postgres_functions');
            if (is_array($custom) && ! empty($custom)) {
                return $custom;
            }
        }

        return $this->nativePostgresFunctions;
    }

    /**
     * Find the vulnerable node (concatenation, interpolation, or user input).
     *
     * Returns the specific node where the vulnerability occurs for precise line reporting.
     *
     * @return Node|null The vulnerable node, or null if no vulnerability found
     */
    private function findVulnerableNode(Node $node): ?Node
    {
        // Check for concatenation
        $concatNode = $this->findConcatenationNode($node);
        if ($concatNode !== null) {
            return $concatNode;
        }

        // Check for interpolation
        $interpolationNode = $this->findInterpolationNode($node);
        if ($interpolationNode !== null) {
            return $interpolationNode;
        }

        return null;
    }

    /**
     * Find the user input node.
     *
     * Returns the specific node where user input is accessed.
     *
     * @return Node|null The user input node, or null if no user input found
     */
    private function findUserInputNode(Node $node): ?Node
    {
        return $this->findUserInputNodeRecursive($node);
    }

    /**
     * Find concatenation node in the tree.
     */
    private function findConcatenationNode(Node $node): ?Node
    {
        // Check if this node is a concatenation
        if ($node instanceof Node\Expr\BinaryOp\Concat) {
            return $node;
        }

        // Recursively check child nodes
        foreach ($node->getSubNodeNames() as $name) {
            $subNode = $node->$name;
            if ($subNode instanceof Node) {
                $found = $this->findConcatenationNode($subNode);
                if ($found !== null) {
                    return $found;
                }
            } elseif (is_array($subNode)) {
                foreach ($subNode as $item) {
                    if ($item instanceof Node) {
                        $found = $this->findConcatenationNode($item);
                        if ($found !== null) {
                            return $found;
                        }
                    }
                }
            }
        }

        return null;
    }

    /**
     * Find interpolation node in the tree.
     */
    private function findInterpolationNode(Node $node): ?Node
    {
        // Check for Encapsed strings (strings with variables like "value $var")
        if ($node instanceof Node\Scalar\Encapsed) {
            return $node;
        }

        // Recursively check child nodes
        foreach ($node->getSubNodeNames() as $name) {
            $subNode = $node->$name;
            if ($subNode instanceof Node) {
                $found = $this->findInterpolationNode($subNode);
                if ($found !== null) {
                    return $found;
                }
            } elseif (is_array($subNode)) {
                foreach ($subNode as $item) {
                    if ($item instanceof Node) {
                        $found = $this->findInterpolationNode($item);
                        if ($found !== null) {
                            return $found;
                        }
                    }
                }
            }
        }

        return null;
    }

    /**
     * Find user input node in the tree.
     */
    private function findUserInputNodeRecursive(Node $node): ?Node
    {
        // Check for superglobals ($_GET, $_POST, $_REQUEST, $_COOKIE)
        if ($node instanceof Node\Expr\ArrayDimFetch) {
            if ($node->var instanceof Node\Expr\Variable && is_string($node->var->name)) {
                $varName = '$'.$node->var->name;
                if (in_array($varName, ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE'], true)) {
                    return $node;
                }
            }
        }

        // Check for request() helper function
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
            if ($node->name->toString() === 'request') {
                return $node;
            }
        }

        // Check for Request facade static calls
        if ($node instanceof Node\Expr\StaticCall && $node->class instanceof Node\Name) {
            $className = $node->class->toString();
            if ($className === 'Request' || $className === 'Input') {
                if ($node->name instanceof Node\Identifier) {
                    $methodName = $node->name->toString();
                    $requestMethods = ['input', 'get', 'all', 'query', 'post', 'cookie', 'header', 'route'];
                    if (in_array($methodName, $requestMethods, true)) {
                        return $node;
                    }
                }
            }
        }

        // Check for $request->input(), $request->get(), etc.
        if ($node instanceof Node\Expr\MethodCall) {
            if ($node->var instanceof Node\Expr\Variable && $node->var->name === 'request') {
                if ($node->name instanceof Node\Identifier) {
                    $methodName = $node->name->toString();
                    $requestMethods = ['input', 'get', 'all', 'query', 'post', 'cookie', 'header', 'route'];
                    if (in_array($methodName, $requestMethods, true)) {
                        return $node;
                    }
                }
            }
        }

        // Recursively check child nodes
        foreach ($node->getSubNodeNames() as $name) {
            $subNode = $node->$name;
            if ($subNode instanceof Node) {
                $found = $this->findUserInputNodeRecursive($subNode);
                if ($found !== null) {
                    return $found;
                }
            } elseif (is_array($subNode)) {
                foreach ($subNode as $item) {
                    if ($item instanceof Node) {
                        $found = $this->findUserInputNodeRecursive($item);
                        if ($found !== null) {
                            return $found;
                        }
                    }
                }
            }
        }

        return null;
    }

    /**
     * Check if a node contains string concatenation (cached wrapper).
     */
    private function hasStringConcatenation(Node $node): bool
    {
        $cacheKey = spl_object_id($node).':concat';

        if (array_key_exists($cacheKey, $this->nodeCheckCache)) {
            return $this->nodeCheckCache[$cacheKey];
        }

        $result = $this->checkStringConcatenation($node);
        $this->nodeCheckCache[$cacheKey] = $result;

        return $result;
    }

    /**
     * Internal method to check if a node contains string concatenation.
     */
    private function checkStringConcatenation(Node $node): bool
    {
        // Check if the node or its children contain string concatenation
        if ($node instanceof Node\Expr\BinaryOp\Concat) {
            return true;
        }

        foreach ($node->getSubNodeNames() as $name) {
            $subNode = $node->$name;
            if ($subNode instanceof Node) {
                if ($this->hasStringConcatenation($subNode)) {
                    return true;
                }
            } elseif (is_array($subNode)) {
                foreach ($subNode as $item) {
                    if ($item instanceof Node && $this->hasStringConcatenation($item)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Check if a node contains variable interpolation in strings (cached wrapper).
     */
    private function hasVariableInterpolation(Node $node): bool
    {
        $cacheKey = spl_object_id($node).':interpolation';

        if (array_key_exists($cacheKey, $this->nodeCheckCache)) {
            return $this->nodeCheckCache[$cacheKey];
        }

        $result = $this->checkVariableInterpolation($node);
        $this->nodeCheckCache[$cacheKey] = $result;

        return $result;
    }

    /**
     * Internal method to check if a node contains variable interpolation in strings.
     */
    private function checkVariableInterpolation(Node $node): bool
    {
        // Check for Encapsed strings (strings with variables like "value $var")
        if ($node instanceof Node\Scalar\Encapsed) {
            return true;
        }

        // Recursively check child nodes
        foreach ($node->getSubNodeNames() as $name) {
            $subNode = $node->$name;
            if ($subNode instanceof Node) {
                if ($this->hasVariableInterpolation($subNode)) {
                    return true;
                }
            } elseif (is_array($subNode)) {
                foreach ($subNode as $item) {
                    if ($item instanceof Node && $this->hasVariableInterpolation($item)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Check if a node contains user input sources using AST structure (cached wrapper).
     *
     * This method recursively checks the AST for user input patterns without
     * converting to string, avoiding false positives from bindings arrays.
     */
    private function hasUserInputInNode(Node $node): bool
    {
        $cacheKey = spl_object_id($node).':userinput';

        if (array_key_exists($cacheKey, $this->nodeCheckCache)) {
            return $this->nodeCheckCache[$cacheKey];
        }

        $result = $this->checkUserInputInNode($node);
        $this->nodeCheckCache[$cacheKey] = $result;

        return $result;
    }

    /**
     * Internal method to check if a node contains user input sources using AST structure.
     */
    private function checkUserInputInNode(Node $node): bool
    {
        // Check for superglobals ($_GET, $_POST, $_REQUEST, $_COOKIE)
        if ($node instanceof Node\Expr\ArrayDimFetch) {
            if ($node->var instanceof Node\Expr\Variable && is_string($node->var->name)) {
                $varName = '$'.$node->var->name;
                if (in_array($varName, ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE'], true)) {
                    return true;
                }
            }
        }

        // Check for request() helper function
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
            if ($node->name->toString() === 'request') {
                return true;
            }
        }

        // Check for Request facade static calls (Request::input, Request::get, etc.)
        if ($node instanceof Node\Expr\StaticCall && $node->class instanceof Node\Name) {
            $className = $node->class->toString();
            if ($className === 'Request' || $className === 'Input') {
                if ($node->name instanceof Node\Identifier) {
                    $methodName = $node->name->toString();
                    $requestMethods = ['input', 'get', 'all', 'query', 'post', 'cookie', 'header', 'route'];
                    if (in_array($methodName, $requestMethods, true)) {
                        return true;
                    }
                }
            }
        }

        // Check for $request->input(), $request->get(), etc.
        if ($node instanceof Node\Expr\MethodCall) {
            if ($node->var instanceof Node\Expr\Variable && $node->var->name === 'request') {
                if ($node->name instanceof Node\Identifier) {
                    $methodName = $node->name->toString();
                    $requestMethods = ['input', 'get', 'all', 'query', 'post', 'cookie', 'header', 'route'];
                    if (in_array($methodName, $requestMethods, true)) {
                        return true;
                    }
                }
            }
        }

        // Recursively check child nodes
        foreach ($node->getSubNodeNames() as $name) {
            $subNode = $node->$name;
            if ($subNode instanceof Node) {
                if ($this->hasUserInputInNode($subNode)) {
                    return true;
                }
            } elseif (is_array($subNode)) {
                foreach ($subNode as $item) {
                    if ($item instanceof Node && $this->hasUserInputInNode($item)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}
