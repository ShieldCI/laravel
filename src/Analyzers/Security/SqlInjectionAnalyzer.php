<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PhpParser\Node;
use PhpParser\PrettyPrinter\Standard as PrettyPrinter;
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
    private array $dangerousMethods = [
        'raw',
        'whereRaw',
        'havingRaw',
        'orderByRaw',
        'selectRaw',
        'unprepared',
    ];

    private array $userInputSources = [
        '$_GET',
        '$_POST',
        '$_REQUEST',
        '$_COOKIE',
        'request(',
        'Request::input',
        'Request::get',
        'Request::all',
        'Request::query',
        'Request::post',
        'Request::cookie',
        'Request::header',
        'Request::route',
        'Input::get',
        'Input::all',
        '$request->input',
        '$request->get',
        '$request->all',
        '$request->query',
        '$request->post',
        '$request->cookie',
    ];

    private array $nativeMysqliFunctions = [
        'mysqli_connect', 'mysqli_execute', 'mysqli_stmt_execute', 'mysqli_stmt_close',
        'mysqli_stmt_fetch', 'mysqli_stmt_get_result', 'mysqli_stmt_more_results',
        'mysqli_stmt_next_result', 'mysqli_stmt_prepare', 'mysqli_close', 'mysqli_commit',
        'mysqli_begin_transaction', 'mysqli_init', 'mysqli_insert_id', 'mysqli_prepare',
        'mysqli_query', 'mysqli_real_connect', 'mysqli_real_query', 'mysqli_store_result',
        'mysqli_use_result', 'mysqli_multi_query',
    ];

    private array $nativePostgresFunctions = [
        'pg_connect', 'pg_close', 'pg_affected_rows', 'pg_delete', 'pg_execute',
        'pg_fetch_all', 'pg_fetch_result', 'pg_fetch_row', 'pg_fetch_all_columns',
        'pg_fetch_array', 'pg_fetch_assoc', 'pg_fetch_object', 'pg_flush', 'pg_insert',
        'pg_get_result', 'pg_pconnect', 'pg_prepare', 'pg_query', 'pg_query_params',
        'pg_select', 'pg_send_execute', 'pg_send_prepare', 'pg_send_query',
        'pg_send_query_params',
    ];

    private array $nativePdoClasses = ['PDO', 'mysqli'];

    private ?PrettyPrinter $printer = null;

    public function __construct(
        private ParserInterface $parser,
        private ?ConfigRepository $config = null
    ) {
        $this->printer = new PrettyPrinter;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'sql-injection',
            name: 'SQL Injection Analyzer',
            description: 'Detects potential SQL injection vulnerabilities in database queries',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['sql', 'injection', 'database', 'security'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/sql-injection',
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
            $ast = $this->parser->parseFile($file);
            if (empty($ast)) {
                continue;
            }

            // Check for DB::raw() with string concatenation or variable interpolation
            $rawCalls = $this->parser->findStaticCalls($ast, 'DB', 'raw');
            foreach ($rawCalls as $call) {
                if ($this->isVulnerable($call)) {
                    $issues[] = $this->createSqlInjectionIssue(
                        $file,
                        $call,
                        'DB::raw()',
                        'Use parameter binding instead of string concatenation. Example: DB::raw("SELECT * FROM users WHERE id = ?", [$id])'
                    );
                }
            }

            // Check for DB::unprepared() - explicitly unsafe method
            $unpreparedCalls = $this->parser->findStaticCalls($ast, 'DB', 'unprepared');
            foreach ($unpreparedCalls as $call) {
                $issues[] = $this->createSqlInjectionIssue(
                    $file,
                    $call,
                    'DB::unprepared()',
                    'Avoid DB::unprepared() - use prepared statements with DB::select(), DB::insert(), etc. with parameter binding'
                );
            }

            // Check for dangerous query methods
            foreach ($this->dangerousMethods as $method) {
                if ($method === 'unprepared') {
                    continue; // Already handled above
                }

                // Check static calls (DB::method)
                $staticCalls = $this->parser->findStaticCalls($ast, 'DB', $method);
                foreach ($staticCalls as $call) {
                    if ($this->isVulnerable($call)) {
                        $issues[] = $this->createSqlInjectionIssue(
                            $file,
                            $call,
                            "DB::{$method}()",
                            "Use parameter binding: DB::{$method}('column = ?', [\$value]) instead of concatenation"
                        );
                    }
                }

                // Check method calls (->method)
                $methodCalls = $this->parser->findMethodCalls($ast, $method);
                foreach ($methodCalls as $call) {
                    if ($this->isVulnerable($call)) {
                        $issues[] = $this->createSqlInjectionIssue(
                            $file,
                            $call,
                            "{$method}()",
                            "Use parameter binding: ->{$method}('column = ?', [\$value]) instead of concatenation"
                        );
                    }
                }
            }

            // Check for DB::select/insert/update/delete with concatenation
            $queryMethods = ['select', 'insert', 'update', 'delete'];
            foreach ($queryMethods as $method) {
                $calls = $this->parser->findStaticCalls($ast, 'DB', $method);
                foreach ($calls as $call) {
                    if ($this->isVulnerable($call)) {
                        $issues[] = $this->createSqlInjectionIssue(
                            $file,
                            $call,
                            "DB::{$method}()",
                            'Use parameter binding with placeholders'
                        );
                    }
                }
            }

            // Check for native PHP database functions
            $nativeFunctions = array_merge(
                $this->getNativeMysqliFunctions(),
                $this->getNativePostgresFunctions()
            );

            $functionCalls = $this->parser->findNodes($ast, Node\Expr\FuncCall::class);
            foreach ($functionCalls as $call) {
                if ($call instanceof Node\Expr\FuncCall && $call->name instanceof Node\Name) {
                    $functionName = $call->name->toString();
                    if (in_array($functionName, $nativeFunctions, true)) {
                        $issues[] = $this->createSqlInjectionIssue(
                            $file,
                            $call,
                            "{$functionName}()",
                            'Avoid native PHP database functions. Use Laravel\'s DB facade or Eloquent ORM for better security and parameter binding'
                        );
                    }
                }
            }

            // Check for PDO/mysqli instantiation
            $newExpressions = $this->parser->findNodes($ast, Node\Expr\New_::class);
            foreach ($newExpressions as $node) {
                if ($node instanceof Node\Expr\New_ && $node->class instanceof Node\Name) {
                    $className = $node->class->toString();
                    if (in_array($className, $this->nativePdoClasses, true)) {
                        $issues[] = $this->createSqlInjectionIssue(
                            $file,
                            $node,
                            "new {$className}()",
                            'Avoid direct PDO/mysqli usage. Use Laravel\'s DB facade or Eloquent ORM for better security'
                        );
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
     */
    private function createSqlInjectionIssue(
        string $file,
        Node $node,
        string $method,
        string $recommendation
    ): Issue {
        return $this->createIssueWithSnippet(
            message: "Potential SQL injection: {$method} with string concatenation or user input",
            filePath: $file,
            lineNumber: $node->getLine(),
            severity: Severity::Critical,
            recommendation: $recommendation
        );
    }

    /**
     * Check if a node is vulnerable (has concatenation or user input or interpolation).
     */
    private function isVulnerable(Node $node): bool
    {
        return $this->hasStringConcatenation($node)
            || $this->hasVariableInterpolation($node)
            || $this->hasUserInput($node);
    }

    /**
     * Get native mysqli functions from config or defaults.
     *
     * @return array<string>
     */
    private function getNativeMysqliFunctions(): array
    {
        if ($this->config) {
            $custom = $this->config->get('shieldci.sql_injection.mysqli_functions');
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
            $custom = $this->config->get('shieldci.sql_injection.postgres_functions');
            if (is_array($custom) && ! empty($custom)) {
                return $custom;
            }
        }

        return $this->nativePostgresFunctions;
    }

    /**
     * Check if a node contains string concatenation.
     */
    private function hasStringConcatenation(Node $node): bool
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
     * Check if a node contains variable interpolation in strings.
     */
    private function hasVariableInterpolation(Node $node): bool
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
     * Check if a node contains user input sources.
     */
    private function hasUserInput(Node $node): bool
    {
        $code = $this->nodeToString($node);

        foreach ($this->userInputSources as $source) {
            if (str_contains($code, $source)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Convert a node to string representation using PhpParser printer.
     */
    private function nodeToString(Node $node): string
    {
        if ($this->printer === null) {
            $this->printer = new PrettyPrinter;
        }

        try {
            if ($node instanceof Node\Expr) {
                return $this->printer->prettyPrintExpr($node);
            }

            // For non-expression nodes, use prettyPrint
            return $this->printer->prettyPrint([$node]);
        } catch (\Exception $e) {
            // Fallback to empty string if printing fails
            return '';
        }
    }
}
