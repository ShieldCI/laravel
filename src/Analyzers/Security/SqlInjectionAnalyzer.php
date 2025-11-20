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
    ];

    private array $userInputSources = [
        '$_GET',
        '$_POST',
        '$_REQUEST',
        '$_COOKIE',
        'request(',
        'Request::input',
        'Request::get',
        'Input::get',
    ];

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'sql-injection',
            name: 'SQL Injection Detector',
            description: 'Detects potential SQL injection vulnerabilities in database queries',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['sql', 'injection', 'database', 'security'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/sql-injection'
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

            // Check for DB::raw() with string concatenation
            $rawCalls = $this->parser->findStaticCalls($ast, 'DB', 'raw');
            foreach ($rawCalls as $call) {
                if ($this->hasStringConcatenation($call) || $this->hasUserInput($call)) {
                    $issues[] = $this->createIssue(
                        message: 'Potential SQL injection: DB::raw() with string concatenation or user input',
                        location: new Location(
                            $this->getRelativePath($file),
                            $call->getLine()
                        ),
                        severity: Severity::Critical,
                        recommendation: 'Use parameter binding instead of string concatenation. Example: DB::raw("SELECT * FROM users WHERE id = ?", [$id])',
                        code: FileParser::getCodeSnippet($file, $call->getLine())
                    );
                }
            }

            // Check for dangerous query methods
            foreach ($this->dangerousMethods as $method) {
                $calls = $this->findMethodCallsWithConcatenation($ast, $method);
                foreach ($calls as $call) {
                    $issues[] = $this->createIssue(
                        message: "Potential SQL injection: {$method}() with string concatenation or user input",
                        location: new Location(
                            $this->getRelativePath($file),
                            $call->getLine()
                        ),
                        severity: Severity::Critical,
                        recommendation: "Use parameter binding: ->{$method}('column = ?', [\$value]) instead of concatenation",
                        code: FileParser::getCodeSnippet($file, $call->getLine())
                    );
                }
            }

            // Check for DB::select/insert/update/delete with concatenation
            $queryMethods = ['select', 'insert', 'update', 'delete'];
            foreach ($queryMethods as $method) {
                $calls = $this->parser->findStaticCalls($ast, 'DB', $method);
                foreach ($calls as $call) {
                    if ($this->hasStringConcatenation($call) || $this->hasUserInput($call)) {
                        $issues[] = $this->createIssue(
                            message: "Potential SQL injection: DB::{$method}() with string concatenation",
                            location: new Location(
                                $this->getRelativePath($file),
                                $call->getLine()
                            ),
                            severity: Severity::Critical,
                            recommendation: 'Use parameter binding with placeholders',
                            code: FileParser::getCodeSnippet($file, $call->getLine())
                        );
                    }
                }
            }
        }

        if (empty($issues)) {
            return $this->passed('No SQL injection vulnerabilities detected');
        }

        return $this->failed(
            sprintf('Found %d potential SQL injection vulnerabilities', count($issues)),
            $issues
        );
    }

    /**
     * Find method calls that have string concatenation in arguments.
     */
    private function findMethodCallsWithConcatenation(array $ast, string $methodName): array
    {
        $results = [];
        $calls = $this->parser->findMethodCalls($ast, $methodName);

        foreach ($calls as $call) {
            if ($this->hasStringConcatenation($call) || $this->hasUserInput($call)) {
                $results[] = $call;
            }
        }

        return $results;
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
     * Convert a node to string representation.
     */
    private function nodeToString(Node $node): string
    {
        // Simple string representation - in production, use a proper printer
        return serialize($node);
    }
}
