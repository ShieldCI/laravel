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
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects App::environment() checks that should use config.
 */
class EnvironmentCheckSmellAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'environment-check-smell',
            name: 'Environment Check Code Smell Detector',
            description: 'Detects environment checks that should use configuration values instead',
            category: Category::BestPractices,
            severity: Severity::Low,
            tags: ['laravel', 'configuration', 'maintainability', 'testing'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/environment-check-smell',
            timeToFix: 15
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $phpFiles = $this->getPhpFiles();

        foreach ($phpFiles as $file) {
            // Skip service providers and exception handlers where env checks are appropriate
            $normalizedPath = str_replace('\\', '/', $file);
            if (str_contains($file, 'ServiceProvider')
                || str_contains($file, 'ExceptionHandler')
                || str_contains($normalizedPath, '/Exceptions/Handler.php')) {
                continue;
            }

            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new EnvironmentCheckVisitor;
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

        if (empty($issues)) {
            return $this->passed('Environment checks are used appropriately');
        }

        return $this->failed(
            sprintf('Found %d environment check(s) that should use config', count($issues)),
            $issues
        );
    }
}

class EnvironmentCheckVisitor extends NodeVisitorAbstract
{
    private array $issues = [];

    public function enterNode(Node $node): ?Node
    {
        // Check for app()->environment()
        if ($node instanceof Node\Expr\MethodCall) {
            if ($node->name instanceof Node\Identifier && $node->name->toString() === 'environment') {
                // Check if it's app()->environment()
                if ($node->var instanceof Node\Expr\FuncCall) {
                    if ($node->var->name instanceof Node\Name && $node->var->name->toString() === 'app') {
                        $this->issues[] = [
                            'message' => 'Using app()->environment() for feature flags or behavior changes',
                            'line' => $node->getLine(),
                            'severity' => Severity::Low,
                            'recommendation' => 'Use config values instead of environment checks for feature flags. Store the decision in config/features.php: config(\'features.feature_name\'). This makes testing easier and behavior more explicit',
                            'code' => null,
                        ];
                    }
                }
            }
        }

        // Check for App::environment()
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->class instanceof Node\Name && $node->class->toString() === 'App') {
                if ($node->name instanceof Node\Identifier && $node->name->toString() === 'environment') {
                    $this->issues[] = [
                        'message' => 'Using App::environment() for feature flags or behavior changes',
                        'line' => $node->getLine(),
                        'severity' => Severity::Low,
                        'recommendation' => 'Use config values instead of environment checks. Environment checks should be for infrastructure concerns only (logging, debugging). Use config(\'features.feature_name\') for behavior changes',
                        'code' => null,
                    ];
                }
            }
        }

        return null;
    }

    public function getIssues(): array
    {
        return $this->issues;
    }
}
