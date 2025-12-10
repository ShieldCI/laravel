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
 * Detects hardcoded storage paths instead of Laravel helpers.
 */
class HardcodedStoragePathsAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'hardcoded-storage-paths',
            name: 'Hardcoded Storage Paths Detector',
            description: 'Finds hardcoded storage/public paths instead of Laravel path helpers',
            category: Category::BestPractices,
            severity: Severity::Medium,
            tags: ['laravel', 'portability', 'paths', 'configuration'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/hardcoded-storage-paths',
            timeToFix: 10
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $phpFiles = $this->getPhpFiles();

        foreach ($phpFiles as $file) {
            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new HardcodedPathsVisitor;
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
            return $this->passed('All paths use Laravel helpers');
        }

        return $this->failed(
            sprintf('Found %d hardcoded path(s)', count($issues)),
            $issues
        );
    }
}

class HardcodedPathsVisitor extends NodeVisitorAbstract
{
    private array $issues = [];

    public function enterNode(Node $node): ?Node
    {
        if ($node instanceof Node\Scalar\String_) {
            $value = $node->value;

            // Check for common hardcoded path patterns
            $patterns = [
                '/\/storage\/app\//i' => 'storage_path(\'app/...\')',
                '/\/storage\/logs\//i' => 'storage_path(\'logs/...\')',
                '/\/storage\/framework\//i' => 'storage_path(\'framework/...\')',
                '/\/public\/uploads\//i' => 'public_path(\'uploads/...\')',
                '/\/public\/images\//i' => 'public_path(\'images/...\')',
                '/\/var\/www\/storage\//i' => 'storage_path(...)',
                '/\/var\/www\/public\//i' => 'public_path(...)',
            ];

            foreach ($patterns as $pattern => $helper) {
                if (preg_match($pattern, $value)) {
                    $this->issues[] = [
                        'message' => sprintf('Hardcoded storage path found: "%s"', substr($value, 0, 50)),
                        'line' => $node->getLine(),
                        'severity' => Severity::Medium,
                        'recommendation' => sprintf('Use Laravel path helper: %s. This ensures portability across environments and enables different storage drivers', $helper),
                        'code' => null,
                    ];
                    break; // Only report once per string
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
