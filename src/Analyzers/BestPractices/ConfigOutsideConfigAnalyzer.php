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
 * Detects configuration values hardcoded in code.
 */
class ConfigOutsideConfigAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'config-outside-config',
            name: 'Hardcoded Configuration Detector',
            description: 'Detects configuration values hardcoded in code instead of config files',
            category: Category::BestPractices,
            severity: Severity::Medium,
            tags: ['laravel', 'configuration', 'maintainability', 'testability'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/config-outside-config',
            timeToFix: 10
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $phpFiles = $this->getPhpFiles();

        foreach ($phpFiles as $file) {
            // Skip config files themselves
            if (str_contains($file, '/config/')) {
                continue;
            }

            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new ConfigHardcodeVisitor;
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
            return $this->passed('Configuration is properly externalized');
        }

        return $this->failed(
            sprintf('Found %d hardcoded configuration value(s)', count($issues)),
            $issues
        );
    }
}

class ConfigHardcodeVisitor extends NodeVisitorAbstract
{
    private array $issues = [];

    public function enterNode(Node $node): ?Node
    {
        if ($node instanceof Node\Scalar\String_) {
            $value = $node->value;

            // Check for hardcoded URLs
            if (preg_match('/^https?:\/\//', $value) && ! str_contains($value, 'example.com')) {
                // Exclude common documentation URLs
                if (! str_contains($value, 'laravel.com') &&
                    ! str_contains($value, 'github.com') &&
                    ! str_contains($value, 'stackoverflow.com')) {
                    $this->issues[] = [
                        'message' => sprintf('Hardcoded URL: "%s"', substr($value, 0, 50)),
                        'line' => $node->getLine(),
                        'severity' => Severity::Medium,
                        'recommendation' => 'Move URLs to config file (e.g., config/services.php). Use config(\'services.api.url\') instead of hardcoding',
                        'code' => null,
                    ];
                }
            }

            // Check for API keys pattern (long alphanumeric strings)
            if (preg_match('/^[a-zA-Z0-9]{20,}$/', $value) && strlen($value) > 30) {
                $this->issues[] = [
                    'message' => 'Possible hardcoded API key or secret detected',
                    'line' => $node->getLine(),
                    'severity' => Severity::High,
                    'recommendation' => 'NEVER hardcode API keys in source code. Use environment variables via config files: config(\'services.api.key\')',
                    'code' => null,
                ];
            }
        }

        return null;
    }

    public function getIssues(): array
    {
        return $this->issues;
    }
}
