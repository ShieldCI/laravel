<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

/**
 * Detects hardcoded storage paths instead of Laravel helpers.
 */
class HardcodedStoragePathsAnalyzer extends AbstractFileAnalyzer
{
    /** @var array<int, string> */
    private array $allowedPaths;

    /** @var array<string, string> */
    private array $patterns;

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'hardcoded-storage-paths',
            name: 'Hardcoded Storage Paths Analyzer',
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
        // Load configuration
        $analyzerConfig = $this->config->get('shieldci.analyzers.best_practices.hardcoded-storage-paths', []);
        $analyzerConfig = is_array($analyzerConfig) ? $analyzerConfig : [];

        $this->allowedPaths = $analyzerConfig['allowed_paths'] ?? [];
        $additionalPatterns = $analyzerConfig['additional_patterns'] ?? [];

        // Default patterns - match absolute and relative hardcoded paths
        // Patterns are ordered from most specific to least specific
        $this->patterns = [
            // Absolute Unix paths (most likely to be hardcoded)
            // Match /var/www/storage/, /var/www/html/storage/, etc.
            '/\/var\/www\/.*storage/i' => 'storage_path(...)',
            '/\/var\/www\/.*public/i' => 'public_path(...)',
            '/\/var\/www\/.*app\//i' => 'app_path(...)',
            '/\/var\/www\/.*resources/i' => 'resource_path(...)',
            '/\/var\/www\/.*database/i' => 'database_path(...)',
            '/\/var\/www\/.*config/i' => 'config_path(...)',

            // Windows absolute paths
            '/[A-Z]:\\\\storage\\\\app\\\\/i' => 'storage_path(\'app/...\')',
            '/[A-Z]:\\\\storage\\\\logs\\\\/i' => 'storage_path(\'logs/...\')',
            '/[A-Z]:\\\\storage\\\\framework\\\\/i' => 'storage_path(\'framework/...\')',
            '/[A-Z]:\\\\storage\\\\/i' => 'storage_path(...)',
            '/[A-Z]:\\\\public\\\\uploads\\\\/i' => 'public_path(\'uploads/...\')',
            '/[A-Z]:\\\\public\\\\images\\\\/i' => 'public_path(\'images/...\')',
            '/[A-Z]:\\\\public\\\\/i' => 'public_path(...)',
            '/[A-Z]:\\\\app\\\\/i' => 'app_path(...)',
            '/[A-Z]:\\\\resources\\\\/i' => 'resource_path(...)',
            '/[A-Z]:\\\\database\\\\/i' => 'database_path(...)',
            '/[A-Z]:\\\\config\\\\/i' => 'config_path(...)',

            // Relative paths with ../ or ./
            '/\.\.\/storage\//i' => 'storage_path(...)',
            '/\.\.\/public\//i' => 'public_path(...)',
            '/\.\.\/app\//i' => 'app_path(...)',
            '/\.\.\/resources\//i' => 'resource_path(...)',
            '/\.\.\/database\//i' => 'database_path(...)',
            '/\.\.\/config\//i' => 'config_path(...)',
            '/\.\/storage\//i' => 'storage_path(...)',
            '/\.\/public\//i' => 'public_path(...)',
            '/\.\/app\//i' => 'app_path(...)',
            '/\.\/resources\//i' => 'resource_path(...)',
            '/\.\/database\//i' => 'database_path(...)',
            '/\.\/config\//i' => 'config_path(...)',

            // Leading slash paths (absolute from root) - specific subdirectories
            '/^\/storage\/app\//i' => 'storage_path(\'app/...\')',
            '/^\/storage\/logs\//i' => 'storage_path(\'logs/...\')',
            '/^\/storage\/framework\//i' => 'storage_path(\'framework/...\')',
            '/^\/storage\//i' => 'storage_path(...)',
            '/^\/public\/uploads\//i' => 'public_path(\'uploads/...\')',
            '/^\/public\/images\//i' => 'public_path(\'images/...\')',
            '/^\/public\//i' => 'public_path(...)',
            '/^\/app\//i' => 'app_path(...)',
            '/^\/resources\//i' => 'resource_path(...)',
            '/^\/database\//i' => 'database_path(...)',
            '/^\/config\//i' => 'config_path(...)',
        ];

        // Merge with additional patterns from config
        $this->patterns = array_merge($this->patterns, $additionalPatterns);

        $issues = [];
        $phpFiles = $this->getPhpFiles();

        foreach ($phpFiles as $file) {
            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new HardcodedPathsVisitor($this->patterns, $this->allowedPaths);
                $traverser = new NodeTraverser;
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getIssues() as $issue) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: $issue['message'],
                        filePath: $file,
                        lineNumber: $issue['line'],
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
    /** @var array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}> */
    private array $issues = [];

    /**
     * @param  array<string, string>  $patterns
     * @param  array<int, string>  $allowedPaths
     */
    public function __construct(
        private array $patterns,
        private array $allowedPaths
    ) {}

    public function enterNode(Node $node): ?Node
    {
        // Handle regular strings
        if ($node instanceof Node\Scalar\String_) {
            $this->checkPath($node->value, $node->getLine());
        }

        // Handle heredoc/nowdoc strings
        if ($node instanceof Node\Scalar\Encapsed) {
            $fullString = '';
            foreach ($node->parts as $part) {
                if ($part instanceof Node\Scalar\EncapsedStringPart) {
                    $fullString .= $part->value;
                }
            }
            if ($fullString !== '') {
                $this->checkPath($fullString, $node->getLine());
            }
        }

        return null;
    }

    /**
     * Check if a string value contains a hardcoded path.
     */
    private function checkPath(string $value, int $line): void
    {
        // Skip URLs (false positives)
        if (preg_match('/^https?:\/\//i', $value)) {
            return;
        }

        // Skip if in allowed paths list
        foreach ($this->allowedPaths as $allowedPath) {
            if (str_contains($value, $allowedPath)) {
                return;
            }
        }

        // Check for hardcoded path patterns
        foreach ($this->patterns as $pattern => $helper) {
            if (preg_match($pattern, $value)) {
                $this->issues[] = [
                    'message' => sprintf('Hardcoded storage path found: "%s"', substr($value, 0, 50)),
                    'line' => $line,
                    'severity' => Severity::Medium,
                    'recommendation' => sprintf('Use Laravel path helper: %s. This ensures portability across environments and enables different storage drivers', $helper),
                    'code' => null,
                ];
                break; // Only report once per string
            }
        }
    }

    /**
     * @return array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
