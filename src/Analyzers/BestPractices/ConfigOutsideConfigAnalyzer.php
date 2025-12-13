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
            name: 'Hardcoded Configuration Analyzer',
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
            // Skip config files themselves (normalize path separators for cross-platform compatibility)
            $normalizedPath = str_replace('\\', '/', $file);
            if (str_contains($normalizedPath, '/config/')) {
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

    /** @var int Minimum length for API key detection */
    private const MIN_API_KEY_PATTERN_LENGTH = 20;

    /** @var int Minimum total length for API key detection */
    private const MIN_API_KEY_TOTAL_LENGTH = 30;

    /** @var int Maximum characters to display in URL messages */
    private const URL_DISPLAY_LENGTH = 50;

    /** @var array<string> Documentation domains to exclude from URL detection */
    private const DOCUMENTATION_DOMAINS = [
        'laravel.com',
        'github.com',
        'stackoverflow.com',
        'example.com',
    ];

    public function enterNode(Node $node): ?Node
    {
        if ($node instanceof Node\Scalar\String_) {
            $value = $node->value;

            // Check for hardcoded URLs (including localhost and IP addresses)
            if ($this->isHardcodedUrl($value)) {
                $this->issues[] = [
                    'message' => sprintf('Hardcoded URL: "%s"', mb_substr($value, 0, self::URL_DISPLAY_LENGTH)),
                    'line' => $node->getLine(),
                    'severity' => Severity::Medium,
                    'recommendation' => 'Move URLs to config file (e.g., config/services.php). Use config(\'services.api.url\') instead of hardcoding',
                    'code' => null,
                ];
            }

            // Check for API keys pattern (long alphanumeric strings, excluding known hash formats)
            if ($this->looksLikeApiKey($value)) {
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

    /**
     * Check if a string is a hardcoded URL that should be in config.
     */
    private function isHardcodedUrl(string $value): bool
    {
        // Must start with http:// or https://
        if (! preg_match('/^https?:\/\//', $value)) {
            return false;
        }

        // Exclude documentation URLs
        foreach (self::DOCUMENTATION_DOMAINS as $domain) {
            if (str_contains($value, $domain)) {
                return false;
            }
        }

        // Detect localhost URLs (should be configured)
        if (preg_match('/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?/', $value)) {
            return true;
        }

        // Detect private IP addresses (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
        if (preg_match('/^https?:\/\/(192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+)(:\d+)?/', $value)) {
            return true;
        }

        // Any other http/https URL should be in config
        return true;
    }

    /**
     * Check if a string looks like an API key (excluding common false positives).
     */
    private function looksLikeApiKey(string $value): bool
    {
        $length = strlen($value);

        // Must be long enough
        if ($length <= self::MIN_API_KEY_TOTAL_LENGTH) {
            return false;
        }

        // Check for common API key prefixes (sk_, pk_, etc.)
        if (preg_match('/^(sk|pk|live|test)_[a-zA-Z0-9_-]+$/', $value)) {
            return true;
        }

        // Must be mostly alphanumeric (allow underscores and dashes)
        if (! preg_match('/^[a-zA-Z0-9_-]{'.self::MIN_API_KEY_PATTERN_LENGTH.',}$/', $value)) {
            return false;
        }

        // Exclude MD5 hashes (32 hex characters, no special chars)
        if ($length === 32 && ctype_xdigit($value)) {
            return false;
        }

        // Exclude SHA1 hashes (40 hex characters, no special chars)
        if ($length === 40 && ctype_xdigit($value)) {
            return false;
        }

        // Exclude SHA256 hashes (64 hex characters, no special chars)
        if ($length === 64 && ctype_xdigit($value)) {
            return false;
        }

        // Likely an API key if it's a long alphanumeric string
        return true;
    }

    public function getIssues(): array
    {
        return $this->issues;
    }
}
