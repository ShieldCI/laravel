<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\Error as PhpParserError;
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
    /** @var array<string> Paths to exclude from analysis */
    private const EXCLUDE_PATHS = [
        '/config/',
        '/tests/',
        '/Tests/',
        '/database/seeders/',
        '/database/factories/',
        '/vendor/',
    ];

    /** @var array<string> User-configured excluded domains */
    private array $excludedDomains = [];

    public function __construct(
        private ParserInterface $parser,
        private Config $config
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
        $this->loadConfiguration();

        $issues = [];
        $phpFiles = $this->getPhpFiles();

        foreach ($phpFiles as $file) {
            // Skip excluded directories (normalize path separators for cross-platform compatibility)
            if ($this->shouldSkipFile($file)) {
                continue;
            }

            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new ConfigHardcodeVisitor($this->excludedDomains);
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
            } catch (PhpParserError $e) {
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

    /**
     * Check if a file should be skipped based on its path.
     */
    private function shouldSkipFile(string $file): bool
    {
        $normalizedPath = str_replace('\\', '/', $file);

        foreach (self::EXCLUDE_PATHS as $excludePath) {
            if (str_contains($normalizedPath, $excludePath)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Normalize a domain string for consistent matching.
     */
    private function normalizeDomain(string $domain): string
    {
        $domain = trim($domain);

        // Extract host if user provided a full URL
        if (preg_match('/^https?:\/\//', $domain)) {
            $host = parse_url($domain, PHP_URL_HOST);
            $domain = $host !== null && $host !== false ? $host : $domain;
        }

        return strtolower($domain);
    }

    /**
     * Load configuration for excluded domains.
     */
    private function loadConfiguration(): void
    {
        $analyzerConfig = $this->config->get('shieldci.analyzers.best-practices.config-outside-config', []);
        $analyzerConfig = is_array($analyzerConfig) ? $analyzerConfig : [];

        $userExcludedDomains = $analyzerConfig['excluded_domains'] ?? [];
        $userExcludedDomains = is_array($userExcludedDomains) ? $userExcludedDomains : [];

        // Normalize and merge domains
        $allDomains = array_merge(
            ConfigHardcodeVisitor::DEFAULT_EXCLUDED_DOMAINS,
            $userExcludedDomains
        );

        // Normalize (trim, lowercase, extract host from URLs) and de-duplicate
        $this->excludedDomains = array_values(array_unique(
            array_filter(array_map([$this, 'normalizeDomain'], $allDomains))
        ));
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

    /** @var array<string> Default domains to exclude from URL detection */
    public const DEFAULT_EXCLUDED_DOMAINS = [
        // Documentation sites
        'laravel.com',
        'github.com',
        'stackoverflow.com',
        'example.com',
        'php.net',
        'packagist.org',
        'readthedocs.io',
        'docs.microsoft.com',
        'developer.mozilla.org',
        'wikipedia.org',

        // Schema/namespace URLs (identifiers, not fetched)
        'w3.org',
        'schema.org',
        'json-schema.org',
        'swagger.io',
        'openapis.org',
        'xmlns.com',
        'purl.org',

        // CDN/asset URLs (typically static, version-pinned)
        'fonts.googleapis.com',
        'fonts.gstatic.com',
        'cdnjs.cloudflare.com',
        'jsdelivr.net',
        'unpkg.com',
        'bootstrapcdn.com',

        // Placeholder/testing services
        'placehold.co',
        'placeholder.com',
        'placekitten.com',
        'gravatar.com',
        'via.placeholder.com',
        'picsum.photos',
    ];

    /** @param array<string> $excludedDomains Domains to exclude from URL detection */
    public function __construct(
        private array $excludedDomains = []
    ) {}

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

        // Exclude allowed domains (documentation, CDNs, schemas, placeholders, and user-configured)
        // Parse the URL host to avoid substring collisions (e.g., "w3.org" matching "notw3.org.evil.com")
        $host = parse_url($value, PHP_URL_HOST);
        if (! is_string($host) || $host === '') {
            return false;
        }
        $host = strtolower($host);

        foreach ($this->excludedDomains as $domain) {
            $domain = strtolower(trim($domain));

            // Exact match or subdomain match (host ends with ".domain")
            if ($host === $domain || str_ends_with($host, '.'.$domain)) {
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

    /** @var array<string> Common CSS/UI keywords that indicate non-secrets */
    private const CSS_KEYWORDS = [
        'container', 'wrapper', 'button', 'input', 'flex', 'grid', 'layout',
        'content', 'header', 'footer', 'sidebar', 'modal', 'card', 'form',
        'table', 'list', 'item', 'row', 'col', 'nav', 'menu', 'text', 'icon',
        'image', 'link', 'title', 'label', 'field', 'section', 'panel', 'view',
    ];

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

        // Check for common API key prefixes - these are definite API keys
        if (preg_match('/^(sk|pk|live|test|key|api|secret|token|bearer|auth)_[a-zA-Z0-9_-]+$/', $value)) {
            return true;
        }

        // Must be mostly alphanumeric (allow underscores and dashes)
        if (! preg_match('/^[a-zA-Z0-9_-]{'.self::MIN_API_KEY_PATTERN_LENGTH.',}$/', $value)) {
            return false;
        }

        // Exclude snake_case identifiers (method names, constants, etc.)
        // Pattern: lowercase words separated by underscores
        if (preg_match('/^[a-z][a-z0-9]*(_[a-z][a-z0-9]*){2,}$/', $value)) {
            return false;
        }

        // Exclude SCREAMING_SNAKE_CASE constants
        if (preg_match('/^[A-Z][A-Z0-9]*(_[A-Z][A-Z0-9]*){2,}$/', $value)) {
            return false;
        }

        // Exclude camelCase identifiers (require lowercase after each capital)
        if (preg_match('/^[a-z][a-z0-9]*([A-Z][a-z0-9]+){2,}$/', $value)) {
            return false;
        }

        // Exclude CSS class combinations (only check if contains dashes, which are typical in CSS)
        if (str_contains($value, '-')) {
            $lowerValue = strtolower($value);
            foreach (self::CSS_KEYWORDS as $keyword) {
                if (str_contains($lowerValue, $keyword)) {
                    return false;
                }
            }
        }

        // Exclude known hash formats
        if ($this->isKnownHashFormat($value, $length)) {
            return false;
        }

        // For remaining strings, require both letters AND digits (entropy indicator)
        // Pure letter or pure digit strings are more likely to be identifiers
        $hasLetter = preg_match('/[a-zA-Z]/', $value);
        $hasDigit = preg_match('/\d/', $value);

        if (! $hasLetter || ! $hasDigit) {
            return false;
        }

        // Likely an API key if it passes all filters
        return true;
    }

    /**
     * Check if a string matches known hash formats.
     */
    private function isKnownHashFormat(string $value, int $length): bool
    {
        // MD5 hashes (32 hex characters)
        if ($length === 32 && ctype_xdigit($value)) {
            return true;
        }

        // SHA1 hashes (40 hex characters)
        if ($length === 40 && ctype_xdigit($value)) {
            return true;
        }

        // SHA256 hashes (64 hex characters)
        if ($length === 64 && ctype_xdigit($value)) {
            return true;
        }

        // SHA512 hashes (128 hex characters)
        if ($length === 128 && ctype_xdigit($value)) {
            return true;
        }

        return false;
    }

    public function getIssues(): array
    {
        return $this->issues;
    }
}
