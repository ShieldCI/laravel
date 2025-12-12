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
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects overriding standard Laravel framework classes that should use extension points instead.
 */
class FrameworkOverrideAnalyzer extends AbstractFileAnalyzer
{
    // Classes that should NEVER be extended (High severity)
    private const NEVER_EXTEND = [
        // Core Foundation
        'Illuminate\\Foundation\\Application',
        'Illuminate\\Foundation\\Http\\Kernel',
        'Illuminate\\Foundation\\Console\\Kernel',

        // HTTP Layer
        'Illuminate\\Http\\Request',
        'Illuminate\\Http\\Response',
        'Illuminate\\Routing\\Router',
        'Illuminate\\Routing\\UrlGenerator',

        // Database
        'Illuminate\\Database\\Connection',
        'Illuminate\\Database\\Query\\Builder',

        // Services
        'Illuminate\\Auth\\AuthManager',
        'Illuminate\\Cache\\CacheManager',
        'Illuminate\\Queue\\Worker',
        'Illuminate\\Validation\\Validator',
        'Illuminate\\View\\View',
    ];

    // Classes that RARELY should be extended (Medium severity)
    private const RARELY_EXTEND = [
        // Database ORM
        'Illuminate\\Database\\Eloquent\\Builder',

        // HTTP Responses
        'Illuminate\\Http\\RedirectResponse',
        'Illuminate\\Http\\JsonResponse',

        // Support
        'Illuminate\\Support\\Facades\\Facade',
    ];

    // Classes that are OK to extend (explicitly documented as safe)
    private const OK_TO_EXTEND = [
        'Illuminate\\Database\\Eloquent\\Model',
        'Illuminate\\Console\\Command',
        'Illuminate\\Foundation\\Http\\FormRequest',
        'Illuminate\\Database\\Seeder',
        'Illuminate\\Foundation\\Testing\\TestCase',
        'Illuminate\\Http\\Middleware\\TrustProxies',
        'Illuminate\\Http\\Middleware\\TrustHosts',
        'Illuminate\\Foundation\\Http\\Middleware\\*',
        'Illuminate\\Routing\\Controller',
        'Illuminate\\Support\\ServiceProvider',
    ];

    /** @var array<int, string> */
    private array $neverExtend;

    /** @var array<int, string> */
    private array $rarelyExtend;

    /** @var array<int, string> */
    private array $okToExtend;

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'framework-override',
            name: 'Framework Override Analyzer',
            description: 'Detects dangerous overrides of Laravel framework classes',
            category: Category::BestPractices,
            severity: Severity::High,
            tags: ['laravel', 'framework', 'upgradability', 'maintenance'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/framework-override',
            timeToFix: 120
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration from config file (best_practices.framework-override)
        $analyzerConfig = $this->config->get('shieldci.analyzers.best_practices.framework-override', []);
        $analyzerConfig = is_array($analyzerConfig) ? $analyzerConfig : [];

        $this->neverExtend = $analyzerConfig['never_extend'] ?? self::NEVER_EXTEND;
        $this->rarelyExtend = $analyzerConfig['rarely_extend'] ?? self::RARELY_EXTEND;
        $this->okToExtend = $analyzerConfig['ok_to_extend'] ?? self::OK_TO_EXTEND;

        $issues = [];
        $phpFiles = $this->getPhpFiles();

        foreach ($phpFiles as $file) {
            // Skip test files and vendor packages
            if (! $this->shouldAnalyze($file)) {
                continue;
            }

            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new FrameworkOverrideVisitor(
                    $this->neverExtend,
                    $this->rarelyExtend,
                    $this->okToExtend
                );
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
            return $this->passed('No dangerous framework overrides detected');
        }

        return $this->failed(
            sprintf('Found %d framework override(s)', count($issues)),
            $issues
        );
    }

    /**
     * Determine if a file should be analyzed.
     * Excludes test files and vendor packages.
     */
    private function shouldAnalyze(string $file): bool
    {
        $normalized = str_replace('\\', '/', $file);

        // Ignore test directories
        if (str_contains($normalized, '/tests/') ||
            str_contains($normalized, '/Tests/')) {
            return false;
        }

        // Ignore vendor packages
        if (str_contains($normalized, '/vendor/')) {
            return false;
        }

        return true;
    }
}

/**
 * Visitor to detect framework class overrides.
 */
class FrameworkOverrideVisitor extends NodeVisitorAbstract
{
    /** @var array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}> */
    private array $issues = [];

    /**
     * @param  array<int, string>  $neverExtend
     * @param  array<int, string>  $rarelyExtend
     * @param  array<int, string>  $okToExtend
     */
    public function __construct(
        private array $neverExtend,
        private array $rarelyExtend,
        private array $okToExtend
    ) {}

    public function enterNode(Node $node): ?Node
    {
        if ($node instanceof Node\Stmt\Class_) {
            if ($node->extends !== null) {
                $parentClass = $node->extends->toString();

                // Skip if extending an explicitly allowed class
                if ($this->isOkToExtend($parentClass)) {
                    return null;
                }

                // Check if extending a problematic framework class
                $matchedClass = $this->getMatchedFrameworkClass($parentClass);
                if ($matchedClass !== null) {
                    $className = $node->name?->toString() ?? 'Unknown';
                    $severity = $this->getSeverity($matchedClass);

                    $this->issues[] = [
                        'message' => sprintf(
                            'Class "%s" extends core framework class "%s"',
                            $className,
                            $matchedClass
                        ),
                        'line' => $node->getLine(),
                        'severity' => $severity,
                        'recommendation' => $this->getRecommendation($matchedClass),
                        'code' => null,
                    ];
                }
            }
        }

        return null;
    }

    /**
     * Check if a class name matches any framework class (NEVER or RARELY extend).
     * Returns the matched framework class or null.
     */
    private function getMatchedFrameworkClass(string $className): ?string
    {
        // Check NEVER_EXTEND list
        foreach ($this->neverExtend as $coreClass) {
            if ($this->matchesClass($className, $coreClass)) {
                return $coreClass;
            }
        }

        // Check RARELY_EXTEND list
        foreach ($this->rarelyExtend as $coreClass) {
            if ($this->matchesClass($className, $coreClass)) {
                return $coreClass;
            }
        }

        return null;
    }

    /**
     * Check if className matches coreClass (handles both short and fully qualified names).
     */
    private function matchesClass(string $className, string $coreClass): bool
    {
        // Direct match (fully qualified name)
        if ($className === $coreClass) {
            return true;
        }

        // Match short class name
        $shortName = $this->getShortClassName($coreClass);
        if ($className === $shortName) {
            return true;
        }

        // Match with leading backslash
        if ($className === '\\'.$coreClass) {
            return true;
        }

        return false;
    }

    /**
     * Check if a class is explicitly allowed to extend.
     */
    private function isOkToExtend(string $className): bool
    {
        foreach ($this->okToExtend as $okClass) {
            if ($this->matchesClass($className, $okClass)) {
                return true;
            }

            // Handle wildcard patterns (e.g., "Illuminate\Http\Middleware\*")
            if (str_ends_with($okClass, '\\*')) {
                $namespace = substr($okClass, 0, -2);
                if (str_starts_with($className, $namespace.'\\')) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Get severity based on which list the class is in.
     */
    private function getSeverity(string $coreClass): Severity
    {
        if (in_array($coreClass, $this->neverExtend, true)) {
            return Severity::High;
        }

        if (in_array($coreClass, $this->rarelyExtend, true)) {
            return Severity::Medium;
        }

        return Severity::Low;
    }

    /**
     * Get class-specific recommendation.
     */
    private function getRecommendation(string $coreClass): string
    {
        $recommendations = [
            'Illuminate\\Http\\Request' => 'Instead of extending Request, use Request::macro() in a service provider to add custom methods, '.
                'or create a FormRequest for validation.',

            'Illuminate\\Database\\Eloquent\\Builder' => 'Instead of extending Builder, use query scopes on your Eloquent models. '.
                'Example: public function scopeActive($query) { return $query->where("active", true); }',

            'Illuminate\\Database\\Query\\Builder' => 'Extending Query Builder is extremely dangerous and will break during framework upgrades. '.
                'Use query scopes on Eloquent models or macros via DB::macro() for query builder extensions.',

            'Illuminate\\Routing\\Router' => 'Extending Router is extremely dangerous and will break during framework upgrades. '.
                'Use Router::macro() in a service provider or configure routes in RouteServiceProvider.',

            'Illuminate\\Foundation\\Application' => 'Never extend Application. This is the core of Laravel and extending it will cause severe upgrade issues. '.
                'Use service providers to customize behavior.',

            'Illuminate\\Http\\Response' => 'Instead of extending Response, use Response::macro() to add custom methods, '.
                'or return custom response types from your controllers.',

            'Illuminate\\Database\\Connection' => 'Extending Connection is extremely risky. Use database events or query macros instead.',

            'Illuminate\\Support\\Facades\\Facade' => 'Create your own facade by extending Facade is discouraged. '.
                'Use dependency injection or create a helper function instead.',

            'Illuminate\\Validation\\Validator' => 'Instead of extending Validator, use custom validation rules via Validator::extend() in a service provider.',
        ];

        return $recommendations[$coreClass] ??
            'Avoid extending core framework classes. They frequently change between Laravel versions. '.
            'Use Laravel\'s extension points instead: macros (e.g., Request::macro()), service providers, '.
            'middleware, event listeners, or custom helpers. Extending core classes will cause issues during framework upgrades.';
    }

    private function getShortClassName(string $fullClassName): string
    {
        $parts = explode('\\', $fullClassName);

        return end($parts);
    }

    /**
     * @return array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
