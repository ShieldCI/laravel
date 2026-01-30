<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use Illuminate\Contracts\Config\Repository as Config;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects applications without error tracking service.
 *
 * Checks for:
 * - Popular error tracking packages (Sentry, Bugsnag, etc.)
 * - Custom error tracking implementations in Handler.php (Laravel <=10)
 * - Custom error tracking in bootstrap/app.php (Laravel 11+)
 * - CloudWatch/Datadog logging configurations
 */
class MissingErrorTrackingAnalyzer extends AbstractFileAnalyzer
{
    /**
     * This analyzer is only relevant in production and staging environments.
     *
     * Custom environment names are automatically handled via environment mapping.
     *
     * Not relevant in:
     * - local: Developers don't need error tracking
     * - development: Same as local
     * - testing: Test suite doesn't need error tracking
     *
     * @var array<string>
     */
    protected ?array $relevantEnvironments = ['production', 'staging'];

    /**
     * error tracking checks are not applicable in CI environments.
     */
    public static bool $runInCI = false;

    /**
     * Known error tracking packages to check for.
     *
     * @var array<string>
     */
    private array $knownPackages = [];

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

    /**
     * Set known packages (for testing).
     *
     * @param  array<string>  $packages
     */
    public function setKnownPackages(array $packages): void
    {
        $this->knownPackages = $packages;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'missing-error-tracking',
            name: 'Missing Error Tracking Analyzer',
            description: 'Detects production applications without error tracking services or custom error monitoring',
            category: Category::BestPractices,
            severity: Severity::Info,
            tags: ['laravel', 'monitoring', 'production', 'error-tracking', 'observability'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/missing-error-tracking',
            timeToFix: 30
        );
    }

    public function shouldRun(): bool
    {
        // Check environment relevance first
        if (! $this->isRelevantForCurrentEnvironment()) {
            return false;
        }

        // Only run if composer.json exists
        $composerPath = $this->basePath.'/composer.json';

        return file_exists($composerPath);
    }

    public function getSkipReason(): string
    {
        if (! $this->isRelevantForCurrentEnvironment()) {
            $currentEnv = $this->getEnvironment();
            $relevantEnvs = implode(', ', $this->relevantEnvironments ?? []);

            return "Not relevant in '{$currentEnv}' environment (only relevant in: {$relevantEnvs})";
        }

        return 'No composer.json found';
    }

    /**
     * Load configuration from config repository.
     */
    private function loadConfiguration(): void
    {
        // Default known error tracking packages
        // Only includes dedicated production error tracking services
        // Excludes: facade/ignition, spatie/laravel-ray, spatie/flare-client-php (dev-only tools)
        // Excludes: aws/aws-sdk-php (too broad - used for S3, SES, SQS without error tracking)
        $defaultPackages = [
            'sentry/sentry-laravel',
            'bugsnag/bugsnag-laravel',
            'rollbar/rollbar-laravel',
            'airbrake/phpbrake',
            'honeybadger-io/honeybadger-laravel',
        ];

        // Load from config
        $configPackages = $this->config->get('shieldci.analyzers.best-practices.missing-error-tracking.known_packages', []);

        // Ensure configPackages is an array
        if (! is_array($configPackages)) {
            $configPackages = [];
        }

        // If config has packages, use them; otherwise use defaults
        // This allows complete override rather than merge
        if (! empty($configPackages)) {
            $this->knownPackages = array_values(array_unique($configPackages));
        } else {
            $this->knownPackages = $defaultPackages;
        }
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration
        $this->loadConfiguration();

        $issues = [];

        // Check composer.json for error tracking packages (we know it exists from shouldRun())
        $composerPath = $this->basePath.'/composer.json';

        $composer = $this->parseComposerJson($composerPath);
        if ($composer === null) {
            // Malformed JSON - fail with error
            return $this->failed(
                'composer.json contains invalid JSON',
                [$this->createIssue(
                    message: 'composer.json contains invalid JSON and cannot be parsed',
                    location: new Location('composer.json'),
                    severity: Severity::High,
                    recommendation: 'Fix JSON syntax errors in composer.json. Run: composer validate',
                )]
            );
        }

        // Check for error tracking packages
        $hasErrorTracking = $this->checkForErrorTrackingPackages($composer);

        // If no package found, check for custom implementations
        if (! $hasErrorTracking) {
            $hasErrorTracking = $this->checkForCustomErrorTracking();
        }

        // If still no error tracking found, report it as info
        if (! $hasErrorTracking) {
            $issues[] = $this->createIssue(
                message: 'No error tracking service detected',
                location: new Location('composer.json'),
                severity: Severity::Info,
                recommendation: 'Consider installing an error tracking service like Sentry (sentry/sentry-laravel), Bugsnag, or Rollbar for better production error visibility. '.
                    'This provides automatic error grouping, stack traces, release tracking, and faster debugging. '.
                    'If you\'re using custom error logging (CloudWatch, Datadog, New Relic APM, or custom solutions), you can safely ignore this recommendation.',
            );
        }

        if (empty($issues)) {
            return $this->passed('Error tracking service is configured');
        }

        return $this->failed(
            'No error tracking service detected',
            $issues
        );
    }

    /**
     * Parse composer.json with proper error handling.
     *
     * @return array<string, mixed>|null
     */
    private function parseComposerJson(string $path): ?array
    {
        $content = FileParser::readFile($path);
        if ($content === null) {
            return null;
        }

        $decoded = json_decode($content, true);

        // Check for JSON decode errors
        if (json_last_error() !== JSON_ERROR_NONE) {
            return null;
        }

        // Ensure it's an array
        if (! is_array($decoded)) {
            return null;
        }

        return $decoded;
    }

    /**
     * Check for known error tracking packages in composer dependencies.
     *
     * @param  array<string, mixed>  $composer
     */
    private function checkForErrorTrackingPackages(array $composer): bool
    {
        $require = is_array($composer['require'] ?? null) ? $composer['require'] : [];
        $requireDev = is_array($composer['require-dev'] ?? null) ? $composer['require-dev'] : [];
        $dependencies = array_merge($require, $requireDev);

        foreach ($this->knownPackages as $service) {
            if (isset($dependencies[$service])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check for custom error tracking implementations.
     *
     * Looks for:
     * - Custom error reporting in Handler.php (Laravel <=10)
     * - Custom error reporting in bootstrap/app.php (Laravel 11+)
     * - CloudWatch configuration in logging.php
     * - Datadog/New Relic mentions
     */
    private function checkForCustomErrorTracking(): bool
    {
        // Check Exception Handler for custom error reporting (Laravel <=10)
        $handlerPath = $this->basePath.'/app/Exceptions/Handler.php';
        if (file_exists($handlerPath) && $this->hasCustomErrorReporting($handlerPath)) {
            return true;
        }

        // Check bootstrap/app.php for exception handling (Laravel 11+)
        $bootstrapAppPath = $this->basePath.'/bootstrap/app.php';
        if (file_exists($bootstrapAppPath) && $this->hasCustomErrorReporting($bootstrapAppPath)) {
            return true;
        }

        // Check logging configuration for CloudWatch or other services
        $loggingConfigPath = $this->basePath.'/config/logging.php';
        if (file_exists($loggingConfigPath)) {
            $loggingContent = FileParser::readFile($loggingConfigPath);
            if ($loggingContent !== null && $this->hasCustomLoggingSetup($loggingContent)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if file has custom error reporting logic using AST and pattern detection.
     */
    private function hasCustomErrorReporting(string $filePath): bool
    {
        // 1. Use AST to find reportable() method calls (most reliable indicator)
        $ast = $this->parser->parseFile($filePath);
        if (! empty($ast)) {
            $reportableCalls = $this->parser->findMethodCalls($ast, 'reportable');
            if (! empty($reportableCalls)) {
                return true;
            }
        }

        // 2. Check file content for SDK/service patterns
        $content = FileParser::readFile($filePath);
        if ($content !== null && $this->hasErrorTrackingPatterns($content)) {
            return true;
        }

        return false;
    }

    /**
     * Check for error tracking SDK patterns in content.
     */
    private function hasErrorTrackingPatterns(string $content): bool
    {
        $patterns = [
            // Cloud services
            'CloudWatch',
            'Datadog',
            'NewRelic',
            'new_relic',

            // Error tracking SDKs
            'Sentry\\',              // Sentry\captureException
            'captureException',      // Common SDK method
            'captureMessage',        // Common SDK method
            'Bugsnag::',             // Bugsnag SDK
            'Rollbar::',             // Rollbar SDK
            'Honeybadger::',         // Honeybadger SDK
            'notifyException',       // Common method name
        ];

        foreach ($patterns as $pattern) {
            if (stripos($content, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if logging config has custom setup (CloudWatch, Datadog, etc.).
     */
    private function hasCustomLoggingSetup(string $content): bool
    {
        $patterns = [
            'cloudwatch',
            'datadog',
            'newrelic',
            'logtail',
            'papertrail',
            'logentries',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match('/'.$pattern.'/i', $content)) {
                return true;
            }
        }

        return false;
    }
}
