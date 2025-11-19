<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects production apps without error tracking service.
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

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'missing-error-tracking',
            name: 'Missing Error Tracking Detector',
            description: 'Detects production applications without error tracking services like Sentry',
            category: Category::BestPractices,
            severity: Severity::Medium,
            tags: ['laravel', 'monitoring', 'production', 'error-tracking'],
            docsUrl: 'https://docs.shieldci.com/analyzers/missing-error-tracking',
        );
    }

    public function shouldRun(): bool
    {
        // Check if relevant for current environment first
        return $this->isRelevantForCurrentEnvironment();
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check composer.json for error tracking packages
        $composerPath = $this->basePath.'/composer.json';
        if (! file_exists($composerPath)) {
            return $this->passed('No composer.json found');
        }

        $composer = json_decode(FileParser::readFile($composerPath) ?? '{}', true);
        $require = is_array($composer['require'] ?? null) ? $composer['require'] : [];
        $requireDev = is_array($composer['require-dev'] ?? null) ? $composer['require-dev'] : [];
        $dependencies = array_merge($require, $requireDev);

        $errorTrackingServices = [
            'sentry/sentry-laravel',
            'bugsnag/bugsnag-laravel',
            'rollbar/rollbar-laravel',
            'airbrake/phpbrake',
            'honeybadger-io/honeybadger-laravel',
        ];

        $hasErrorTracking = false;
        foreach ($errorTrackingServices as $service) {
            if (isset($dependencies[$service])) {
                $hasErrorTracking = true;
                break;
            }
        }

        if (! $hasErrorTracking) {
            $issues[] = $this->createIssue(
                message: 'No error tracking service found in composer.json',
                location: new Location('composer.json', 1),
                severity: Severity::Medium,
                recommendation: 'Install an error tracking service like Sentry (sentry/sentry-laravel), Bugsnag, or Rollbar for production error monitoring. This provides better visibility into production errors, automatic error grouping, and faster debugging',
                code: null,
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
}
