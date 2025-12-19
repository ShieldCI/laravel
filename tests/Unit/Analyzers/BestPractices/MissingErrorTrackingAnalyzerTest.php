<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\BestPractices\MissingErrorTrackingAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class MissingErrorTrackingAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        // Build best-practices config with defaults
        $bestPracticesConfig = [
            'enabled' => true,
            'missing-error-tracking' => [
                'known_packages' => $config['known_packages'] ?? [],
            ],
        ];

        $configRepo = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => $bestPracticesConfig,
                ],
            ],
        ]);

        return new MissingErrorTrackingAnalyzer($configRepo);
    }

    public function test_passes_with_sentry_installed(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
                'sentry/sentry-laravel' => '^3.0',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_bugsnag_installed(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
                'bugsnag/bugsnag-laravel' => '^2.0',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_rollbar_installed(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
                'rollbar/rollbar-laravel' => '^7.0',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_airbrake_installed(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
                'airbrake/phpbrake' => '^1.0',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_honeybadger_installed(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
                'honeybadger-io/honeybadger-laravel' => '^3.0',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_error_tracking_in_require_dev(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
            ],
            'require-dev' => [
                'sentry/sentry-laravel' => '^3.0',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_without_error_tracking_service(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('No error tracking service detected', $result);
    }

    public function test_skips_when_composer_json_not_found(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
    }

    public function test_provides_helpful_recommendation(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('Sentry', $issues[0]->recommendation);
        $this->assertStringContainsString('production error visibility', $issues[0]->recommendation);
    }

    public function test_handles_malformed_composer_json(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => 'invalid json {{{',
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }
}
