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

        return new MissingErrorTrackingAnalyzer($this->parser, $configRepo);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

    public function test_passes_with_reportable_in_handler(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
            ],
        ]);

        $handlerContent = <<<'PHP'
<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Throwable;

class Handler extends ExceptionHandler
{
    public function register(): void
    {
        $this->reportable(function (Throwable $e) {
            // Send to custom error tracking service
            app('error-tracker')->report($e);
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
            'app/Exceptions/Handler.php' => $handlerContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_sentry_sdk_in_handler(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
            ],
        ]);

        $handlerContent = <<<'PHP'
<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Throwable;

class Handler extends ExceptionHandler
{
    public function report(Throwable $e): void
    {
        if ($this->shouldReport($e)) {
            \Sentry\captureException($e);
        }
        parent::report($e);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
            'app/Exceptions/Handler.php' => $handlerContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_nested_report_method_containing_sdk_patterns(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
            ],
        ]);

        // This was previously failing due to the broken regex
        $handlerContent = <<<'PHP'
<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Throwable;

class Handler extends ExceptionHandler
{
    public function report(Throwable $e): void
    {
        if ($e instanceof CustomException) {
            try {
                $this->customErrorTracker->captureException($e);
            } catch (\Exception $inner) {
                logger()->error('Failed to report', ['error' => $inner->getMessage()]);
            }
        }
        parent::report($e);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
            'app/Exceptions/Handler.php' => $handlerContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_trivial_report_override(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
            ],
        ]);

        // Trivial override that just calls parent - no actual error tracking
        $handlerContent = <<<'PHP'
<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Throwable;

class Handler extends ExceptionHandler
{
    public function report(Throwable $e): void
    {
        parent::report($e);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
            'app/Exceptions/Handler.php' => $handlerContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('No error tracking service detected', $result);
    }

    public function test_passes_with_bugsnag_sdk_in_handler(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
            ],
        ]);

        $handlerContent = <<<'PHP'
<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Throwable;

class Handler extends ExceptionHandler
{
    public function report(Throwable $e): void
    {
        Bugsnag::notifyException($e);
        parent::report($e);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
            'app/Exceptions/Handler.php' => $handlerContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_cloudwatch_in_handler(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
            ],
        ]);

        $handlerContent = <<<'PHP'
<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Throwable;

class Handler extends ExceptionHandler
{
    public function report(Throwable $e): void
    {
        // Send to CloudWatch
        $this->cloudWatchLogger->logException($e);
        parent::report($e);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
            'app/Exceptions/Handler.php' => $handlerContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_cloudwatch_in_comments(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
            ],
        ]);

        // CloudWatch mentioned only in comment - should NOT count as error tracking
        $handlerContent = <<<'PHP'
<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Throwable;

class Handler extends ExceptionHandler
{
    public function report(Throwable $e): void
    {
        // TODO: add CloudWatch logging later
        parent::report($e);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
            'app/Exceptions/Handler.php' => $handlerContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('No error tracking service detected', $result);
    }

    public function test_ignores_sdk_patterns_in_comments(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
            ],
        ]);

        // SDK pattern in comment only - should NOT count as error tracking
        $handlerContent = <<<'PHP'
<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Throwable;

class Handler extends ExceptionHandler
{
    public function report(Throwable $e): void
    {
        // Sentry\captureException($e); - disabled for now
        parent::report($e);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
            'app/Exceptions/Handler.php' => $handlerContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('No error tracking service detected', $result);
    }

    public function test_ignores_cloudwatch_in_logging_config_comments(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
            ],
        ]);

        // CloudWatch in config comment only - should NOT count as error tracking
        $loggingConfig = <<<'PHP'
<?php

return [
    'default' => env('LOG_CHANNEL', 'stack'),

    'channels' => [
        'stack' => [
            'driver' => 'stack',
            'channels' => ['single'],
        ],
        'single' => [
            'driver' => 'single',
            'path' => storage_path('logs/laravel.log'),
        ],
        // TODO: Configure cloudwatch channel for production
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
            'config/logging.php' => $loggingConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('No error tracking service detected', $result);
    }

    public function test_ignores_patterns_in_docblocks(): void
    {
        $composerJson = json_encode([
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
            ],
        ]);

        // Pattern in docblock - should NOT count as error tracking
        $handlerContent = <<<'PHP'
<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Throwable;

/**
 * Application exception handler.
 *
 * For production, consider using Sentry\captureException or Bugsnag::notifyException
 * to track errors. CloudWatch integration is also available.
 */
class Handler extends ExceptionHandler
{
    public function report(Throwable $e): void
    {
        parent::report($e);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            '.env' => 'APP_ENV=production',
            'app/Exceptions/Handler.php' => $handlerContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('No error tracking service detected', $result);
    }
}
