<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\BestPractices\MissingErrorTrackingAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
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

    public function test_fails_with_error_tracking_only_in_require_dev(): void
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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('No error tracking service detected', $result);
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

        $this->assertError($result);
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

    public function test_passes_with_laravel_flare_installed(): void
    {
        $this->assertPassed($this->analyzeProject(['composer.json' => $this->composerRequiring('spatie/laravel-flare')]));
    }

    public function test_passes_with_inspector_installed(): void
    {
        $this->assertPassed($this->analyzeProject(['composer.json' => $this->composerRequiring('inspector-apm/inspector-laravel')]));
    }

    public function test_passes_with_nightwatch_installed(): void
    {
        $this->assertPassed($this->analyzeProject(['composer.json' => $this->composerRequiring('laravel/nightwatch')]));
    }

    public function test_log_channel_does_not_count_for_switched_off_nightwatch(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('laravel/nightwatch'),
            '.env' => "APP_ENV=production\nNIGHTWATCH_ENABLED=false",
            'config/logging.php' => <<<'PHP'
<?php

return [
    'default' => env('LOG_CHANNEL', 'stack'),
    'channels' => [
        'stack' => ['driver' => 'stack', 'channels' => ['nightwatch']],
        'nightwatch' => ['driver' => 'nightwatch'],
    ],
];
PHP,
        ]);

        $this->assertWarning($result);
    }

    public function test_fails_when_nightwatch_is_switched_off_in_config(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('laravel/nightwatch'),
            'config/nightwatch.php' => "<?php\n\nreturn [\n    'enabled' => false,\n    'token' => env('NIGHTWATCH_TOKEN'),\n];\n",
        ]);

        $this->assertWarning($result);
        $this->assertHasIssueContaining('No error tracking service detected', $result);
    }

    public function test_passes_when_nightwatch_enabled_comes_from_env(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('laravel/nightwatch'),
            'config/nightwatch.php' => "<?php\n\nreturn [\n    'enabled' => env('NIGHTWATCH_ENABLED', false),\n];\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_fails_when_env_file_switches_off_unpublished_nightwatch(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('laravel/nightwatch'),
            '.env' => "APP_ENV=production\nNIGHTWATCH_ENABLED=false\nNIGHTWATCH_TOKEN=abc123",
        ]);

        $this->assertWarning($result);
        $this->assertHasIssueContaining('No error tracking service detected', $result);
    }

    public function test_fails_when_env_file_switches_off_published_nightwatch(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('laravel/nightwatch'),
            'config/nightwatch.php' => "<?php\n\nreturn [\n    'enabled' => env('NIGHTWATCH_ENABLED', true),\n    'token' => env('NIGHTWATCH_TOKEN'),\n];\n",
            '.env' => "APP_ENV=production\nNIGHTWATCH_ENABLED=\"(false)\" # paused\nNIGHTWATCH_TOKEN=abc123",
        ]);

        $this->assertWarning($result);
    }

    public function test_fails_when_unquoted_env_value_switches_off_nightwatch_before_a_comment(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('laravel/nightwatch'),
            '.env' => "APP_ENV=production\nNIGHTWATCH_ENABLED=false # paused\nNIGHTWATCH_TOKEN=abc123",
        ]);

        $this->assertWarning($result);
    }

    public function test_passes_when_env_file_enables_nightwatch(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('laravel/nightwatch'),
            '.env' => "APP_ENV=production\nNIGHTWATCH_ENABLED=true # on\nNIGHTWATCH_TOKEN='abc123'",
        ]);

        $this->assertPassed($result);
    }

    public function test_passes_when_env_file_leaves_nightwatch_token_to_the_server(): void
    {
        $result = $this->analyzeProject(['composer.json' => $this->composerRequiring('laravel/nightwatch')]);

        $this->assertPassed($result);
    }

    public function test_fails_when_env_file_leaves_nightwatch_token_empty(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('laravel/nightwatch'),
            '.env' => "APP_ENV=production\nNIGHTWATCH_TOKEN=",
        ]);

        $this->assertWarning($result);
    }

    public function test_fails_when_env_file_sets_nightwatch_token_to_null(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('laravel/nightwatch'),
            '.env' => "APP_ENV=production\nexport NIGHTWATCH_TOKEN=null",
        ]);

        $this->assertWarning($result);
    }

    public function test_fails_when_config_hard_codes_an_empty_nightwatch_token(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('laravel/nightwatch'),
            'config/nightwatch.php' => "<?php\n\nreturn [\n    'enabled' => true,\n    'token' => '',\n];\n",
            '.env' => "APP_ENV=production\nNIGHTWATCH_TOKEN=abc123",
        ]);

        $this->assertWarning($result);
    }

    public function test_passes_when_config_hard_codes_a_nightwatch_token(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('laravel/nightwatch'),
            'config/nightwatch.php' => "<?php\n\nreturn [\n    'token' => 'abc123',\n];\n",
            '.env' => "APP_ENV=production\nNIGHTWATCH_TOKEN=",
        ]);

        $this->assertPassed($result);
    }

    public function test_switched_off_nightwatch_does_not_hide_a_tracker_listed_after_it(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => (string) json_encode(['require' => [
                'laravel/nightwatch' => '^1.0',
                'sentry/sentry-laravel' => '^4.0',
            ]]),
            'config/nightwatch.php' => "<?php\n\nreturn ['enabled' => false];\n",
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer(['known_packages' => ['laravel/nightwatch', 'sentry/sentry-laravel']]);
        $analyzer->setBasePath($tempDir);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_fails_when_the_running_app_environment_switches_off_nightwatch(): void
    {
        $result = $this->analyzeRunningApp(
            ['composer.json' => $this->composerRequiring('laravel/nightwatch')],
            ['NIGHTWATCH_ENABLED' => 'false'],
        );

        $this->assertWarning($result);
        $this->assertHasIssueContaining('No error tracking service detected', $result);
    }

    public function test_fails_when_the_running_app_environment_empties_the_nightwatch_token(): void
    {
        $result = $this->analyzeRunningApp(
            ['composer.json' => $this->composerRequiring('laravel/nightwatch')],
            ['NIGHTWATCH_TOKEN' => ''],
        );

        $this->assertWarning($result);
    }

    public function test_running_app_environment_overrides_the_env_file(): void
    {
        $result = $this->analyzeRunningApp(
            [
                'composer.json' => $this->composerRequiring('laravel/nightwatch'),
                '.env' => "APP_ENV=production\nNIGHTWATCH_ENABLED=false",
            ],
            ['NIGHTWATCH_ENABLED' => 'true'],
        );

        $this->assertPassed($result);
    }

    public function test_falls_back_to_the_env_file_when_the_running_app_environment_is_silent(): void
    {
        $result = $this->analyzeRunningApp(
            [
                'composer.json' => $this->composerRequiring('laravel/nightwatch'),
                '.env' => "APP_ENV=production\nNIGHTWATCH_ENABLED=false",
            ],
            [],
        );

        $this->assertWarning($result);
    }

    public function test_ignores_this_process_environment_for_another_project(): void
    {
        putenv('NIGHTWATCH_ENABLED=false');

        try {
            $result = $this->analyzeProject(['composer.json' => $this->composerRequiring('laravel/nightwatch')]);
        } finally {
            putenv('NIGHTWATCH_ENABLED');
        }

        $this->assertPassed($result);
    }

    public function test_recognises_the_running_app_through_a_symlinked_base_path(): void
    {
        $tempDir = $this->createTempDirectory([
            'project/composer.json' => $this->composerRequiring('laravel/nightwatch'),
            'project/.env' => 'APP_ENV=production',
        ]);

        if (! @symlink($tempDir.'/project', $tempDir.'/link')) {
            $this->markTestSkipped('Cannot create symlinks on this system');
        }

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir.'/project');

        putenv('NIGHTWATCH_ENABLED=false');

        try {
            $result = $this->withBasePath($tempDir.'/link', fn () => $analyzer->analyze());
        } finally {
            putenv('NIGHTWATCH_ENABLED');
        }

        $this->assertWarning($result);
    }

    public function test_passes_with_tracker_in_lock_file_packages(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('acme/monitoring-bundle'),
            'composer.lock' => $this->composerLock(['acme/monitoring-bundle', 'sentry/sentry-laravel']),
        ]);

        $this->assertPassed($result);
    }

    public function test_fails_with_tracker_only_in_lock_file_packages_dev(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('laravel/framework'),
            'composer.lock' => $this->composerLock(['laravel/framework'], ['sentry/sentry-laravel']),
        ]);

        $this->assertWarning($result);
        $this->assertHasIssueContaining('No error tracking service detected', $result);
    }

    public function test_lock_file_is_authoritative_over_composer_json(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('sentry/sentry-laravel'),
            'composer.lock' => $this->composerLock(['laravel/framework']),
        ]);

        $this->assertWarning($result);
    }

    public function test_ignores_tracker_named_only_in_a_package_requirement(): void
    {
        $lock = (string) json_encode([
            'packages' => [[
                'name' => 'acme/toolkit',
                'suggest' => ['sentry/sentry-laravel' => 'Report errors'],
            ]],
            'packages-dev' => [],
        ]);

        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('acme/toolkit'),
            'composer.lock' => $lock,
        ]);

        $this->assertWarning($result);
    }

    public function test_errors_on_malformed_composer_lock(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('sentry/sentry-laravel'),
            'composer.lock' => 'invalid json {{{',
        ]);

        $this->assertError($result);
        $this->assertStringContainsString('composer.lock', $result->getMessage());
    }

    public function test_errors_on_composer_lock_without_packages(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('sentry/sentry-laravel'),
            'composer.lock' => (string) json_encode(['content-hash' => 'abc']),
        ]);

        $this->assertError($result);
        $this->assertSame('composer.lock has no "packages" list', $result->getMessage());
    }

    public function test_errors_on_composer_json_that_is_not_an_object(): void
    {
        $result = $this->analyzeProject(['composer.json' => '"sentry/sentry-laravel"']);

        $this->assertError($result);
        $this->assertSame('composer.json does not contain a JSON object', $result->getMessage());
    }

    public function test_errors_on_unreadable_composer_lock(): void
    {
        if (function_exists('posix_getuid') && posix_getuid() === 0) {
            $this->markTestSkipped('root reads a file whatever its mode');
        }

        $tempDir = $this->createTempDirectory([
            'composer.json' => $this->composerRequiring('sentry/sentry-laravel'),
            'composer.lock' => $this->composerLock(['sentry/sentry-laravel']),
            '.env' => 'APP_ENV=production',
        ]);
        chmod($tempDir.'/composer.lock', 0000);

        try {
            $analyzer = $this->createAnalyzer();
            $analyzer->setBasePath($tempDir);
            $result = $analyzer->analyze();
        } finally {
            chmod($tempDir.'/composer.lock', 0644);
        }

        $this->assertError($result);
        $this->assertSame('composer.lock could not be read', $result->getMessage());
    }

    public function test_finding_from_lock_file_names_it_but_points_at_composer_json(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('sentry/sentry-laravel'),
            'composer.lock' => $this->composerLock(['laravel/framework']),
        ]);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame('composer.json', $issues[0]->location?->file);
        $this->assertStringStartsWith('composer.lock, not composer.json, decides', $issues[0]->recommendation);
    }

    public function test_finding_from_composer_json_has_no_lock_file_note(): void
    {
        $result = $this->analyzeProject(['composer.json' => $this->composerRequiring('laravel/framework')]);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringStartsWith('Consider installing', $issues[0]->recommendation);
    }

    public function test_package_names_match_case_insensitively(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => (string) json_encode(['require' => ['Sentry/Sentry-Laravel' => '^4.0']]),
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer(['known_packages' => ['SENTRY/sentry-laravel']]);
        $analyzer->setBasePath($tempDir);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_known_package_with_capitals_matches_lowercase_lock_entry(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => $this->composerRequiring('acme/error-reporter'),
            'composer.lock' => $this->composerLock(['acme/error-reporter']),
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer(['known_packages' => ['Acme/Error-Reporter']]);
        $analyzer->setBasePath($tempDir);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_lock_entry_with_capitals_matches_known_package(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('laravel/framework'),
            'composer.lock' => $this->composerLock(['Sentry/Sentry-Laravel']),
        ]);

        $this->assertPassed($result);
    }

    public function test_passes_with_flare_wired_in_bootstrap_app(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('laravel/framework'),
            'bootstrap/app.php' => <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Spatie\LaravelFlare\Facades\Flare;

return Application::configure(basePath: dirname(__DIR__))
    ->withExceptions(function (Exceptions $exceptions) {
        Flare::handles($exceptions);
    })->create();
PHP,
        ]);

        $this->assertPassed($result);
    }

    public function test_passes_with_inspector_reporting_in_handler(): void
    {
        $result = $this->analyzeProject([
            'composer.json' => $this->composerRequiring('laravel/framework'),
            'app/Exceptions/Handler.php' => <<<'PHP'
<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Inspector\Laravel\Facades\Inspector;
use Throwable;

class Handler extends ExceptionHandler
{
    public function report(Throwable $e): void
    {
        Inspector::reportException($e);
        parent::report($e);
    }
}
PHP,
        ]);

        $this->assertPassed($result);
    }

    public function test_known_packages_override_applies_to_lock_file(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => $this->composerRequiring('acme/error-reporter'),
            'composer.lock' => $this->composerLock(['acme/error-reporter']),
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer(['known_packages' => ['acme/error-reporter']]);
        $analyzer->setBasePath($tempDir);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * @param  array<string, string>  $files
     */
    private function analyzeProject(array $files): ResultInterface
    {
        $tempDir = $this->createTempDirectory($files + ['.env' => 'APP_ENV=production']);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        return $analyzer->analyze();
    }

    /**
     * Analyze a project that is also the application running the analysis, with the given
     * variables in this process's environment.
     *
     * @param  array<string, string>  $files
     * @param  array<string, string>  $env
     */
    private function analyzeRunningApp(array $files, array $env): ResultInterface
    {
        $tempDir = $this->createTempDirectory($files + ['.env' => 'APP_ENV=production']);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        foreach ($env as $key => $value) {
            putenv("{$key}={$value}");
        }

        try {
            return $this->withBasePath($tempDir, fn () => $analyzer->analyze());
        } finally {
            foreach (array_keys($env) as $key) {
                putenv($key);
            }
        }
    }

    private function composerRequiring(string $package): string
    {
        return (string) json_encode(['require' => ['php' => '^8.1', $package => '*']]);
    }

    /**
     * @param  list<string>  $packages
     * @param  list<string>  $devPackages
     */
    private function composerLock(array $packages, array $devPackages = []): string
    {
        $entries = fn (array $names): array => array_map(
            fn (string $name): array => ['name' => $name, 'version' => '1.0.0'],
            $names,
        );

        return (string) json_encode([
            'packages' => $entries($packages),
            'packages-dev' => $entries($devPackages),
        ]);
    }
}
