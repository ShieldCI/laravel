<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\DebugModeAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class DebugModeAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new DebugModeAnalyzer;
    }

    // =================================================================
    // .env File Tests
    // =================================================================

    public function test_detects_app_debug_true_in_regular_env(): void
    {
        $envContent = <<<'ENV'
APP_DEBUG=true
APP_ENV=local
ENV;

        $tempDir = $this->createTempDirectory(['.env' => $envContent]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('APP_DEBUG=true', $result);
        $issues = $result->getIssues();
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $issues[0]->severity);
    }

    public function test_detects_app_debug_true_in_env_production(): void
    {
        $envContent = <<<'ENV'
APP_DEBUG=true
APP_ENV=production
ENV;

        $tempDir = $this->createTempDirectory(['.env.production' => $envContent]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('APP_DEBUG', $result);
        $issues = $result->getIssues();
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
    }

    public function test_detects_app_debug_true_in_env_prod(): void
    {
        $envContent = <<<'ENV'
APP_DEBUG=true
APP_ENV=production
ENV;

        $tempDir = $this->createTempDirectory(['.env.prod' => $envContent]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('APP_DEBUG', $result);
        $issues = $result->getIssues();
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
    }

    public function test_ignores_commented_app_debug(): void
    {
        $envContent = <<<'ENV'
# APP_DEBUG=true
APP_DEBUG=false
ENV;

        $tempDir = $this->createTempDirectory(['.env' => $envContent]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_app_debug_with_spaces(): void
    {
        $envContent = <<<'ENV'
APP_DEBUG  =  true
ENV;

        $tempDir = $this->createTempDirectory(['.env' => $envContent]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('APP_DEBUG', $result);
    }

    public function test_detects_multiple_env_files_with_debug(): void
    {
        $envContent = 'APP_DEBUG=true';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.production' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
    }

    public function test_includes_metadata_for_env_issues(): void
    {
        $envContent = 'APP_DEBUG=true';

        $tempDir = $this->createTempDirectory(['.env' => $envContent]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertArrayHasKey('file', $issues[0]->metadata);
        $this->assertArrayHasKey('env_var', $issues[0]->metadata);
        $this->assertEquals('APP_DEBUG', $issues[0]->metadata['env_var']);
    }

    public function test_handles_missing_env_files(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
    }

    public function test_passes_with_debug_disabled(): void
    {
        $envContent = <<<'ENV'
APP_DEBUG=false
APP_ENV=production
ENV;

        $tempDir = $this->createTempDirectory(['.env' => $envContent]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_severity_critical_for_production_env(): void
    {
        $envContent = 'APP_DEBUG=true';

        $tempDir = $this->createTempDirectory(['.env.production' => $envContent]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
    }

    // =================================================================
    // Config File Tests
    // =================================================================

    public function test_detects_hardcoded_debug_true_in_app_config(): void
    {
        $appConfig = <<<'PHP'
<?php
return [
    'debug' => true,
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/app.php' => $appConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('hardcoded', $result);
        $issues = $result->getIssues();
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
    }

    public function test_ignores_env_based_debug_config(): void
    {
        $appConfig = <<<'PHP'
<?php
return [
    'debug' => env('APP_DEBUG', false),
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/app.php' => $appConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_missing_debug_hide_in_production(): void
    {
        $appConfig = <<<'PHP'
<?php
return [
    'debug' => env('APP_DEBUG', true),
    'env' => env('APP_ENV', 'production'),
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/app.php' => $appConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('sensitive environment variables', $result);
    }

    public function test_detects_missing_debug_blacklist(): void
    {
        $appConfig = <<<'PHP'
<?php
return [
    'debug' => true,
    'env' => env('APP_ENV', 'staging'),
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/app.php' => $appConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('sensitive environment variables', $result);
    }

    public function test_passes_with_debug_hide_configured(): void
    {
        $appConfig = <<<'PHP'
<?php
return [
    'debug' => env('APP_DEBUG', true),
    'env' => env('APP_ENV', 'production'),
    'debug_hide' => [
        'password',
        'api_key',
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/app.php' => $appConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_missing_config_files(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
    }

    public function test_includes_metadata_for_config_issues(): void
    {
        $appConfig = <<<'PHP'
<?php
return [
    'debug' => true,
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/app.php' => $appConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertArrayHasKey('file', $issues[0]->metadata);
        $this->assertArrayHasKey('config_key', $issues[0]->metadata);
        $this->assertEquals('debug', $issues[0]->metadata['config_key']);
    }

    public function test_detects_app_env_production_without_debug_hide(): void
    {
        $appConfig = <<<'PHP'
<?php
return [
    'debug' => env('APP_DEBUG', true),
    'env' => env('APP_ENV', 'production'),
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/app.php' => $appConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertArrayHasKey('app_env', $issues[0]->metadata);
        $this->assertEquals('production', $issues[0]->metadata['app_env']);
    }

    public function test_ignores_debug_hide_check_for_local_env(): void
    {
        $appConfig = <<<'PHP'
<?php
return [
    'debug' => env('APP_DEBUG', true),
    'env' => env('APP_ENV', 'local'),
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/app.php' => $appConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_debug_hide_multi_line_array_detection(): void
    {
        $appConfig = <<<'PHP'
<?php
return [
    'debug' => env('APP_DEBUG', true),
    'env' => env('APP_ENV', 'production'),
    'debug_hide' =>
        ['password', 'secret'],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/app.php' => $appConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_severity_critical_for_hardcoded_debug(): void
    {
        $appConfig = <<<'PHP'
<?php
return ['debug' => true];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/app.php' => $appConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
    }

    // =================================================================
    // Debug Function Tests
    // =================================================================

    public function test_detects_dd_function(): void
    {
        $code = <<<'PHP'
<?php
namespace App\Http\Controllers;

class TestController
{
    public function index()
    {
        dd($data);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/TestController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('dd()', $result);
        $issues = $result->getIssues();
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $issues[0]->severity);
    }

    public function test_detects_dump_function(): void
    {
        $code = <<<'PHP'
<?php
dump($variable);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Debug.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('dump()', $result);
    }

    public function test_detects_var_dump_function(): void
    {
        $code = <<<'PHP'
<?php
var_dump($data);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Helpers/test.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('var_dump()', $result);
    }

    public function test_detects_print_r_function(): void
    {
        $code = <<<'PHP'
<?php
print_r($array);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/helpers.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('print_r()', $result);
    }

    public function test_detects_var_export_function(): void
    {
        $code = <<<'PHP'
<?php
var_export($data);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/debug.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('var_export()', $result);
        $issues = $result->getIssues();
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $issues[0]->severity);
    }

    public function test_detects_debug_backtrace_function(): void
    {
        $code = <<<'PHP'
<?php
$trace = debug_backtrace();
PHP;

        $tempDir = $this->createTempDirectory([
            'app/debug.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('debug_backtrace()', $result);
    }

    public function test_detects_debug_print_backtrace_function(): void
    {
        $code = <<<'PHP'
<?php
debug_print_backtrace();
PHP;

        $tempDir = $this->createTempDirectory([
            'app/debug.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('debug_print_backtrace()', $result);
    }

    public function test_detects_ray_function(): void
    {
        $code = <<<'PHP'
<?php
ray($data);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/debug.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Ray', $result);
        $issues = $result->getIssues();
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $issues[0]->severity);
    }

    public function test_detects_error_reporting_e_all(): void
    {
        $code = <<<'PHP'
<?php

error_reporting(E_ALL);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/bootstrap.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Verbose error reporting', $result);
    }

    public function test_detects_ini_set_display_errors(): void
    {
        $code = <<<'PHP'
<?php
ini_set('display_errors', 1);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/bootstrap.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('ini_set', $result);
    }

    public function test_ignores_debug_functions_in_test_files(): void
    {
        $code = <<<'PHP'
<?php
namespace Tests\Unit;

class ExampleTest
{
    public function testDebug()
    {
        dd($data);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'tests/Unit/ExampleTest.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['tests']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_debug_functions_in_seeders(): void
    {
        $code = <<<'PHP'
<?php
namespace Database\Seeders;

class DatabaseSeeder
{
    public function run()
    {
        dump('Seeding...');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'database/seeders/DatabaseSeeder.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['database']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_debug_functions_in_factories(): void
    {
        $code = <<<'PHP'
<?php
namespace Database\Factories;

class UserFactory
{
    public function definition()
    {
        var_dump('Factory');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'database/factories/UserFactory.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['database']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_includes_metadata_for_function_issues(): void
    {
        $code = <<<'PHP'
<?php
dd($data);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/test.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertArrayHasKey('function', $issues[0]->metadata);
        $this->assertEquals('dd', $issues[0]->metadata['function']);
    }

    public function test_severity_high_for_critical_functions(): void
    {
        $code = <<<'PHP'
<?php
dd($data);
dump($other);
var_dump($more);
print_r($array);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/test.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        // All HIGH_SEVERITY_FUNCTIONS should be High
        foreach ($issues as $issue) {
            $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $issue->severity);
        }
    }

    // =================================================================
    // Composer Package Tests
    // =================================================================

    public function test_detects_debugbar_in_require(): void
    {
        $composer = <<<'JSON'
{
    "require": {
        "php": "^8.1",
        "barryvdh/laravel-debugbar": "^3.8"
    }
}
JSON;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composer,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Debugbar', $result);
    }

    public function test_detects_telescope_in_require(): void
    {
        $composer = <<<'JSON'
{
    "require": {
        "laravel/telescope": "^4.0"
    }
}
JSON;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composer,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Telescope', $result);
    }

    public function test_detects_ray_in_require(): void
    {
        $composer = <<<'JSON'
{
    "require": {
        "spatie/laravel-ray": "^1.0"
    }
}
JSON;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composer,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Ray', $result);
    }

    public function test_detects_dump_server_in_require(): void
    {
        $composer = <<<'JSON'
{
    "require": {
        "beyondcode/laravel-dump-server": "^1.0"
    }
}
JSON;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composer,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Dump Server', $result);
    }

    public function test_passes_when_debug_packages_in_require_dev(): void
    {
        $composer = <<<'JSON'
{
    "require": {
        "php": "^8.1"
    },
    "require-dev": {
        "barryvdh/laravel-debugbar": "^3.8",
        "laravel/telescope": "^4.0"
    }
}
JSON;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composer,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_missing_composer_json(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_DEBUG=false',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_includes_metadata_for_package_issues(): void
    {
        $composer = <<<'JSON'
{
    "require": {
        "barryvdh/laravel-debugbar": "^3.8"
    }
}
JSON;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composer,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertArrayHasKey('package', $issues[0]->metadata);
        $this->assertEquals('barryvdh/laravel-debugbar', $issues[0]->metadata['package']);
    }

    public function test_multiple_debug_packages_in_require(): void
    {
        $composer = <<<'JSON'
{
    "require": {
        "barryvdh/laravel-debugbar": "^3.8",
        "laravel/telescope": "^4.0",
        "spatie/laravel-ray": "^1.0"
    }
}
JSON;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composer,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
    }

    // =================================================================
    // shouldRun Tests
    // =================================================================

    public function test_should_run_with_env_file(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_DEBUG=false',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_run_with_config_directory(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/app.php' => '<?php return [];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_run_with_composer_json(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{"require": {}}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_not_run_without_files(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
    }

    // =================================================================
    // Metadata Tests
    // =================================================================

    public function test_all_issues_include_metadata(): void
    {
        $envContent = 'APP_DEBUG=true';
        $appConfig = '<?php return ["debug" => true];';
        $code = '<?php dd($data);';
        $composer = '{"require": {"barryvdh/laravel-debugbar": "^3.8"}}';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'config/app.php' => $appConfig,
            'app/test.php' => $code,
            'composer.json' => $composer,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        foreach ($issues as $issue) {
            $this->assertNotEmpty($issue->metadata, 'All issues should have metadata');
        }
    }

    public function test_metadata_structure_consistency(): void
    {
        $code = '<?php dd($data); ray($test);';

        $tempDir = $this->createTempDirectory([
            'app/test.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        // Both debug function issues should have consistent metadata structure
        foreach ($issues as $issue) {
            $this->assertArrayHasKey('function', $issue->metadata);
            $this->assertArrayHasKey('file', $issue->metadata);
        }
    }
}
