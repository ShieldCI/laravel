<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use ShieldCI\Analyzers\Performance\EnvCallAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class EnvCallAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new EnvCallAnalyzer;
    }

    public function test_detects_env_calls_outside_config(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    public function getKey()
    {
        return env('API_KEY');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ApiService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('env()', $result);
    }

    public function test_ignores_env_calls_in_config_files(): void
    {
        $code = <<<'PHP'
<?php

return [
    'api_key' => env('API_KEY', 'default'),
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/api.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_env_static_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Env;

class EnvService
{
    public function getKey()
    {
        return Env::get('API_KEY');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/EnvService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Env::get()', $result);
    }

    public function test_detects_env_static_calls_with_alias(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Env as EnvFacade;

class AliasService
{
    public function getKey()
    {
        return EnvFacade::get('API_KEY');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/AliasService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Env::get()', $result);
    }

    public function test_ignores_env_calls_in_app_tests_directory(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Tests;

class Helper
{
    public function run()
    {
        return env('SHOULD_IGNORE');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Tests/Helper.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_windows_style_paths_are_excluded(): void
    {
        $analyzer = new class extends EnvCallAnalyzer
        {
            public function shouldExclude(string $path): bool
            {
                return $this->shouldExcludeEnvFile($path);
            }
        };

        $this->assertTrue($analyzer->shouldExclude('C:\\project\\config\\app.php'));
        $this->assertTrue($analyzer->shouldExclude('C:\\project\\tests\\Feature\\Example.php'));
    }

    // Critical Untested Cases

    public function test_detects_fully_qualified_env_facade_without_import(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class FullyQualifiedService
{
    public function getKey()
    {
        return \Illuminate\Support\Facades\Env::get('API_KEY');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/FullyQualifiedService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Env::get()', $result);
    }

    public function test_detects_group_use_statements(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\{Config, Env};

class GroupUseService
{
    public function getKey()
    {
        return Env::get('API_KEY');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/GroupUseService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Env::get()', $result);
    }

    public function test_detects_multiple_env_calls_in_same_file(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class MultipleCallsService
{
    public function getKeys()
    {
        $key1 = env('API_KEY');
        $key2 = env('SECRET_KEY');
        $key3 = env('DATABASE_URL');

        return compact('key1', 'key2', 'key3');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/MultipleCallsService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
    }

    public function test_handles_env_with_variable_argument(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class VariableArgService
{
    public function getKey($varName)
    {
        return env($varName);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/VariableArgService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        // Variable argument results in null metadata
        $this->assertArrayHasKey('variable', $issues[0]->metadata);
        $this->assertNull($issues[0]->metadata['variable']);
    }

    public function test_handles_env_with_second_parameter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DefaultValueService
{
    public function getKey()
    {
        return env('API_KEY', 'default_value');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/DefaultValueService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('API_KEY', $issues[0]->metadata['variable'] ?? '');
    }

    public function test_handles_env_with_constant_argument(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ConstantArgService
{
    const MY_KEY = 'API_KEY';

    public function getKey()
    {
        return env(self::MY_KEY);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ConstantArgService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('env()', $result);
    }

    public function test_detects_nested_env_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class NestedCallService
{
    public function getKey()
    {
        return strtolower(env('API_KEY'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/NestedCallService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('env()', $result);
    }

    public function test_detects_env_in_controller(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ApiController
{
    public function index()
    {
        $key = env('API_KEY');
        return response()->json(['key' => $key]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ApiController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('controller', $issues[0]->metadata['file_type'] ?? '');
    }

    public function test_detects_env_in_model(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

class User
{
    public function getApiKey()
    {
        return env('USER_API_KEY');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('model', $issues[0]->metadata['file_type'] ?? '');
    }

    public function test_detects_env_in_middleware(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Middleware;

class ApiMiddleware
{
    public function handle($request, $next)
    {
        if (env('API_ENABLED') === 'true') {
            return $next($request);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/ApiMiddleware.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('env()', $result);
    }

    public function test_detects_env_in_blade_view(): void
    {
        $code = <<<'PHP'
<?php echo env('APP_NAME'); ?>
PHP;

        $tempDir = $this->createTempDirectory([
            'resources/views/welcome.blade.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources/views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('env()', $result);
    }

    public function test_detects_env_in_route_file(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return env('APP_NAME');
});
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('env()', $result);
    }

    public function test_handles_files_with_parse_errors_gracefully(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class BrokenService
{
    public function broken(
        // Missing closing brace
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/BrokenService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass (no valid env calls detected, parse error skipped)
        $this->assertPassed($result);
    }

    public function test_passes_when_no_php_files_exist(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/.gitkeep' => '',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_mixed_env_and_static_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Env;

class MixedCallsService
{
    public function getKeys()
    {
        $key1 = env('API_KEY');
        $key2 = Env::get('SECRET_KEY');

        return compact('key1', 'key2');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/MixedCallsService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);

        $functions = array_map(fn ($issue) => $issue->metadata['function'] ?? '', $issues);
        $this->assertContains('env', $functions);
        $this->assertContains('Env::get', $functions);
    }

    public function test_only_matches_env_get_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Env;

class EnvMethodsService
{
    public function test()
    {
        Env::get('KEY'); // Should detect
        // Env::set() doesn't exist in Laravel, but if it did, shouldn't match
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/EnvMethodsService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues); // Only Env::get()
    }

    public function test_env_in_closure(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ClosureService
{
    public function process()
    {
        return collect([1, 2, 3])->map(function ($item) {
            return env('MULTIPLIER') * $item;
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ClosureService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('env()', $result);
    }

    public function test_env_in_array_values(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ArrayService
{
    public function getConfig()
    {
        return [
            'api_key' => env('API_KEY'),
            'secret' => env('SECRET'),
        ];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ArrayService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
    }

    public function test_env_with_different_variable_patterns(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class VariablePatternService
{
    public function getKeys()
    {
        $debug = env('APP_DEBUG');
        $url = env('DATABASE_URL');
        $mailer = env('MAIL_MAILER');

        return compact('debug', 'url', 'mailer');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/VariablePatternService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(3, $issues);

        $variables = array_map(fn ($issue) => $issue->metadata['variable'] ?? '', $issues);
        $this->assertContains('APP_DEBUG', $variables);
        $this->assertContains('DATABASE_URL', $variables);
        $this->assertContains('MAIL_MAILER', $variables);
    }

    public function test_excludes_config_directory_with_trailing_slash(): void
    {
        $code = <<<'PHP'
<?php

return [
    'key' => env('API_KEY'),
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/api.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['config']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_nonexistent_search_paths(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/.gitkeep' => '',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['nonexistent', 'also-missing']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_recommendation_contains_config_alternative(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class RecommendationService
{
    public function getKey()
    {
        return env('API_KEY');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/RecommendationService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $recommendation = $issues[0]->recommendation;
        // ConfigSuggester formats as: config('custom.api_key')
        $this->assertStringContainsString("config('", $recommendation);
    }

    public function test_metadata_includes_all_fields(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class MetadataController
{
    public function index()
    {
        return env('APP_NAME');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/MetadataController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $metadata = $issues[0]->metadata;
        $this->assertArrayHasKey('function', $metadata);
        $this->assertArrayHasKey('variable', $metadata);
        $this->assertArrayHasKey('file_type', $metadata);
        $this->assertEquals('env', $metadata['function']);
        $this->assertEquals('APP_NAME', $metadata['variable']);
    }

    public function test_issue_count_matches_message(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CountService
{
    public function getKeys()
    {
        return [
            env('KEY1'),
            env('KEY2'),
            env('KEY3'),
        ];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/CountService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
        $this->assertStringContainsString('Found 3 env()', $result->getMessage());
    }

    public function test_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('env-call-outside-config', $metadata->id);
        $this->assertEquals('Env Calls Outside Config', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Performance, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $metadata->severity);
        $this->assertContains('configuration', $metadata->tags);
        $this->assertContains('env', $metadata->tags);
    }

    public function test_detects_env_with_numeric_argument(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class NumericArgService
{
    public function getKey()
    {
        return env(123); // Edge case
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/NumericArgService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('env()', $result);
    }

    public function test_handles_env_static_call_with_numeric_argument(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Env;

class NumericStaticService
{
    public function getKey()
    {
        return Env::get(456);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/NumericStaticService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        // Numeric arguments are converted to null (only strings are kept)
        $this->assertArrayHasKey('variable', $issues[0]->metadata);
        $this->assertNull($issues[0]->metadata['variable']);
    }

    public function test_ignores_tests_directory_with_capital_t(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Tests\Unit;

class UnitTest
{
    public function test_something()
    {
        $value = env('TEST_VALUE');
        $this->assertNotNull($value);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Tests/Unit/UnitTest.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_issue_has_correct_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class SeverityService
{
    public function getKey()
    {
        return env('API_KEY');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/SeverityService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $issues[0]->severity);
    }
}
