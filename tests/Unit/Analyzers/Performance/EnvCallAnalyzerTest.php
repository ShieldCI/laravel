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
}
