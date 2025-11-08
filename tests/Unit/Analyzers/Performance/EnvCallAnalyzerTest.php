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
}
