<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use ShieldCI\Analyzers\Performance\SessionDriverAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class SessionDriverAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new SessionDriverAnalyzer;
    }

    public function test_passes_with_redis_driver(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'driver' => 'redis',
    'connection' => 'session',
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_warns_about_file_driver_in_production(): void
    {
        $envContent = 'APP_ENV=production';
        $sessionConfig = <<<'PHP'
<?php

return [
    'driver' => 'file',
    'files' => storage_path('framework/sessions'),
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'config/session.php' => $sessionConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('file', $result);
    }

    public function test_fails_with_array_driver(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'driver' => 'array',
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('array', $result);
    }
}
