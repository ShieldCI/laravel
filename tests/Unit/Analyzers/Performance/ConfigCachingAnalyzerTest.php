<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use ShieldCI\Analyzers\Performance\ConfigCachingAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class ConfigCachingAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new ConfigCachingAnalyzer;
    }

    public function test_warns_when_config_cached_in_local(): void
    {
        $envContent = 'APP_ENV=local';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'bootstrap/cache/config.php' => '<?php return [];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('cached in local', $result);
    }

    public function test_warns_when_config_not_cached_in_production(): void
    {
        $envContent = 'APP_ENV=production';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'bootstrap/cache/.gitkeep' => '',
            'config/app.php' => '<?php return [];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('not cached', $result);
    }

    public function test_passes_with_proper_caching_setup(): void
    {
        $envContent = 'APP_ENV=production';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'bootstrap/cache/config.php' => '<?php return [];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
