<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use ShieldCI\Analyzers\Performance\RouteCachingAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class RouteCachingAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new RouteCachingAnalyzer;
    }

    public function test_warns_when_routes_cached_in_local(): void
    {
        $envContent = 'APP_ENV=local';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'bootstrap/cache/routes-v7.php' => '<?php return [];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('cached in local', $result);
    }

    public function test_fails_when_routes_not_cached_in_production(): void
    {
        $envContent = 'APP_ENV=production';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'bootstrap/cache/.gitkeep' => '',
            'routes/web.php' => '<?php',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not cached', $result);
    }

    public function test_passes_with_routes_cached_in_production(): void
    {
        $envContent = 'APP_ENV=production';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'bootstrap/cache/routes-v7.php' => '<?php return [];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
