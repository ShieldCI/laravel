<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use ShieldCI\Analyzers\Performance\ViewCachingAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class ViewCachingAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new ViewCachingAnalyzer;
    }

    public function test_warns_when_views_not_cached_in_production(): void
    {
        $envContent = 'APP_ENV=production';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'resources/views/welcome.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('not cached', $result);
    }

    public function test_passes_with_views_cached(): void
    {
        $envContent = 'APP_ENV=production';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'resources/views/welcome.blade.php' => '<html></html>',
            'bootstrap/cache/views.php' => '<?php return [];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_when_no_views_directory(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
    }
}
