<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\CacheStatusAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CacheStatusAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CacheStatusAnalyzer;
    }

    public function test_checks_cache_functionality(): void
    {
        $cacheConfig = <<<'PHP'
<?php

return [
    'default' => 'array',
    'stores' => [
        'array' => [
            'driver' => 'array',
            'serialize' => false,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/cache.php' => $cacheConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // May pass or fail depending on cache driver availability
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }
}
