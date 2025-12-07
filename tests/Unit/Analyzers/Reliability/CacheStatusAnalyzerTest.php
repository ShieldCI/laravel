<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use Illuminate\Support\Facades\Cache;
use RuntimeException;
use ShieldCI\Analyzers\Reliability\CacheStatusAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CacheStatusAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CacheStatusAnalyzer;
    }

    protected function tearDown(): void
    {
        $root = Cache::getFacadeRoot();
        if (is_object($root) && method_exists($root, 'flush')) {
            Cache::flush();
        }

        Cache::clearResolvedInstance('cache');
        parent::tearDown();
    }

    public function test_passes_when_cache_operational(): void
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

        config(['cache.default' => 'array']);
        config(['cache.stores.array.driver' => 'array']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_cache_returns_incorrect_value(): void
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

        config(['cache.default' => 'array']);
        config(['cache.stores.array.driver' => 'array']);

        Cache::shouldReceive('put')->andReturnTrue();
        Cache::shouldReceive('get')->andReturn('wrong');
        Cache::shouldReceive('forget')->andReturnTrue();

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('write/read test failed', $result);
    }

    public function test_fails_when_cache_put_throws_exception(): void
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

        config(['cache.default' => 'array']);
        config(['cache.stores.array.driver' => 'array']);

        Cache::shouldReceive('put')->andThrow(new RuntimeException('Cache offline'));
        Cache::shouldReceive('forget')->andReturnTrue();

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Cache connection/operation failed', $result);
    }

    // =========================================================================
    // Cache Read Failure Tests
    // =========================================================================

    public function test_fails_when_cache_get_throws_exception(): void
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

        config(['cache.default' => 'array']);
        config(['cache.stores.array.driver' => 'array']);

        Cache::shouldReceive('put')->andReturnTrue();
        Cache::shouldReceive('get')->andThrow(new RuntimeException('Connection lost'));
        Cache::shouldReceive('forget')->andReturnTrue();

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Cache connection/operation failed', $result);
    }

    public function test_handles_cache_get_returning_null(): void
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

        config(['cache.default' => 'array']);
        config(['cache.stores.array.driver' => 'array']);

        Cache::shouldReceive('put')->andReturnTrue();
        Cache::shouldReceive('get')->andReturn(null);
        Cache::shouldReceive('forget')->andReturnTrue();

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('write/read test failed', $result);
    }

    public function test_handles_cache_get_returning_false(): void
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

        config(['cache.default' => 'array']);
        config(['cache.stores.array.driver' => 'array']);

        Cache::shouldReceive('put')->andReturnTrue();
        Cache::shouldReceive('get')->andReturn(false);
        Cache::shouldReceive('forget')->andReturnTrue();

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('write/read test failed', $result);
    }

    // =========================================================================
    // Cleanup Failure Tests
    // =========================================================================

    public function test_handles_cleanup_failure_on_success_path(): void
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

        config(['cache.default' => 'array']);
        config(['cache.stores.array.driver' => 'array']);

        $testValue = null;
        Cache::shouldReceive('put')
            ->once()
            ->andReturnUsing(function ($key, $value) use (&$testValue) {
                $testValue = $value;

                return true;
            });

        Cache::shouldReceive('get')
            ->once()
            ->andReturnUsing(function () use (&$testValue) {
                return $testValue;
            });

        Cache::shouldReceive('forget')
            ->once()
            ->andThrow(new RuntimeException('Cleanup failed'));

        $result = $analyzer->analyze();

        // Should still pass because cleanup failure doesn't affect the actual test
        $this->assertPassed($result);
    }

    public function test_handles_cleanup_failure_on_error_path(): void
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

        config(['cache.default' => 'array']);
        config(['cache.stores.array.driver' => 'array']);

        Cache::shouldReceive('put')->andThrow(new RuntimeException('Cache offline'));
        Cache::shouldReceive('forget')->andThrow(new RuntimeException('Cleanup also failed'));

        $result = $analyzer->analyze();

        // Should fail with original cache error, not cleanup error
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Cache connection/operation failed', $result);
    }

    // =========================================================================
    // Configuration Edge Cases
    // =========================================================================

    public function test_handles_missing_cache_config_file(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        config(['cache.default' => 'array']);
        config(['cache.stores.array.driver' => 'array']);

        $result = $analyzer->analyze();

        // Should still run the test even without config file
        $this->assertPassed($result);
    }

    public function test_handles_invalid_cache_driver(): void
    {
        $cacheConfig = <<<'PHP'
<?php

return [
    'default' => null,
    'stores' => [],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/cache.php' => $cacheConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        config(['cache.default' => null]);

        // Should handle gracefully even with invalid config
        $result = $analyzer->analyze();

        // This will likely pass or fail depending on how Laravel handles null driver
        $this->assertNotEquals('error', $result->getStatus()->value);
    }

    // =========================================================================
    // Different Cache Driver Tests
    // =========================================================================

    public function test_works_with_file_driver(): void
    {
        $cacheConfig = <<<'PHP'
<?php

return [
    'default' => 'file',
    'stores' => [
        'file' => [
            'driver' => 'file',
            'path' => storage_path('framework/cache/data'),
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/cache.php' => $cacheConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        config(['cache.default' => 'file']);
        config([
            'cache.stores.file' => [
                'driver' => 'file',
                'path' => $tempDir.'/cache',
            ],
        ]);

        if (! is_dir($tempDir.'/cache')) {
            mkdir($tempDir.'/cache', 0755, true);
        }

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // =========================================================================
    // Error Message Sanitization Tests
    // =========================================================================

    public function test_sanitizes_long_error_messages(): void
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

        config(['cache.default' => 'array']);
        config(['cache.stores.array.driver' => 'array']);

        $longError = str_repeat('This is a very long error message. ', 20);
        Cache::shouldReceive('put')->andThrow(new RuntimeException($longError));
        Cache::shouldReceive('forget')->andReturnTrue();

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        // Error should be truncated in recommendation
        $recommendation = $issues[0]->recommendation;
        $this->assertLessThanOrEqual(500, strlen($recommendation)); // Recommendation shouldn't be too long
        // Verify error was actually truncated (has ...)
        $this->assertStringContainsString('...', $recommendation);
    }

    public function test_handles_empty_error_message(): void
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

        config(['cache.default' => 'array']);
        config(['cache.stores.array.driver' => 'array']);

        Cache::shouldReceive('put')->andThrow(new RuntimeException(''));
        Cache::shouldReceive('forget')->andReturnTrue();

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Cache connection/operation failed', $result);
    }

    // =========================================================================
    // Metadata Validation Tests
    // =========================================================================

    public function test_includes_correct_metadata_on_failure(): void
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

        config(['cache.default' => 'array']);
        config(['cache.stores.array.driver' => 'array']);

        Cache::shouldReceive('put')->andThrow(new RuntimeException('Test error'));
        Cache::shouldReceive('forget')->andReturnTrue();

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $metadata = $issues[0]->metadata;
        $this->assertArrayHasKey('cache_driver', $metadata);
        $this->assertArrayHasKey('exception', $metadata);
        $this->assertArrayHasKey('error', $metadata);
        $this->assertEquals('array', $metadata['cache_driver']);
        $this->assertEquals(RuntimeException::class, $metadata['exception']);
        $this->assertEquals('Test error', $metadata['error']);
    }

    public function test_includes_driver_info_in_metadata(): void
    {
        $cacheConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'stores' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'cache',
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/cache.php' => $cacheConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        config(['cache.default' => 'redis']);
        config(['cache.stores.redis.driver' => 'redis']);

        Cache::shouldReceive('put')->andReturnTrue();
        Cache::shouldReceive('get')->andReturn('wrong_value');
        Cache::shouldReceive('forget')->andReturnTrue();

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $metadata = $issues[0]->metadata;
        $this->assertArrayHasKey('cache_driver', $metadata);
        $this->assertEquals('redis', $metadata['cache_driver']);
    }
}
