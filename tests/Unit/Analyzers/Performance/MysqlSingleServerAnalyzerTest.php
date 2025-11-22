<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Mockery;
use ShieldCI\Analyzers\Performance\MysqlSingleServerAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class MysqlSingleServerAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $configValues
     */
    protected function createAnalyzer(array $configValues = []): AnalyzerInterface
    {
        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        // Set up default config values
        $defaults = [
            'app' => [
                'env' => 'production', // Default to production so tests actually run
            ],
            'database' => [
                'default' => 'mysql',
                'connections' => [
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => '127.0.0.1',
                        'database' => 'laravel',
                    ],
                ],
            ],
        ];

        $configMap = array_replace_recursive($defaults, $configValues);

        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $config->shouldReceive('get')
            ->andReturnUsing(function ($key, $default = null) use ($configMap) {
                // Handle dotted key access (e.g., 'database.connections.mysql.driver')
                $keys = explode('.', $key);
                $value = $configMap;

                foreach ($keys as $segment) {
                    if (is_array($value) && array_key_exists($segment, $value)) {
                        $value = $value[$segment];
                    } else {
                        return $default;
                    }
                }

                return $value ?? $default;
            });

        return new MysqlSingleServerAnalyzer($config);
    }

    public function test_passes_when_using_unix_socket(): void
    {
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => 'mysql',
                'connections' => [
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => 'localhost',
                        'unix_socket' => '/var/run/mysqld/mysqld.sock',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('optimally configured', $result->getMessage());
    }

    public function test_warns_when_using_localhost_without_socket(): void
    {
        $analyzer = $this->createAnalyzer([
            'database' => [
                'connections' => [
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => 'localhost',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Unix socket', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('localhost', $issues[0]->metadata['host'] ?? '');
        $this->assertTrue($issues[0]->metadata['is_default'] ?? false);
    }

    public function test_warns_when_using_127_0_0_1_without_socket(): void
    {
        $analyzer = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => '127.0.0.1',
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Unix socket', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('127.0.0.1', $issues[0]->metadata['host'] ?? '');
    }

    public function test_passes_when_using_remote_host(): void
    {
        $analyzer = $this->createAnalyzer([
            'database' => [
                'connections' => [
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => 'db.example.com',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_using_remote_url_connection(): void
    {
        $analyzer = $this->createAnalyzer([
            'database' => [
                'connections' => [
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => '',
                        'url' => 'mysql://user:pass@db.example.com:3306/database',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_warns_when_url_points_to_localhost_without_socket(): void
    {
        $analyzer = $this->createAnalyzer([
            'database' => [
                'connections' => [
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => '',
                        'url' => 'mysql://user:pass@localhost:3306/database',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Unix socket', $result);
    }

    public function test_checks_multiple_connections(): void
    {
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => 'mysql',
                'connections' => [
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => 'localhost',
                    ],
                    'mysql_read' => [
                        'driver' => 'mysql',
                        'host' => '127.0.0.1',
                    ],
                    'pgsql' => [
                        'driver' => 'pgsql',
                        'host' => 'localhost',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertCount(2, $issues); // mysql and mysql_read, not pgsql

        $connectionNames = array_map(fn ($issue) => $issue->metadata['connection_name'] ?? '', $issues);
        $this->assertContains('mysql', $connectionNames);
        $this->assertContains('mysql_read', $connectionNames);
    }

    public function test_different_severity_for_default_connection(): void
    {
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => 'mysql',
                'connections' => [
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => 'localhost',
                    ],
                    'mysql_read' => [
                        'driver' => 'mysql',
                        'host' => 'localhost',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertCount(2, $issues);

        // Default connection should have Medium severity
        $defaultIssue = collect($issues)->firstWhere(fn ($i) => $i->metadata['is_default'] ?? false);
        $this->assertNotNull($defaultIssue);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $defaultIssue->severity);

        // Non-default connection should have Low severity
        $nonDefaultIssue = collect($issues)->firstWhere(fn ($i) => ! ($i->metadata['is_default'] ?? false));
        $this->assertNotNull($nonDefaultIssue);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Low, $nonDefaultIssue->severity);
    }

    public function test_skips_when_not_using_mysql(): void
    {
        /** @var MysqlSingleServerAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => 'pgsql',
                'connections' => [
                    'pgsql' => [
                        'driver' => 'pgsql',
                    ],
                ],
            ],
        ]);

        $this->assertFalse($analyzer->shouldRun());
        $this->assertStringContainsString('pgsql', $analyzer->getSkipReason());
    }

    public function test_passes_when_empty_socket_is_null(): void
    {
        $analyzer = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => 'localhost',
                    'unix_socket' => null,
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // Null socket should be treated as empty (no socket configured)
        $this->assertWarning($result);
    }

    public function test_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('mysql-single-server-optimization', $metadata->id);
        $this->assertEquals('MySQL Single Server Optimization', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Performance, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $metadata->severity);
        $this->assertContains('mysql', $metadata->tags);
    }

    public function test_run_in_ci_property_is_false(): void
    {
        $this->assertFalse(MysqlSingleServerAnalyzer::$runInCI);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
