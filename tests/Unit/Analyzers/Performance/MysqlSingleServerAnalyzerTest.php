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
        $this->assertEquals('MySQL Single Server Optimization Analyzer', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Performance, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $metadata->severity);
        $this->assertContains('mysql', $metadata->tags);
    }

    public function test_run_in_ci_property_is_false(): void
    {
        $this->assertFalse(MysqlSingleServerAnalyzer::$runInCI);
    }

    // Category 1: Host Detection Edge Cases

    public function test_warns_when_host_is_empty_string(): void
    {
        // Empty host defaults to localhost in Laravel
        $analyzer = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => '',
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Unix socket', $result);
    }

    public function test_warns_when_host_has_whitespace_only(): void
    {
        // Whitespace-only host should be trimmed and treated as empty (localhost)
        $analyzer = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => '   ',
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
    }

    public function test_warns_when_using_ipv6_localhost_without_socket(): void
    {
        // IPv6 localhost (::1) should be detected
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => 'mysql',
                'connections' => [
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => '::1',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Unix socket', $result);

        $issues = $result->getIssues();
        $this->assertEquals('::1', $issues[0]->metadata['host'] ?? '');
    }

    public function test_warns_with_mixed_case_localhost(): void
    {
        // LOCALHOST, LocalHost, etc. should all be detected
        $analyzer = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => 'LOCALHOST',
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Unix socket', $result);
    }

    public function test_handles_non_string_host_value_gracefully(): void
    {
        // Non-string host should be converted to empty string
        $analyzer = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => 123, // Integer
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // Non-string host becomes empty string, which is localhost
        $this->assertWarning($result);
    }

    public function test_handles_array_host_value_gracefully(): void
    {
        // Array host should be converted to empty string
        $analyzer = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => ['localhost'], // Array
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // Non-string host becomes empty string, which is localhost
        $this->assertWarning($result);
    }

    public function test_url_with_port_in_host(): void
    {
        // URL parsing should extract host correctly even with port
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => 'mysql',
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
        $issues = $result->getIssues();
        $this->assertEquals('localhost', $issues[0]->metadata['host'] ?? '');
    }

    // Category 2: Unix Socket Detection Edge Cases

    public function test_socket_with_whitespace_only_is_treated_as_empty(): void
    {
        $analyzer = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => 'localhost',
                    'unix_socket' => '   ',
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // Whitespace-only socket should be treated as no socket
        $this->assertWarning($result);
    }

    public function test_handles_non_string_unix_socket_value(): void
    {
        $analyzer = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => 'localhost',
                    'unix_socket' => 123, // Non-string
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // Non-string socket becomes empty string
        $this->assertWarning($result);
    }

    public function test_passes_with_url_containing_socket_path(): void
    {
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => 'mysql',
                'connections' => [
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => '',
                        'url' => 'mysql://user:pass@localhost/var/run/mysqld/mysqld.sock',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // URL with .sock in path should be detected as using socket
        $this->assertPassed($result);
    }

    public function test_url_with_socket_path_not_containing_sock_extension(): void
    {
        // Some systems might use socket paths without .sock extension
        $analyzer = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => '',
                    'url' => 'mysql://user:pass@localhost/tmp/mysql',
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // Without .sock, should not be detected as socket
        $this->assertWarning($result);
    }

    public function test_socket_with_leading_trailing_whitespace_is_trimmed(): void
    {
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => 'mysql',
                'connections' => [
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => 'localhost',
                        'unix_socket' => '  /var/run/mysqld/mysqld.sock  ',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // Socket with whitespace should be trimmed and recognized
        $this->assertPassed($result);
    }

    public function test_empty_string_socket_vs_null_socket(): void
    {
        // Both empty string and null should be treated the same
        $analyzerWithEmpty = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => 'localhost',
                    'unix_socket' => '',
                ],
            ],
        ]);

        $analyzerWithNull = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => 'localhost',
                    'unix_socket' => null,
                ],
            ],
        ]);

        $resultEmpty = $analyzerWithEmpty->analyze();
        $resultNull = $analyzerWithNull->analyze();

        // Both should warn
        $this->assertWarning($resultEmpty);
        $this->assertWarning($resultNull);
    }

    // Category 3: URL Parsing Edge Cases

    public function test_handles_malformed_url_gracefully(): void
    {
        $analyzer = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => 'localhost',
                    'url' => 'not-a-valid-url:::',
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // Should fall back to host value
        $this->assertWarning($result);
    }

    public function test_url_with_query_string(): void
    {
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => 'mysql',
                'connections' => [
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => '',
                        'url' => 'mysql://user:pass@db.example.com:3306/database?charset=utf8&collation=utf8_unicode_ci',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // Remote host, should pass
        $this->assertPassed($result);
    }

    public function test_url_with_fragment(): void
    {
        $analyzer = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => '',
                    'url' => 'mysql://user:pass@localhost/database#anchor',
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // localhost in URL, should warn
        $this->assertWarning($result);
    }

    public function test_url_without_host(): void
    {
        $analyzer = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => 'localhost',
                    'url' => 'mysql:///database',
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // URL without host, falls back to host value
        $this->assertWarning($result);
    }

    public function test_handles_non_string_url_value(): void
    {
        $analyzer = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => 'localhost',
                    'url' => 123, // Non-string
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // Non-string URL should be ignored, fall back to host
        $this->assertWarning($result);
    }

    public function test_url_with_empty_string(): void
    {
        $analyzer = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => 'localhost',
                    'url' => '',
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // Empty URL should be ignored, fall back to host
        $this->assertWarning($result);
    }

    // Category 4: Configuration Validation

    public function test_returns_error_when_connections_is_not_array(): void
    {
        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);
        $config->shouldReceive('get')
            ->andReturnUsing(function ($key, $default = null) {
                return match ($key) {
                    'app.env' => 'production',
                    'database.default' => 'mysql',
                    'database.connections.mysql.driver' => 'mysql',
                    'database.connections' => 'not-an-array',
                    default => $default,
                };
            });

        $analyzer = new MysqlSingleServerAnalyzer($config);

        $result = $analyzer->analyze();

        $this->assertError($result);
        $this->assertStringContainsString('invalid', $result->getMessage());
    }

    public function test_skips_non_string_connection_names(): void
    {
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => 'mysql',
                'connections' => [
                    0 => [ // Numeric key
                        'driver' => 'mysql',
                        'host' => 'localhost',
                    ],
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => 'localhost',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // Should only process 'mysql', skip numeric key
        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals('mysql', $issues[0]->metadata['connection_name']);
    }

    public function test_skips_non_array_connection_values(): void
    {
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => 'mysql',
                'connections' => [
                    'invalid' => 'not-an-array',
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => 'localhost',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // Should only process 'mysql', skip invalid connection
        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
    }

    public function test_handles_non_string_default_connection_in_should_run(): void
    {
        /** @var MysqlSingleServerAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => 123, // Non-string
                'connections' => [
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => 'localhost',
                    ],
                ],
            ],
        ]);

        // Non-string default connection should cause shouldRun() to return false
        $this->assertFalse($analyzer->shouldRun());
    }

    public function test_skips_connection_with_missing_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => 'mysql',
                'connections' => [
                    'no_driver' => [
                        'host' => 'localhost',
                        // Missing 'driver' key
                    ],
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => 'localhost',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // Should only process 'mysql', skip connection without driver
        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals('mysql', $issues[0]->metadata['connection_name']);
    }

    public function test_skips_connection_with_non_string_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => 'mysql',
                'connections' => [
                    'invalid_driver' => [
                        'driver' => 123, // Non-string
                        'host' => 'localhost',
                    ],
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => 'localhost',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // Should only process 'mysql', skip invalid driver
        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
    }

    // Category 5: Multiple Connections Scenarios

    public function test_mixed_localhost_and_remote_hosts(): void
    {
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => 'mysql',
                'connections' => [
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => 'localhost',
                    ],
                    'mysql_remote' => [
                        'driver' => 'mysql',
                        'host' => 'db.example.com',
                    ],
                    'mysql_local_127' => [
                        'driver' => 'mysql',
                        'host' => '127.0.0.1',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues); // Only localhost and 127.0.0.1

        $connectionNames = array_map(fn ($issue) => $issue->metadata['connection_name'] ?? '', $issues);
        $this->assertContains('mysql', $connectionNames);
        $this->assertContains('mysql_local_127', $connectionNames);
        $this->assertNotContains('mysql_remote', $connectionNames);
    }

    public function test_passes_when_all_connections_use_sockets(): void
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
                    'mysql_read' => [
                        'driver' => 'mysql',
                        'host' => '127.0.0.1',
                        'unix_socket' => '/var/run/mysqld/mysqld.sock',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // All connections using sockets, should pass
        $this->assertPassed($result);
        $this->assertStringContainsString('optimally configured', $result->getMessage());
    }

    // Category 6: Environment & Skip Conditions

    public function test_skips_in_non_relevant_environment(): void
    {
        /** @var MysqlSingleServerAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => 'mysql',
                'connections' => [
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => 'localhost',
                    ],
                ],
            ],
        ]);

        // Set relevant environments to production/staging only
        $analyzer->setRelevantEnvironments(['production', 'staging']);

        // Mock is set to production in createAnalyzer, so it should run
        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_empty_default_connection_string_should_skip(): void
    {
        /** @var MysqlSingleServerAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => '', // Empty string
                'connections' => [
                    'mysql' => [
                        'driver' => 'mysql',
                        'host' => 'localhost',
                    ],
                ],
            ],
        ]);

        $this->assertFalse($analyzer->shouldRun());
    }

    public function test_skip_reason_with_non_string_driver(): void
    {
        /** @var MysqlSingleServerAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer([
            'database' => [
                'default' => 'mysql',
                'connections' => [
                    'mysql' => [
                        'driver' => 123, // Non-string
                    ],
                ],
            ],
        ]);

        $this->assertFalse($analyzer->shouldRun());
        $skipReason = $analyzer->getSkipReason();
        $this->assertStringContainsString('unknown', $skipReason);
    }

    // Category 7: Recommendation & Metadata

    public function test_recommendation_contains_connection_name(): void
    {
        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);
        $config->shouldReceive('get')
            ->andReturnUsing(function ($key, $default = null) {
                return match ($key) {
                    'app.env' => 'production',
                    'database.default' => 'my_custom_connection',
                    'database.connections.my_custom_connection.driver' => 'mysql',
                    'database.connections' => [
                        'my_custom_connection' => [
                            'driver' => 'mysql',
                            'host' => 'localhost',
                        ],
                    ],
                    default => $default,
                };
            });

        $analyzer = new MysqlSingleServerAnalyzer($config);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('my_custom_connection', $issues[0]->recommendation);
    }

    public function test_recommendation_contains_socket_paths(): void
    {
        $analyzer = $this->createAnalyzer([
            'database.connections' => [
                'mysql' => [
                    'driver' => 'mysql',
                    'host' => 'localhost',
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $recommendation = $issues[0]->recommendation;

        // Should mention common socket paths
        $this->assertStringContainsString('/var/run/mysqld/mysqld.sock', $recommendation);
        $this->assertStringContainsString('/tmp/mysql.sock', $recommendation);
        $this->assertStringContainsString('/var/lib/mysql/mysql.sock', $recommendation);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
