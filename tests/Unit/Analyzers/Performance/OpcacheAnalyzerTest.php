<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use ShieldCI\Analyzers\Performance\OpcacheAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class OpcacheAnalyzerTest extends AnalyzerTestCase
{
    /**
     * Bytes per megabyte. opcache_get_configuration() reports
     * opcache.memory_consumption in bytes, so overrides use byte values.
     */
    private const MB = 1048576;

    protected function createAnalyzer(): AnalyzerInterface
    {
        $analyzer = new class extends OpcacheAnalyzer
        {
            /**
             * @param  array<string, mixed>|null  $configuration
             */
            public function setScenario(bool $extensionLoaded, ?array $configuration): void
            {
                $this->setExtensionLoaded($extensionLoaded);
                $this->setConfiguration($configuration);
            }
        };

        $analyzer->setRelevantEnvironments(null);

        return $analyzer;
    }

    public function test_fails_when_extension_not_loaded(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(false, null);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not loaded', $result);
    }

    public function test_fails_when_opcache_disabled(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => ['opcache.enable' => false],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('OPcache is disabled', $result);
    }

    public function test_warns_on_low_memory_configuration(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.validate_timestamps' => false,
                'opcache.memory_consumption' => 64 * self::MB,
                'opcache.interned_strings_buffer' => 8,
                'opcache.max_accelerated_files' => 5000,
                'opcache.revalidate_freq' => 0,
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('memory', $result);
    }

    public function test_passes_with_optimal_configuration(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.validate_timestamps' => false,
                'opcache.memory_consumption' => 256 * self::MB,
                'opcache.interned_strings_buffer' => 16,
                'opcache.max_accelerated_files' => 20000,
                'opcache.revalidate_freq' => 0,
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // Category 1: Extension Loading Edge Cases

    public function test_checks_zend_opcache_extension_name(): void
    {
        // Tests extension_loaded('Zend OPcache')
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.validate_timestamps' => false,
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_configuration_cannot_be_retrieved(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // Extension not loaded means config can't be retrieved
        // @phpstan-ignore-next-line
        $analyzer->setScenario(false, null);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // When extension is not loaded, we get "not loaded" message, not "unable to retrieve"
        $this->assertHasIssueContaining('not loaded', $result);
    }

    public function test_warns_when_directives_key_missing(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, []); // Missing 'directives' key

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Unable to retrieve', $result);
    }

    public function test_warns_when_directives_is_not_array(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => 'not-an-array',
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Unable to retrieve', $result);
    }

    public function test_passes_when_directives_is_empty(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [],
        ]);

        $result = $analyzer->analyze();

        // Empty directives means opcache.enable is not set, should fail
        $this->assertFailed($result);
        $this->assertHasIssueContaining('disabled', $result);
    }

    // Category 2: validate_timestamps Tests

    public function test_warns_when_validate_timestamps_is_true(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.validate_timestamps' => true, // Suboptimal in production
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('validate_timestamps', $result);
        $issues = $result->getIssues();
        $this->assertEquals(true, $issues[0]->metadata['current_value']);
        $this->assertEquals(0, $issues[0]->metadata['recommended_value']);
    }

    public function test_passes_when_validate_timestamps_is_false(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.validate_timestamps' => false, // Optimal
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_validate_timestamps_is_missing(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                // validate_timestamps not set
            ],
        ]);

        $result = $analyzer->analyze();

        // Missing validate_timestamps doesn't trigger the warning
        $this->assertPassed($result);
    }

    // Category 3: memory_consumption Tests

    public function test_warns_when_memory_consumption_below_minimum(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.memory_consumption' => 64 * self::MB, // Below MIN (128)
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('memory consumption', $result);
        $issues = $result->getIssues();
        $this->assertEquals(64, $issues[0]->metadata['current_value']);
        $this->assertEquals(256, $issues[0]->metadata['recommended_value']);
    }

    public function test_passes_when_memory_consumption_exactly_at_minimum(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.memory_consumption' => 128 * self::MB, // Exactly at MIN
            ],
        ]);

        $result = $analyzer->analyze();

        // Exactly at minimum should pass (>= MIN check)
        $this->assertPassed($result);
    }

    public function test_passes_when_memory_consumption_is_missing(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                // memory_consumption not set
            ],
        ]);

        $result = $analyzer->analyze();

        // Missing setting doesn't trigger warning
        $this->assertPassed($result);
    }

    public function test_ignores_non_numeric_memory_consumption(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.memory_consumption' => 'invalid', // Non-numeric
            ],
        ]);

        $result = $analyzer->analyze();

        // Non-numeric value is ignored
        $this->assertPassed($result);
    }

    public function test_handles_string_numeric_memory_consumption(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.memory_consumption' => (string) (64 * self::MB), // String number (bytes)
            ],
        ]);

        $result = $analyzer->analyze();

        // String "64" should be cast to int and warn
        $this->assertWarning($result);
        $this->assertHasIssueContaining('memory consumption', $result);
    }

    // Category 4: interned_strings_buffer Tests

    public function test_warns_when_interned_strings_buffer_below_minimum(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.interned_strings_buffer' => 8, // Below MIN (16)
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('interned strings buffer', $result);
        $issues = $result->getIssues();
        $this->assertEquals(8, $issues[0]->metadata['current_value']);
        $this->assertEquals(16, $issues[0]->metadata['recommended_value']);
    }

    public function test_passes_when_interned_strings_buffer_exactly_at_minimum(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.interned_strings_buffer' => 16, // Exactly at MIN
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_interned_strings_buffer_is_missing(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                // interned_strings_buffer not set
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_non_numeric_interned_strings_buffer(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.interned_strings_buffer' => 'invalid',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // Category 5: max_accelerated_files Tests

    public function test_warns_when_max_accelerated_files_below_minimum(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.max_accelerated_files' => 5000, // Below MIN (10000)
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('max accelerated files', $result);
        $issues = $result->getIssues();
        $this->assertEquals(5000, $issues[0]->metadata['current_value']);
        $this->assertEquals(20000, $issues[0]->metadata['recommended_value']);
    }

    public function test_passes_when_max_accelerated_files_exactly_at_minimum(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.max_accelerated_files' => 10000, // Exactly at MIN
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_max_accelerated_files_is_missing(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                // max_accelerated_files not set
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_non_numeric_max_accelerated_files(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.max_accelerated_files' => 'invalid',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // Category 6: revalidate_freq Tests

    public function test_warns_when_revalidate_freq_positive_with_validate_timestamps_false(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.validate_timestamps' => false,
                'opcache.revalidate_freq' => 60, // > 0 when validate_timestamps is false
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('revalidate_freq', $result);
        $issues = $result->getIssues();
        $this->assertEquals(60, $issues[0]->metadata['current_value']);
        $this->assertEquals(0, $issues[0]->metadata['recommended_value']);
    }

    public function test_passes_when_revalidate_freq_zero_with_validate_timestamps_false(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.validate_timestamps' => false,
                'opcache.revalidate_freq' => 0, // Optimal
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_warns_when_revalidate_freq_positive_with_validate_timestamps_true(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.validate_timestamps' => true,
                'opcache.revalidate_freq' => 60, // OK when validate_timestamps is true
            ],
        ]);

        $result = $analyzer->analyze();

        // Should only warn about validate_timestamps, not revalidate_freq
        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('validate_timestamps', $issues[0]->message);
    }

    public function test_passes_when_revalidate_freq_is_missing(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                // revalidate_freq not set
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_non_numeric_revalidate_freq(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.validate_timestamps' => false,
                'opcache.revalidate_freq' => 'invalid',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // Category 7: Combined Configuration Scenarios

    public function test_reports_multiple_issues_when_multiple_settings_suboptimal(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.validate_timestamps' => true, // Issue 1
                'opcache.memory_consumption' => 64 * self::MB, // Issue 2
                'opcache.interned_strings_buffer' => 8, // Issue 3
                'opcache.max_accelerated_files' => 5000, // Issue 4
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(4, $issues);
    }

    public function test_reports_single_issue_when_only_one_setting_suboptimal(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.validate_timestamps' => false,
                'opcache.memory_consumption' => 64 * self::MB, // Only this is suboptimal
                'opcache.interned_strings_buffer' => 16,
                'opcache.max_accelerated_files' => 20000,
                'opcache.revalidate_freq' => 0,
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('memory', $issues[0]->message);
    }

    // Category 9: Metadata & Severity Tests

    public function test_extension_not_loaded_has_critical_severity(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(false, null);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    public function test_opcache_disabled_has_high_severity(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => ['opcache.enable' => false],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals(Severity::High, $issues[0]->severity);
    }

    public function test_configuration_issues_have_low_severity(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.memory_consumption' => 64 * self::MB,
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertEquals(Severity::Low, $issues[0]->severity);
    }

    public function test_issue_metadata_contains_php_version(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(false, null);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertArrayHasKey('php_version', $issues[0]->metadata);
        $this->assertEquals(PHP_VERSION, $issues[0]->metadata['php_version']);
    }

    public function test_extension_not_loaded_includes_loaded_extensions_in_metadata(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(false, null);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertArrayHasKey('loaded_extensions', $issues[0]->metadata);
        $this->assertIsArray($issues[0]->metadata['loaded_extensions']);
    }

    public function test_memory_consumption_recommendation_contains_specific_values(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.memory_consumption' => 64 * self::MB,
            ],
        ]);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('128', $recommendation);
        $this->assertStringContainsString('256', $recommendation);
        $this->assertStringContainsString('64', $recommendation);
    }

    // Category 10: Analyzer Metadata Tests

    public function test_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('opcache-enabled', $metadata->id);
        $this->assertEquals('OPcache Enabled Analyzer', $metadata->name);
        $this->assertEquals(Category::Performance, $metadata->category);
        $this->assertEquals(Severity::High, $metadata->severity);
        $this->assertContains('opcache', $metadata->tags);
        $this->assertContains('performance', $metadata->tags);
    }

    public function test_run_in_ci_property_is_false(): void
    {
        $this->assertFalse(OpcacheAnalyzer::$runInCI);
    }

    // Category 11: Comment Detection Bug Fix

    public function test_commented_setting_does_not_report_commented_line(): void
    {
        $tempDir = $this->createTempDirectory([
            'php.ini' => implode("\n", [
                '[opcache]',
                '; opcache.validate_timestamps=1',
                ';opcache.memory_consumption=64',
                '# opcache.max_accelerated_files=5000',
            ]),
        ]);

        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.validate_timestamps' => true,
            ],
        ]);
        $analyzer->setPhpIniPath($tempDir.'/php.ini');

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        // No active (uncommented) line exists, so the issue must NOT be pinned to
        // a line — the commented line is not "active" and line 1 would be misleading.
        $this->assertNotNull($issues[0]->location);
        $this->assertNull($issues[0]->location->line);
        // And no code snippet should be attached when there's no line to point at.
        $this->assertNull($issues[0]->codeSnippet);
    }

    public function test_active_setting_reports_correct_line_number(): void
    {
        $tempDir = $this->createTempDirectory([
            'php.ini' => implode("\n", [
                '[opcache]',
                '; opcache.validate_timestamps=0',
                'opcache.enable=1',
                'opcache.validate_timestamps=1',
                'opcache.memory_consumption=64',
            ]),
        ]);

        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.validate_timestamps' => true,
                'opcache.memory_consumption' => 64 * self::MB,
            ],
        ]);
        $analyzer->setPhpIniPath($tempDir.'/php.ini');

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);

        // memory_consumption is active on line 5 (PHP_INI_SYSTEM — checked first)
        $this->assertNotNull($issues[0]->location);
        $this->assertEquals(5, $issues[0]->location->line);

        // validate_timestamps is active on line 4 (PHP_INI_ALL — checked second)
        $this->assertNotNull($issues[1]->location);
        $this->assertEquals(4, $issues[1]->location->line);
    }

    // Category 12: Vapor / Serverless Support

    public function test_vapor_adjusts_opcache_recommendations(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.memory_consumption' => 64 * self::MB,
            ],
        ]);
        $analyzer->setDeploymentPlatform('vapor');

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $recommendation = $issues[0]->recommendation;
        // Uses relative path, not absolute
        $this->assertStringContainsString('php/conf.d/php.ini', $recommendation);
        $this->assertStringContainsString('Vapor', $recommendation);
        $this->assertStringContainsString('read-only', $recommendation);
        $this->assertStringContainsString('Redeploy', $recommendation);
        // Should NOT contain "restart PHP" — irrelevant on Vapor
        $this->assertStringNotContainsString('restart PHP', $recommendation);
        // Should use relative path, not absolute basePath
        $this->assertNotNull($this->app);
        $this->assertStringNotContainsString($this->app->basePath(), $recommendation);

        $this->assertArrayHasKey('deployment_platform', $issues[0]->metadata);
        $this->assertEquals('vapor', $issues[0]->metadata['deployment_platform']);
    }

    // Category 13: Laravel Cloud / Docker Support

    public function test_skips_all_config_checks_on_laravel_cloud(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.memory_consumption' => 32 * self::MB,          // below MIN — would normally flag
                'opcache.interned_strings_buffer' => 4,       // below MIN — would normally flag
                'opcache.max_accelerated_files' => 1000,      // below MIN — would normally flag
                'opcache.validate_timestamps' => true,        // enabled — would normally flag
                'opcache.revalidate_freq' => 60,              // non-zero — would normally flag
            ],
        ]);
        $analyzer->setDeploymentPlatform('laravel-cloud');

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertCount(0, $result->getIssues());
    }

    public function test_skips_php_ini_system_checks_on_docker_but_keeps_php_ini_all(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.memory_consumption' => 32 * self::MB,          // PHP_INI_SYSTEM — should be suppressed
                'opcache.interned_strings_buffer' => 4,       // PHP_INI_SYSTEM — should be suppressed
                'opcache.max_accelerated_files' => 1000,      // PHP_INI_SYSTEM — should be suppressed
                'opcache.validate_timestamps' => true,        // PHP_INI_ALL — should still flag
            ],
        ]);
        $analyzer->setDeploymentPlatform('docker');

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $issueMessages = array_map(fn ($i) => $i->message, $issues);

        // PHP_INI_SYSTEM settings are suppressed on Docker
        foreach ($issueMessages as $message) {
            $this->assertStringNotContainsString('memory consumption', $message);
            $this->assertStringNotContainsString('interned strings buffer', $message);
            $this->assertStringNotContainsString('max accelerated files', $message);
        }

        // PHP_INI_ALL (validate_timestamps) is still reported on Docker — user controls container build
        $validateIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'validate_timestamps')) {
                $validateIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($validateIssue, 'validate_timestamps should still be reported on Docker');
    }

    public function test_traditional_platform_does_not_mention_vapor(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.memory_consumption' => 64 * self::MB,
            ],
        ]);
        // No setDeploymentPlatform() call — traditional server

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $recommendation = $issues[0]->recommendation;
        $this->assertStringNotContainsString('Vapor', $recommendation);
        $this->assertStringNotContainsString('read-only', $recommendation);
        $this->assertStringNotContainsString('php/conf.d', $recommendation);

        $this->assertArrayNotHasKey('deployment_platform', $issues[0]->metadata);
    }

    // Category 14: conf.d Drop-in Scanning

    public function test_reports_directive_set_in_conf_d_drop_in(): void
    {
        // Common Debian/Ubuntu layout: OPcache is loaded and tuned from a
        // conf.d drop-in, not the main php.ini.
        $tempDir = $this->createTempDirectory([
            'php.ini' => implode("\n", [
                '[opcache]',
                '; opcache is tuned in conf.d',
            ]),
            '10-opcache.ini' => implode("\n", [
                '; configuration for php opcache module',
                'zend_extension=opcache.so',
                'opcache.interned_strings_buffer=8',
            ]),
        ]);

        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.interned_strings_buffer' => 8,
            ],
        ]);
        $analyzer->setPhpIniPath($tempDir.'/php.ini');
        $analyzer->setScannedIniFiles([$tempDir.'/10-opcache.ini']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        // The issue must point at the conf.d drop-in (line 3), not the main php.ini.
        $this->assertNotNull($issues[0]->location);
        $this->assertEquals(3, $issues[0]->location->line);
        $this->assertStringContainsString('10-opcache.ini', $issues[0]->location->file);
    }

    public function test_falls_back_to_php_ini_when_directive_not_in_any_scanned_file(): void
    {
        // OPcache loaded via a drop-in that only loads the extension — no tuning
        // anywhere, so the runtime value is a PHP default with no line to point at.
        $tempDir = $this->createTempDirectory([
            'php.ini' => implode("\n", [
                '[opcache]',
                ';opcache.interned_strings_buffer=8',
            ]),
            '10-opcache.ini' => implode("\n", [
                '; configuration for php opcache module',
                'zend_extension=opcache.so',
                'opcache.jit=off',
            ]),
        ]);

        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.interned_strings_buffer' => 8,
            ],
        ]);
        $analyzer->setPhpIniPath($tempDir.'/php.ini');
        $analyzer->setScannedIniFiles([$tempDir.'/10-opcache.ini']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        // No active line anywhere → fall back to php.ini with no line / snippet.
        $this->assertNotNull($issues[0]->location);
        $this->assertNull($issues[0]->location->line);
        $this->assertStringContainsString('php.ini', $issues[0]->location->file);
        $this->assertNull($issues[0]->codeSnippet);
    }
}
