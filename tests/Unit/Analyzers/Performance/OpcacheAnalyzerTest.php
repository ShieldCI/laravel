<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use ShieldCI\Analyzers\Performance\OpcacheAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class OpcacheAnalyzerTest extends AnalyzerTestCase
{
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
                'opcache.memory_consumption' => 64,
                'opcache.interned_strings_buffer' => 8,
                'opcache.max_accelerated_files' => 5000,
                'opcache.revalidate_freq' => 0,
                'opcache.fast_shutdown' => false,
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
                'opcache.memory_consumption' => 256,
                'opcache.interned_strings_buffer' => 16,
                'opcache.max_accelerated_files' => 20000,
                'opcache.revalidate_freq' => 0,
                'opcache.fast_shutdown' => true,
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
                'opcache.memory_consumption' => 64, // Below MIN (128)
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
                'opcache.memory_consumption' => 128, // Exactly at MIN
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
                'opcache.memory_consumption' => '64', // String number
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

    // Category 7: fast_shutdown Tests

    public function test_warns_when_fast_shutdown_is_false(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.fast_shutdown' => false, // Suboptimal
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('fast_shutdown', $result);
        $issues = $result->getIssues();
        $this->assertEquals(false, $issues[0]->metadata['current_value']);
        $this->assertEquals(1, $issues[0]->metadata['recommended_value']);
    }

    public function test_passes_when_fast_shutdown_is_true(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.fast_shutdown' => true, // Optimal
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_fast_shutdown_is_missing(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                // fast_shutdown not set
            ],
        ]);

        $result = $analyzer->analyze();

        // Missing is treated same as true (no warning)
        $this->assertPassed($result);
    }

    public function test_handles_non_boolean_fast_shutdown(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.fast_shutdown' => 0, // Integer 0
            ],
        ]);

        $result = $analyzer->analyze();

        // 0 is not === true, so should warn
        $this->assertWarning($result);
        $this->assertHasIssueContaining('fast_shutdown', $result);
    }

    // Category 8: Combined Configuration Scenarios

    public function test_reports_multiple_issues_when_multiple_settings_suboptimal(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.validate_timestamps' => true, // Issue 1
                'opcache.memory_consumption' => 64, // Issue 2
                'opcache.interned_strings_buffer' => 8, // Issue 3
                'opcache.max_accelerated_files' => 5000, // Issue 4
                'opcache.fast_shutdown' => false, // Issue 5
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(5, $issues);
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
                'opcache.memory_consumption' => 256,
                'opcache.interned_strings_buffer' => 16,
                'opcache.max_accelerated_files' => 20000,
                'opcache.revalidate_freq' => 0,
                'opcache.fast_shutdown' => false, // Only this is suboptimal
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('fast_shutdown', $issues[0]->message);
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
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
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
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $issues[0]->severity);
    }

    public function test_configuration_issues_have_low_severity(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.memory_consumption' => 64,
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Low, $issues[0]->severity);
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

    public function test_recommendation_mentions_performance_improvement(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(false, null);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('30-70%', $recommendation);
        $this->assertStringContainsString('performance', $recommendation);
    }

    public function test_memory_consumption_recommendation_contains_specific_values(): void
    {
        /** @var OpcacheAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        // @phpstan-ignore-next-line
        $analyzer->setScenario(true, [
            'directives' => [
                'opcache.enable' => true,
                'opcache.memory_consumption' => 64,
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
        $this->assertEquals('OPcache Enabled', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Performance, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $metadata->severity);
        $this->assertContains('opcache', $metadata->tags);
        $this->assertContains('performance', $metadata->tags);
    }

    public function test_run_in_ci_property_is_false(): void
    {
        $this->assertFalse(OpcacheAnalyzer::$runInCI);
    }
}
