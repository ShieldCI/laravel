<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Commands;

use Mockery;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\AnalyzerManager;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Enums\Status;
use ShieldCI\AnalyzersCore\Results\AnalysisResult;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\Tests\TestCase;

/**
 * @phpstan-type TestAnalyzerMock MockInterface&AnalyzerInterface
 */
class AnalyzeCommandTest extends TestCase
{
    protected function tearDown(): void
    {
        $this->cleanupTempPaths();
        Mockery::close();
        parent::tearDown();
    }

    #[Test]
    public function it_runs_all_analyzers_by_default(): void
    {
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_runs_specific_analyzer_by_id(): void
    {
        $this->registerTestAnalyzers();

        $output = $this->artisan('shield:analyze', [
            '--analyzer' => 'test-security-analyzer',
            '--format' => 'json',
        ]);

        $output->assertSuccessful();
    }

    #[Test]
    public function it_runs_multiple_analyzers_by_comma_separated_ids(): void
    {
        $this->registerTestAnalyzers();

        $output = $this->artisan('shield:analyze', [
            '--analyzer' => 'test-security-analyzer,test-performance-analyzer',
            '--format' => 'json',
        ]);

        $output->assertSuccessful();
    }

    #[Test]
    public function it_rejects_invalid_analyzer_id(): void
    {
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', [
            '--analyzer' => 'non-existent-analyzer',
        ])->assertFailed();
    }

    #[Test]
    public function it_runs_analyzers_by_category(): void
    {
        $this->registerTestAnalyzers();

        $output = $this->artisan('shield:analyze', [
            '--category' => 'security',
            '--format' => 'json',
        ]);

        $output->assertSuccessful();
    }

    #[Test]
    public function it_rejects_invalid_category(): void
    {
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', [
            '--category' => 'invalid-category',
        ])->assertFailed();
    }

    #[Test]
    public function it_outputs_json_format(): void
    {
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('"summary"');
    }

    #[Test]
    public function it_outputs_console_format(): void
    {
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'console'])
            ->assertSuccessful()
            ->expectsOutputToContain('ShieldCI');
    }

    #[Test]
    public function it_rejects_invalid_format(): void
    {
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', [
            '--format' => 'xml',
        ])->assertFailed();
    }

    #[Test]
    public function it_requires_json_extension_for_output_file(): void
    {
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', [
            '--output' => 'report.txt',
        ])->assertFailed();
    }

    #[Test]
    public function it_rejects_path_traversal_in_output(): void
    {
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', [
            '--output' => '../outside/report.json',
        ])->assertFailed();
    }

    #[Test]
    public function it_rejects_absolute_paths_in_output(): void
    {
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', [
            '--output' => '/etc/report.json',
        ])->assertFailed();
    }

    #[Test]
    public function it_rejects_protected_files_in_output(): void
    {
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', [
            '--output' => 'composer.json',
        ])->assertFailed();

        $this->artisan('shield:analyze', [
            '--output' => 'package.json',
        ])->assertFailed();
    }

    #[Test]
    public function it_saves_report_to_file(): void
    {
        $this->registerTestAnalyzers();

        // Use a path that exists (tests directory)
        $outputPath = base_path('tests/shieldci-test-report.json');

        // Clean up before test
        if (file_exists($outputPath)) {
            unlink($outputPath);
        }

        $this->artisan('shield:analyze', [
            '--format' => 'json',
            '--output' => 'tests/shieldci-test-report.json',
        ])->assertSuccessful();

        // Clean up after test
        if (file_exists($outputPath)) {
            unlink($outputPath);
        }
    }

    #[Test]
    public function it_respects_enabled_config(): void
    {
        config(['shieldci.enabled' => false]);

        $this->artisan('shield:analyze')
            ->assertSuccessful()
            ->expectsOutputToContain('disabled');
    }

    #[Test]
    public function it_warns_about_baseline_without_file(): void
    {
        $this->registerTestAnalyzers();
        config(['shieldci.baseline_file' => '/non/existent/baseline.json']);

        $this->artisan('shield:analyze', ['--baseline' => true, '--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('baseline');
    }

    #[Test]
    public function it_validates_ignore_errors_config(): void
    {
        $this->registerTestAnalyzers();

        // Set invalid ignore_errors config
        config(['shieldci.ignore_errors' => [
            'invalid-analyzer-id' => [
                ['path' => 'test.php'],
            ],
        ]]);

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_exits_with_failure_on_disabled_categories(): void
    {
        config(['shieldci.analyzers' => [
            'security' => ['enabled' => false],
            'performance' => ['enabled' => false],
            'reliability' => ['enabled' => false],
            'code_quality' => ['enabled' => false],
            'best_practices' => ['enabled' => false],
        ]]);

        $this->artisan('shield:analyze')
            ->assertFailed()
            ->expectsOutputToContain('disabled');
    }

    #[Test]
    public function it_fails_when_disabled_category_is_requested(): void
    {
        $this->registerTestAnalyzers();

        config(['shieldci.analyzers' => [
            'security' => ['enabled' => false],
        ]]);

        $this->artisan('shield:analyze', [
            '--category' => 'security',
        ])->assertFailed();
    }

    #[Test]
    public function it_runs_in_console_streaming_mode_by_default(): void
    {
        $this->registerTestAnalyzers();

        // Default format is 'console', which triggers streaming mode
        $this->artisan('shield:analyze')
            ->assertSuccessful()
            ->expectsOutputToContain('ShieldCI');
    }

    #[Test]
    public function it_shows_failed_analyzer_details_in_console(): void
    {
        config(['shieldci.fail_on' => 'never']);
        $this->registerFailedAnalyzers();

        $this->artisan('shield:analyze')
            ->assertSuccessful()
            ->expectsOutputToContain('Report Card');
    }

    #[Test]
    public function it_shows_report_card_in_streaming_mode(): void
    {
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'console'])
            ->assertSuccessful()
            ->expectsOutputToContain('Report Card');
    }

    #[Test]
    public function it_fails_when_critical_issues_found_and_fail_on_high(): void
    {
        config(['shieldci.fail_on' => 'high']);
        $this->registerFailedAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertFailed();
    }

    #[Test]
    public function it_succeeds_when_fail_on_is_never(): void
    {
        config(['shieldci.fail_on' => 'never']);
        $this->registerFailedAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_fails_when_score_below_threshold(): void
    {
        config(['shieldci.fail_threshold' => 100]);
        $this->registerFailedAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertFailed();
    }

    #[Test]
    public function it_applies_memory_limit_from_config(): void
    {
        config(['shieldci.memory_limit' => '512M']);
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_applies_timeout_from_config(): void
    {
        config(['shieldci.timeout' => 300]);
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_saves_report_using_config_output_file(): void
    {
        $this->registerTestAnalyzers();
        $outputPath = base_path('tests/shieldci-config-output.json');

        config(['shieldci.report.output_file' => $outputPath]);

        if (file_exists($outputPath)) {
            unlink($outputPath);
        }

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();

        if (file_exists($outputPath)) {
            unlink($outputPath);
        }
    }

    #[Test]
    public function it_fails_on_low_severity_when_fail_on_is_low(): void
    {
        config(['shieldci.fail_on' => 'low']);
        $this->registerFailedAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertFailed();
    }

    #[Test]
    public function it_handles_dont_report_config(): void
    {
        config(['shieldci.dont_report' => ['test-security-failed']]);
        $this->registerFailedAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_filters_issues_with_ignore_errors_config(): void
    {
        config(['shieldci.ignore_errors' => [
            'test-security-failed' => [
                ['path' => '/app/Vulnerable.php'],
            ],
        ]]);
        $this->registerFailedAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_warns_about_invalid_ignore_errors_config(): void
    {
        config(['shieldci.ignore_errors' => [
            'non-existent-analyzer' => [
                ['path' => 'test.php'],
            ],
        ]]);
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('Configuration Warnings');
    }

    #[Test]
    public function it_filters_issues_with_ignore_errors_path_pattern(): void
    {
        config([
            'shieldci.fail_on' => 'never',
            'shieldci.ignore_errors' => [
                'test-security-failed' => [
                    ['path_pattern' => '*/Vulnerable*'],
                ],
            ],
        ]);
        $this->registerFailedAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_filters_issues_with_ignore_errors_message_pattern(): void
    {
        config([
            'shieldci.fail_on' => 'never',
            'shieldci.ignore_errors' => [
                'test-security-failed' => [
                    ['message_pattern' => '*SQL Injection*'],
                ],
            ],
        ]);
        $this->registerFailedAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_filters_issues_with_ignore_errors_exact_message(): void
    {
        config([
            'shieldci.fail_on' => 'never',
            'shieldci.ignore_errors' => [
                'test-security-failed' => [
                    ['message' => 'SQL Injection vulnerability'],
                ],
            ],
        ]);
        $this->registerFailedAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_filters_issues_with_ignore_errors_path_and_message(): void
    {
        config([
            'shieldci.fail_on' => 'never',
            'shieldci.ignore_errors' => [
                'test-security-failed' => [
                    [
                        'path' => '/app/Vulnerable.php',
                        'message' => 'SQL Injection vulnerability',
                    ],
                ],
            ],
        ]);
        $this->registerFailedAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_does_not_filter_when_path_does_not_match(): void
    {
        config([
            'shieldci.fail_on' => 'high',
            'shieldci.ignore_errors' => [
                'test-security-failed' => [
                    ['path' => '/app/NotVulnerable.php'],
                ],
            ],
        ]);
        $this->registerFailedAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertFailed();
    }

    #[Test]
    public function it_filters_against_baseline_with_hash_matching(): void
    {
        $this->registerFailedAnalyzers();

        // Create a baseline file with hash matching
        $baselinePath = base_path('tests/test-baseline.json');
        $issueHash = hash('sha256', json_encode([
            'file' => '/app/Vulnerable.php',
            'line' => 42,
            'message' => 'SQL Injection vulnerability',
        ]) ?: '');

        $baseline = [
            'generated_at' => '2024-01-01T00:00:00Z',
            'version' => '1.0.0',
            'errors' => [
                'test-security-failed' => [
                    ['hash' => $issueHash],
                ],
            ],
        ];

        file_put_contents($baselinePath, json_encode($baseline));
        config([
            'shieldci.baseline_file' => $baselinePath,
            'shieldci.fail_on' => 'high',
        ]);

        $this->artisan('shield:analyze', ['--baseline' => true, '--format' => 'json'])
            ->assertSuccessful();

        @unlink($baselinePath);
    }

    #[Test]
    public function it_filters_against_baseline_with_pattern_matching(): void
    {
        $this->registerFailedAnalyzers();

        $baselinePath = base_path('tests/test-baseline-pattern.json');
        $baseline = [
            'generated_at' => '2024-01-01T00:00:00Z',
            'version' => '1.0.0',
            'errors' => [
                'test-security-failed' => [
                    [
                        'type' => 'pattern',
                        'path_pattern' => '*/Vulnerable*',
                        'message_pattern' => '*SQL*',
                    ],
                ],
            ],
        ];

        file_put_contents($baselinePath, json_encode($baseline));
        config([
            'shieldci.baseline_file' => $baselinePath,
            'shieldci.fail_on' => 'high',
        ]);

        $this->artisan('shield:analyze', ['--baseline' => true, '--format' => 'json'])
            ->assertSuccessful();

        @unlink($baselinePath);
    }

    #[Test]
    public function it_filters_against_baseline_with_exact_path_and_message(): void
    {
        $this->registerFailedAnalyzers();

        $baselinePath = base_path('tests/test-baseline-exact.json');
        $baseline = [
            'generated_at' => '2024-01-01T00:00:00Z',
            'version' => '1.0.0',
            'errors' => [
                'test-security-failed' => [
                    [
                        'type' => 'pattern',
                        'path' => '/app/Vulnerable.php',
                        'message' => 'SQL Injection vulnerability',
                    ],
                ],
            ],
        ];

        file_put_contents($baselinePath, json_encode($baseline));
        config([
            'shieldci.baseline_file' => $baselinePath,
            'shieldci.fail_on' => 'high',
        ]);

        $this->artisan('shield:analyze', ['--baseline' => true, '--format' => 'json'])
            ->assertSuccessful();

        @unlink($baselinePath);
    }

    #[Test]
    public function it_warns_about_invalid_baseline_structure(): void
    {
        $this->registerFailedAnalyzers();

        $baselinePath = base_path('tests/test-baseline-invalid.json');
        file_put_contents($baselinePath, json_encode(['invalid' => 'structure']));
        config([
            'shieldci.baseline_file' => $baselinePath,
            'shieldci.fail_on' => 'never',
        ]);

        $this->artisan('shield:analyze', ['--baseline' => true, '--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('baseline');

        @unlink($baselinePath);
    }

    #[Test]
    public function it_handles_baseline_dont_report(): void
    {
        $this->registerFailedAnalyzers();

        $baselinePath = base_path('tests/test-baseline-dont-report.json');
        $baseline = [
            'generated_at' => '2024-01-01T00:00:00Z',
            'version' => '1.0.0',
            'errors' => [],
            'dont_report' => ['test-security-failed'],
        ];

        file_put_contents($baselinePath, json_encode($baseline));
        config([
            'shieldci.baseline_file' => $baselinePath,
            'shieldci.fail_on' => 'high',
        ]);

        $this->artisan('shield:analyze', ['--baseline' => true, '--format' => 'json'])
            ->assertSuccessful();

        @unlink($baselinePath);
    }

    #[Test]
    public function it_fails_on_medium_severity_when_fail_on_medium(): void
    {
        config(['shieldci.fail_on' => 'medium']);
        $this->registerFailedAnalyzersWithSeverity(Severity::Medium);

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertFailed();
    }

    #[Test]
    public function it_fails_on_critical_severity_when_fail_on_critical(): void
    {
        config(['shieldci.fail_on' => 'critical']);
        $this->registerFailedAnalyzersWithSeverity(Severity::Critical);

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertFailed();
    }

    #[Test]
    public function it_succeeds_on_medium_severity_when_fail_on_critical(): void
    {
        config(['shieldci.fail_on' => 'critical']);
        $this->registerFailedAnalyzersWithSeverity(Severity::Medium);

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_succeeds_on_low_severity_when_fail_on_high(): void
    {
        config(['shieldci.fail_on' => 'high']);
        $this->registerFailedAnalyzersWithSeverity(Severity::Low);

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_runs_specific_analyzer_in_streaming_mode(): void
    {
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', [
            '--analyzer' => 'test-security-analyzer',
            '--format' => 'console',
        ])->assertSuccessful()
            ->expectsOutputToContain('Running analyzer');
    }

    #[Test]
    public function it_runs_multiple_analyzers_in_streaming_mode(): void
    {
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', [
            '--analyzer' => 'test-security-analyzer,test-performance-analyzer',
            '--format' => 'console',
        ])->assertSuccessful()
            ->expectsOutputToContain('Running analyzers');
    }

    #[Test]
    public function it_runs_category_filter_in_json_mode(): void
    {
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', [
            '--category' => 'security',
            '--format' => 'json',
        ])->assertSuccessful();
    }

    #[Test]
    public function it_validates_ignore_errors_with_conflicting_path_keys(): void
    {
        config(['shieldci.ignore_errors' => [
            'test-security-analyzer' => [
                ['path' => 'test.php', 'path_pattern' => '*.php'],
            ],
        ]]);
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('Conflicting');
    }

    #[Test]
    public function it_validates_ignore_errors_with_conflicting_message_keys(): void
    {
        config(['shieldci.ignore_errors' => [
            'test-security-analyzer' => [
                ['message' => 'test', 'message_pattern' => '*test*'],
            ],
        ]]);
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('Conflicting');
    }

    #[Test]
    public function it_validates_ignore_errors_with_empty_rules(): void
    {
        config(['shieldci.ignore_errors' => [
            'test-security-analyzer' => [],
        ]]);
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('Empty rules');
    }

    #[Test]
    public function it_validates_ignore_errors_with_invalid_keys(): void
    {
        config(['shieldci.ignore_errors' => [
            'test-security-analyzer' => [
                ['invalid_key' => 'value', 'path' => 'test.php'],
            ],
        ]]);
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('Invalid keys');
    }

    #[Test]
    public function it_partially_filters_ignore_errors_in_json_mode(): void
    {
        // Register analyzer with 2 issues, only 1 is filtered
        config([
            'shieldci.fail_on' => 'never',
            'shieldci.ignore_errors' => [
                'test-multi-issues' => [
                    ['path' => '/app/Vulnerable.php'],
                ],
            ],
        ]);
        $this->registerMultiIssueAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_partially_filters_ignore_errors_in_streaming_mode(): void
    {
        // Streaming mode uses filterSingleResultAgainstIgnoreErrors
        config([
            'shieldci.fail_on' => 'never',
            'shieldci.ignore_errors' => [
                'test-multi-issues' => [
                    ['path' => '/app/Vulnerable.php'],
                ],
            ],
        ]);
        $this->registerMultiIssueAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'console'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_partially_filters_baseline_issues(): void
    {
        // Register analyzer with 2 issues, baseline matches only 1
        $this->registerMultiIssueAnalyzers();

        $baselinePath = base_path('tests/test-baseline-partial.json');
        $issueHash = hash('sha256', json_encode([
            'file' => '/app/Vulnerable.php',
            'line' => 42,
            'message' => 'SQL Injection vulnerability',
        ]) ?: '');

        $baseline = [
            'generated_at' => '2024-01-01T00:00:00Z',
            'version' => '1.0.0',
            'errors' => [
                'test-multi-issues' => [
                    ['hash' => $issueHash],
                ],
            ],
        ];

        file_put_contents($baselinePath, json_encode($baseline));
        config([
            'shieldci.baseline_file' => $baselinePath,
            'shieldci.fail_on' => 'never',
        ]);

        $this->artisan('shield:analyze', ['--baseline' => true, '--format' => 'json'])
            ->assertSuccessful();

        @unlink($baselinePath);
    }

    #[Test]
    public function it_handles_singular_grammar_fix_in_partial_filter(): void
    {
        // 2 issues in message "Found 2 security issues", one gets filtered to "Found 1 security issue"
        config([
            'shieldci.fail_on' => 'never',
            'shieldci.ignore_errors' => [
                'test-multi-issues' => [
                    ['path' => '/app/Vulnerable.php'],
                ],
            ],
        ]);
        $this->registerMultiIssueAnalyzers('Found 2 security issues');

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_filters_with_ignore_errors_recommendation_matching(): void
    {
        config([
            'shieldci.fail_on' => 'never',
            'shieldci.ignore_errors' => [
                'test-security-failed' => [
                    ['message_pattern' => '*prepared statements*'],
                ],
            ],
        ]);
        $this->registerFailedAnalyzers();

        // The recommendation "Use prepared statements" should match
        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_validates_ignore_errors_with_invalid_glob_pattern(): void
    {
        config(['shieldci.ignore_errors' => [
            'test-security-analyzer' => [
                ['path_pattern' => '**test'],
            ],
        ]]);
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('Invalid glob pattern');
    }

    #[Test]
    public function it_validates_ignore_errors_with_empty_rule(): void
    {
        config(['shieldci.ignore_errors' => [
            'test-security-analyzer' => [
                [],
            ],
        ]]);
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('Empty rule');
    }

    #[Test]
    public function it_validates_ignore_errors_with_non_array_rules(): void
    {
        config(['shieldci.ignore_errors' => [
            'test-security-analyzer' => 'invalid',
        ]]);
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('expected array');
    }

    #[Test]
    public function it_validates_ignore_errors_with_non_array_rule(): void
    {
        config(['shieldci.ignore_errors' => [
            'test-security-analyzer' => [
                'not-an-array',
            ],
        ]]);
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('expected array');
    }

    #[Test]
    public function it_warns_about_baseline_with_invalid_errors_field(): void
    {
        $this->registerFailedAnalyzers();

        $baselinePath = base_path('tests/test-baseline-bad-errors.json');
        $baseline = [
            'generated_at' => '2024-01-01T00:00:00Z',
            'version' => '1.0.0',
            'errors' => 'not-an-array',
        ];
        file_put_contents($baselinePath, json_encode($baseline));
        config([
            'shieldci.baseline_file' => $baselinePath,
            'shieldci.fail_on' => 'never',
        ]);

        $this->artisan('shield:analyze', ['--baseline' => true, '--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('errors');

        @unlink($baselinePath);
    }

    #[Test]
    public function it_fails_on_warnings_with_low_fail_on(): void
    {
        config(['shieldci.fail_on' => 'low']);
        $this->registerWarningAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertFailed();
    }

    #[Test]
    public function it_succeeds_on_warnings_with_high_fail_on(): void
    {
        config(['shieldci.fail_on' => 'high']);
        $this->registerWarningAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_fails_on_warnings_with_medium_severity_and_medium_fail_on(): void
    {
        config(['shieldci.fail_on' => 'medium']);
        $this->registerWarningAnalyzersWithSeverity(Severity::Medium);

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertFailed();
    }

    #[Test]
    public function it_succeeds_on_low_warnings_with_medium_fail_on(): void
    {
        config(['shieldci.fail_on' => 'medium']);
        $this->registerWarningAnalyzers(); // Low severity

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_handles_baseline_dont_report_in_exit_code(): void
    {
        config(['shieldci.fail_on' => 'medium']);
        $this->registerFailedAnalyzersWithSeverity(Severity::Medium);

        $baselinePath = base_path('tests/test-baseline-dont-report-exit.json');
        $baseline = [
            'generated_at' => '2024-01-01T00:00:00Z',
            'version' => '1.0.0',
            'errors' => [],
            'dont_report' => ['test-severity-failed'],
        ];

        file_put_contents($baselinePath, json_encode($baseline));
        config(['shieldci.baseline_file' => $baselinePath]);

        $this->artisan('shield:analyze', ['--baseline' => true, '--format' => 'json'])
            ->assertSuccessful();

        @unlink($baselinePath);
    }

    #[Test]
    public function it_validates_empty_string_analyzer_option(): void
    {
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', [
            '--analyzer' => ',',
        ])->assertFailed();
    }

    #[Test]
    public function it_handles_skipped_analyzers_in_streaming_mode(): void
    {
        config(['shieldci.fail_on' => 'never']);
        $this->registerAnalyzersWithSkipped();

        $this->artisan('shield:analyze')
            ->assertSuccessful()
            ->expectsOutputToContain('skipped');
    }

    #[Test]
    public function it_handles_skipped_analyzers_in_json_mode(): void
    {
        config(['shieldci.fail_on' => 'never']);
        $this->registerAnalyzersWithSkipped();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_handles_skipped_analyzers_with_category_filter_in_json(): void
    {
        config(['shieldci.fail_on' => 'never']);
        $this->registerAnalyzersWithSkipped();

        $this->artisan('shield:analyze', ['--category' => 'security', '--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_handles_skipped_analyzers_with_category_in_streaming(): void
    {
        config(['shieldci.fail_on' => 'never']);
        $this->registerAnalyzersWithSkipped();

        $this->artisan('shield:analyze', ['--category' => 'security'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_saves_report_in_console_format(): void
    {
        $this->registerTestAnalyzers();

        $outputPath = base_path('tests/shieldci-console-report.json');
        if (file_exists($outputPath)) {
            unlink($outputPath);
        }

        $this->artisan('shield:analyze', [
            '--format' => 'console',
            '--output' => 'tests/shieldci-console-report.json',
        ])->assertSuccessful();

        if (file_exists($outputPath)) {
            unlink($outputPath);
        }
    }

    #[Test]
    public function it_validates_null_baseline(): void
    {
        $this->registerFailedAnalyzers();

        $baselinePath = base_path('tests/test-baseline-null.json');
        file_put_contents($baselinePath, 'null');
        config([
            'shieldci.baseline_file' => $baselinePath,
            'shieldci.fail_on' => 'never',
        ]);

        $this->artisan('shield:analyze', ['--baseline' => true, '--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('baseline');

        @unlink($baselinePath);
    }

    #[Test]
    public function it_fully_filters_all_issues_via_ignore_errors_in_streaming_mode(): void
    {
        // When ALL issues match ignore_errors, status becomes Passed and message changes
        config([
            'shieldci.fail_on' => 'never',
            'shieldci.ignore_errors' => [
                'test-multi-issues' => [
                    ['path' => '/app/Vulnerable.php'],
                    ['path' => '/app/Other.php'],
                ],
            ],
        ]);
        $this->registerMultiIssueAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'console'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_skips_ignore_errors_for_analyzer_not_in_config(): void
    {
        // ignore_errors config exists but for a different analyzer ID
        config([
            'shieldci.fail_on' => 'never',
            'shieldci.ignore_errors' => [
                'some-other-analyzer' => [
                    ['path' => '/app/Something.php'],
                ],
            ],
        ]);
        $this->registerFailedAnalyzers();

        // test-security-failed is NOT in ignore_errors, so line 953 is hit
        $this->artisan('shield:analyze', ['--format' => 'console'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_fully_filters_all_issues_via_ignore_errors_in_json_mode(): void
    {
        config([
            'shieldci.fail_on' => 'never',
            'shieldci.ignore_errors' => [
                'test-multi-issues' => [
                    ['path' => '/app/Vulnerable.php'],
                    ['path' => '/app/Other.php'],
                ],
            ],
        ]);
        $this->registerMultiIssueAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_validates_invalid_category_option(): void
    {
        $this->registerTestAnalyzers();

        $this->artisan('shield:analyze', ['--category' => 'nonexistent-category'])
            ->assertFailed();
    }

    #[Test]
    public function it_counts_skipped_without_category_config_in_streaming(): void
    {
        config(['shieldci.analyzers' => []]);
        $this->registerAnalyzersWithSkipped();

        $this->artisan('shield:analyze')
            ->assertSuccessful()
            ->expectsOutputToContain('skipped');
    }

    #[Test]
    public function it_counts_skipped_without_category_config_in_json(): void
    {
        config(['shieldci.analyzers' => []]);
        $this->registerAnalyzersWithSkipped();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_handles_string_category_in_report_card(): void
    {
        config(['shieldci.fail_on' => 'never']);
        $this->registerAnalyzersWithStringCategory();

        $this->artisan('shield:analyze')
            ->assertSuccessful()
            ->expectsOutputToContain('Report Card');
    }

    #[Test]
    public function it_handles_invalid_category_value_in_report_card(): void
    {
        config(['shieldci.fail_on' => 'never']);
        $this->registerAnalyzersWithInvalidCategory();

        $this->artisan('shield:analyze')
            ->assertSuccessful()
            ->expectsOutputToContain('Report Card');
    }

    #[Test]
    public function it_handles_null_category_in_report_card(): void
    {
        config(['shieldci.fail_on' => 'never']);
        $this->registerAnalyzersWithNullCategory();

        $this->artisan('shield:analyze')
            ->assertSuccessful()
            ->expectsOutputToContain('Report Card');
    }

    #[Test]
    public function it_falls_back_when_all_results_are_skipped(): void
    {
        config(['shieldci.fail_on' => 'never']);
        $this->registerAllSkippedAnalyzers();

        $this->artisan('shield:analyze')
            ->assertSuccessful()
            ->expectsOutputToContain('Report Card');
    }

    #[Test]
    public function it_rejects_non_writable_output_directory(): void
    {
        $this->registerTestAnalyzers();

        $readOnlyDir = base_path('tests/readonly-'.uniqid());
        mkdir($readOnlyDir, 0555);

        $relativeDir = str_replace(base_path().'/', '', $readOnlyDir);

        try {
            $this->artisan('shield:analyze', [
                '--format' => 'json',
                '--output' => $relativeDir.'/report.json',
            ])->assertFailed();
        } finally {
            chmod($readOnlyDir, 0755);
            rmdir($readOnlyDir);
        }
    }

    #[Test]
    public function it_handles_non_array_ignore_error_entry_at_runtime(): void
    {
        // Non-array entries in ignore_errors should be skipped during runtime filtering
        config([
            'shieldci.fail_on' => 'never',
            'shieldci.ignore_errors' => [
                'test-security-failed' => [
                    'string-not-array', // non-array entry
                    ['path' => '/app/Vulnerable.php'], // valid entry
                ],
            ],
        ]);
        $this->registerFailedAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_skips_empty_ignore_error_rule_at_runtime(): void
    {
        // Empty rules (no path/message/pattern keys) should be skipped during filtering
        config([
            'shieldci.fail_on' => 'never',
            'shieldci.ignore_errors' => [
                'test-security-failed' => [
                    [], // empty rule
                    ['path' => '/app/Vulnerable.php'], // valid entry
                ],
            ],
        ]);
        $this->registerFailedAnalyzers();

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_handles_non_array_baseline_issue_entry(): void
    {
        $this->registerFailedAnalyzers();

        $baselinePath = base_path('tests/test-baseline-non-array.json');
        $baseline = [
            'generated_at' => '2024-01-01T00:00:00Z',
            'version' => '1.0.0',
            'errors' => [
                'test-security-failed' => [
                    'string-not-array', // non-array entry should be skipped
                ],
            ],
        ];

        file_put_contents($baselinePath, json_encode($baseline));
        config([
            'shieldci.baseline_file' => $baselinePath,
            'shieldci.fail_on' => 'never',
        ]);

        $this->artisan('shield:analyze', ['--baseline' => true, '--format' => 'json'])
            ->assertSuccessful();

        @unlink($baselinePath);
    }

    #[Test]
    public function it_handles_baseline_without_errors_key(): void
    {
        $this->registerFailedAnalyzers();

        $baselinePath = base_path('tests/test-baseline-no-errors.json');
        $baseline = [
            'generated_at' => '2024-01-01T00:00:00Z',
            'version' => '1.0.0',
            // No 'errors' key at all
        ];

        file_put_contents($baselinePath, json_encode($baseline));
        config([
            'shieldci.baseline_file' => $baselinePath,
            'shieldci.fail_on' => 'never',
        ]);

        $this->artisan('shield:analyze', ['--baseline' => true, '--format' => 'json'])
            ->assertSuccessful();

        @unlink($baselinePath);
    }

    #[Test]
    public function it_handles_string_category_in_skipped_streaming_output(): void
    {
        config(['shieldci.fail_on' => 'never']);
        $this->registerAnalyzersWithStringCategorySkipped();

        $this->artisan('shield:analyze')
            ->assertSuccessful();
    }

    #[Test]
    public function it_returns_empty_results_when_no_analyzers_run(): void
    {
        /** @phpstan-ignore-next-line */
        $this->app->singleton(AnalyzerManager::class, function ($app) {
            /** @var \Mockery\MockInterface&AnalyzerManager $manager */
            $manager = Mockery::mock(AnalyzerManager::class);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getAnalyzers')
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getByCategory')
                ->with(Mockery::any())
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getSkippedAnalyzers')
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('runAll')
                ->andReturn(collect());

            return $manager;
        });

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertFailed()
            ->expectsOutputToContain('No analyzers were run');
    }

    // ==========================================
    // Inline @shieldci-ignore suppression tests
    // ==========================================

    /**
     * @var list<string> Temp files/dirs to clean up
     */
    private array $tempPaths = [];

    private function createTempPhpFile(string $content): string
    {
        $dir = sys_get_temp_dir().'/shieldci-cmd-test-'.uniqid();
        mkdir($dir, 0755, true);
        $path = $dir.'/test_'.uniqid().'.php';
        file_put_contents($path, $content);
        $this->tempPaths[] = $dir;

        return $path;
    }

    private function cleanupTempPaths(): void
    {
        foreach ($this->tempPaths as $dir) {
            if (is_dir($dir)) {
                $files = glob($dir.'/*');
                if ($files !== false) {
                    array_map('unlink', $files);
                }
                rmdir($dir);
            }
        }
        $this->tempPaths = [];
    }

    #[Test]
    public function inline_suppression_filters_issues_in_json_mode(): void
    {
        $file = $this->createTempPhpFile(<<<'PHP'
<?php
// @shieldci-ignore
$result = DB::select("SELECT * FROM users WHERE id = $id");
PHP);

        $result = new AnalysisResult(
            analyzerId: 'sql-injection',
            status: Status::Failed,
            message: 'Found 1 issues',
            issues: [
                new Issue(
                    message: 'SQL Injection detected',
                    location: new \ShieldCI\AnalyzersCore\ValueObjects\Location($file, 3),
                    severity: Severity::Critical,
                    recommendation: 'Use prepared statements',
                ),
            ],
            executionTime: 0.1,
            metadata: [
                'id' => 'sql-injection',
                'name' => 'SQL Injection',
                'description' => 'Detects SQL injection',
                'category' => Category::Security,
                'severity' => Severity::Critical,
            ],
        );

        $this->registerManagerWithResults([$result]);
        config(['shieldci.fail_on' => 'never']);

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('"status": "passed"');

        $this->cleanupTempPaths();
    }

    #[Test]
    public function inline_suppression_filters_issues_in_streaming_mode(): void
    {
        $file = $this->createTempPhpFile(<<<'PHP'
<?php
// @shieldci-ignore
$result = DB::select("SELECT * FROM users WHERE id = $id");
PHP);

        $result = new AnalysisResult(
            analyzerId: 'sql-injection',
            status: Status::Failed,
            message: 'Found 1 issues',
            issues: [
                new Issue(
                    message: 'SQL Injection detected',
                    location: new \ShieldCI\AnalyzersCore\ValueObjects\Location($file, 3),
                    severity: Severity::Critical,
                    recommendation: 'Use prepared statements',
                ),
            ],
            executionTime: 0.1,
            metadata: [
                'id' => 'sql-injection',
                'name' => 'SQL Injection',
                'description' => 'Detects SQL injection',
                'category' => Category::Security,
                'severity' => Severity::Critical,
            ],
        );

        $this->registerManagerWithResults([$result]);
        config(['shieldci.fail_on' => 'never']);

        $output = $this->artisan('shield:analyze', ['--format' => 'console']);
        $output->assertSuccessful();

        $this->cleanupTempPaths();
    }

    #[Test]
    public function inline_suppression_partial_filtering_keeps_unsuppressed_issues(): void
    {
        $file = $this->createTempPhpFile(<<<'PHP'
<?php
// @shieldci-ignore sql-injection
$result = DB::select("SELECT * FROM users WHERE id = $id");

echo $userInput;
PHP);

        $result = new AnalysisResult(
            analyzerId: 'sql-injection',
            status: Status::Failed,
            message: 'Found 2 issues',
            issues: [
                new Issue(
                    message: 'SQL Injection on suppressed line',
                    location: new \ShieldCI\AnalyzersCore\ValueObjects\Location($file, 3),
                    severity: Severity::High,
                    recommendation: 'Use prepared statements',
                ),
                new Issue(
                    message: 'SQL Injection on unsuppressed line',
                    location: new \ShieldCI\AnalyzersCore\ValueObjects\Location($file, 5),
                    severity: Severity::High,
                    recommendation: 'Use prepared statements',
                ),
            ],
            executionTime: 0.1,
            metadata: [
                'id' => 'sql-injection',
                'name' => 'SQL Injection',
                'description' => 'Detects SQL injection',
                'category' => Category::Security,
                'severity' => Severity::High,
            ],
        );

        $this->registerManagerWithResults([$result]);
        config(['shieldci.fail_on' => 'never']);

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('SQL Injection on unsuppressed line');

        $this->cleanupTempPaths();
    }

    #[Test]
    public function inline_suppression_all_issues_suppressed_changes_status_to_passed(): void
    {
        $file = $this->createTempPhpFile(<<<'PHP'
<?php
// @shieldci-ignore
$a = DB::select("SELECT * FROM users WHERE id = $id");
// @shieldci-ignore
$b = DB::select("SELECT * FROM posts WHERE id = $id");
PHP);

        $result = new AnalysisResult(
            analyzerId: 'sql-injection',
            status: Status::Failed,
            message: 'Found 2 issues',
            issues: [
                new Issue(
                    message: 'SQL Injection issue 1',
                    location: new \ShieldCI\AnalyzersCore\ValueObjects\Location($file, 3),
                    severity: Severity::High,
                    recommendation: 'Use prepared statements',
                ),
                new Issue(
                    message: 'SQL Injection issue 2',
                    location: new \ShieldCI\AnalyzersCore\ValueObjects\Location($file, 5),
                    severity: Severity::High,
                    recommendation: 'Use prepared statements',
                ),
            ],
            executionTime: 0.1,
            metadata: [
                'id' => 'sql-injection',
                'name' => 'SQL Injection',
                'description' => 'Detects SQL injection',
                'category' => Category::Security,
                'severity' => Severity::High,
            ],
        );

        $this->registerManagerWithResults([$result]);
        config(['shieldci.fail_on' => 'never']);

        $exitCode = \Illuminate\Support\Facades\Artisan::call('shield:analyze', ['--format' => 'json']);
        $output = \Illuminate\Support\Facades\Artisan::output();

        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString('"status": "passed"', $output);
        $this->assertStringContainsString('All issues are suppressed via @shieldci-ignore', $output);

        $this->cleanupTempPaths();
    }

    #[Test]
    public function inline_suppression_keeps_issues_without_location(): void
    {
        $file = $this->createTempPhpFile(<<<'PHP'
<?php
// @shieldci-ignore
$x = 1;
PHP);

        $result = new AnalysisResult(
            analyzerId: 'app-wide-check',
            status: Status::Failed,
            message: 'Found 1 issues',
            issues: [
                new Issue(
                    message: 'Application-wide issue with no location',
                    location: null,
                    severity: Severity::Medium,
                    recommendation: 'Fix it',
                ),
            ],
            executionTime: 0.1,
            metadata: [
                'id' => 'app-wide-check',
                'name' => 'App Wide Check',
                'description' => 'Tests app-wide issues',
                'category' => Category::Reliability,
                'severity' => Severity::Medium,
            ],
        );

        $this->registerManagerWithResults([$result]);
        config(['shieldci.fail_on' => 'never']);

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('Application-wide issue with no location');

        $this->cleanupTempPaths();
    }

    #[Test]
    public function inline_suppression_keeps_issues_with_line_zero(): void
    {
        $file = $this->createTempPhpFile(<<<'PHP'
<?php
// @shieldci-ignore
$x = 1;
PHP);

        $result = new AnalysisResult(
            analyzerId: 'line-zero-check',
            status: Status::Failed,
            message: 'Found 1 issues',
            issues: [
                new Issue(
                    message: 'Issue at line zero',
                    location: new \ShieldCI\AnalyzersCore\ValueObjects\Location($file, 0),
                    severity: Severity::Medium,
                    recommendation: 'Fix it',
                ),
            ],
            executionTime: 0.1,
            metadata: [
                'id' => 'line-zero-check',
                'name' => 'Line Zero Check',
                'description' => 'Tests line zero handling',
                'category' => Category::Reliability,
                'severity' => Severity::Medium,
            ],
        );

        $this->registerManagerWithResults([$result]);
        config(['shieldci.fail_on' => 'never']);

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('Issue at line zero');

        $this->cleanupTempPaths();
    }

    #[Test]
    public function inline_suppression_passes_non_analysis_result_unchanged(): void
    {
        $command = new \ShieldCI\Commands\AnalyzeCommand;

        // Initialize the suppression parser via reflection
        $parserProp = new \ReflectionProperty($command, 'suppressionParser');
        $parserProp->setAccessible(true);
        $parserProp->setValue($command, new \ShieldCI\Support\InlineSuppressionParser);

        $method = new \ReflectionMethod($command, 'filterAgainstInlineSuppressions');
        $method->setAccessible(true);

        // Create a mock ResultInterface that is NOT an AnalysisResult
        /** @var \ShieldCI\AnalyzersCore\Contracts\ResultInterface&MockInterface $mockResult */
        $mockResult = Mockery::mock(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class);
        /** @phpstan-ignore-next-line */
        $mockResult->shouldReceive('getAnalyzerId')->andReturn('mock-analyzer');
        /** @phpstan-ignore-next-line */
        $mockResult->shouldReceive('getStatus')->andReturn(Status::Failed);
        /** @phpstan-ignore-next-line */
        $mockResult->shouldReceive('getMessage')->andReturn('Mock failed');
        /** @phpstan-ignore-next-line */
        $mockResult->shouldReceive('getIssues')->andReturn([]);
        /** @phpstan-ignore-next-line */
        $mockResult->shouldReceive('getExecutionTime')->andReturn(0.1);
        /** @phpstan-ignore-next-line */
        $mockResult->shouldReceive('getMetadata')->andReturn([]);
        /** @phpstan-ignore-next-line */
        $mockResult->shouldReceive('isSuccess')->andReturn(false);
        /** @phpstan-ignore-next-line */
        $mockResult->shouldReceive('toArray')->andReturn([]);

        $report = new \ShieldCI\ValueObjects\AnalysisReport(
            projectId: 'test-project-id',
            laravelVersion: '11.0',
            packageVersion: '1.0.0',
            results: collect([$mockResult]),
            totalExecutionTime: 0.1,
            analyzedAt: new \DateTimeImmutable('2026-01-01T00:00:00Z'),
        );

        /** @var \ShieldCI\ValueObjects\AnalysisReport $filteredReport */
        $filteredReport = $method->invoke($command, $report);

        // The non-AnalysisResult object should pass through unchanged
        $this->assertSame($mockResult, $filteredReport->results->first());
    }

    // ==========================================
    // adjustFilteredMessage tests (via reflection)
    // ==========================================

    #[Test]
    public function adjust_filtered_message_all_filtered_returns_suppressed_message(): void
    {
        $command = new \ShieldCI\Commands\AnalyzeCommand;
        $method = new \ReflectionMethod($command, 'adjustFilteredMessage');
        $method->setAccessible(true);

        $result = $method->invoke($command, 'Found 3 issues', 3, 0);

        $this->assertSame('All issues are suppressed via @shieldci-ignore', $result);
    }

    #[Test]
    public function adjust_filtered_message_none_filtered_returns_original(): void
    {
        $command = new \ShieldCI\Commands\AnalyzeCommand;
        $method = new \ReflectionMethod($command, 'adjustFilteredMessage');
        $method->setAccessible(true);

        $result = $method->invoke($command, 'Found 3 issues', 3, 3);

        $this->assertSame('Found 3 issues', $result);
    }

    #[Test]
    public function adjust_filtered_message_partial_filter_updates_count(): void
    {
        $command = new \ShieldCI\Commands\AnalyzeCommand;
        $method = new \ReflectionMethod($command, 'adjustFilteredMessage');
        $method->setAccessible(true);

        $result = $method->invoke($command, 'Found 3 issues', 3, 2);

        $this->assertSame('Found 2 issues', $result);
    }

    #[Test]
    public function adjust_filtered_message_singular_grammar_for_issues(): void
    {
        $command = new \ShieldCI\Commands\AnalyzeCommand;
        $method = new \ReflectionMethod($command, 'adjustFilteredMessage');
        $method->setAccessible(true);

        $this->assertSame('Found 1 issue', $method->invoke($command, 'Found 3 issues', 3, 1));
        $this->assertSame('Found 1 error', $method->invoke($command, 'Found 3 errors', 3, 1));
        $this->assertSame('Found 1 vulnerability', $method->invoke($command, 'Found 3 vulnerabilities', 3, 1));
        $this->assertSame('Found 1 warning', $method->invoke($command, 'Found 3 warnings', 3, 1));
        $this->assertSame('Found 1 problem', $method->invoke($command, 'Found 3 problems', 3, 1));
    }

    #[Test]
    public function adjust_filtered_message_zero_original_and_zero_filtered(): void
    {
        $command = new \ShieldCI\Commands\AnalyzeCommand;
        $method = new \ReflectionMethod($command, 'adjustFilteredMessage');
        $method->setAccessible(true);

        // filteredCount === 0, so it returns the suppressed message
        $result = $method->invoke($command, 'Something wrong', 0, 0);

        $this->assertSame('All issues are suppressed via @shieldci-ignore', $result);
    }

    // ─── API Integration Tests ────────────────────────────────────────────

    #[Test]
    public function it_does_not_send_to_api_when_config_is_not_set(): void
    {
        $this->registerTestAnalyzers();

        // Ensure send_to_api is not set (default)
        config(['shieldci.report.send_to_api' => false]);

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->doesntExpectOutputToContain('Sending report to ShieldCI platform');
    }

    #[Test]
    public function it_sends_to_api_when_report_flag_is_used(): void
    {
        $this->registerTestAnalyzers();

        config(['shieldci.report.send_to_api' => false]);

        \Illuminate\Support\Facades\Http::fake([
            'api.test.shieldci.com/api/reports' => \Illuminate\Support\Facades\Http::response([
                'success' => true,
            ]),
        ]);

        $this->artisan('shield:analyze', ['--format' => 'json', '--report' => true])
            ->assertSuccessful()
            ->expectsOutputToContain('Report sent successfully');
    }

    #[Test]
    public function it_sends_to_api_when_configured_and_reports_success(): void
    {
        $this->registerTestAnalyzers();

        config(['shieldci.report.send_to_api' => true]);

        \Illuminate\Support\Facades\Http::fake([
            'api.test.shieldci.com/api/reports' => \Illuminate\Support\Facades\Http::response([
                'success' => true,
            ]),
        ]);

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('Sending report to ShieldCI platform')
            ->expectsOutputToContain('Report sent successfully');
    }

    #[Test]
    public function it_sends_to_api_and_reports_failure_response(): void
    {
        $this->registerTestAnalyzers();

        config(['shieldci.report.send_to_api' => true]);

        \Illuminate\Support\Facades\Http::fake([
            'api.test.shieldci.com/api/reports' => \Illuminate\Support\Facades\Http::response([
                'success' => false,
                'message' => 'Invalid token',
            ]),
        ]);

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('Failed to send report: Invalid token');
    }

    #[Test]
    public function it_sends_to_api_and_handles_failure_without_message(): void
    {
        $this->registerTestAnalyzers();

        config(['shieldci.report.send_to_api' => true]);

        \Illuminate\Support\Facades\Http::fake([
            'api.test.shieldci.com/api/reports' => \Illuminate\Support\Facades\Http::response([
                'error' => 'something',
            ]),
        ]);

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('Failed to send report: Unknown error');
    }

    #[Test]
    public function it_sends_to_api_and_handles_connection_exception(): void
    {
        $this->registerTestAnalyzers();

        config(['shieldci.report.send_to_api' => true]);

        // Mock the ClientInterface to throw an exception
        $this->app->singleton(\ShieldCI\Contracts\ClientInterface::class, function () {
            $mock = Mockery::mock(\ShieldCI\Contracts\ClientInterface::class);
            /** @phpstan-ignore-next-line */
            $mock->shouldReceive('sendReport')
                ->andThrow(new \Exception('Connection timed out'));

            return $mock;
        });

        $this->artisan('shield:analyze', ['--format' => 'json'])
            ->assertSuccessful()
            ->expectsOutputToContain('Failed to send report to API: Connection timed out');
    }

    #[Test]
    public function it_sends_to_api_in_streaming_mode(): void
    {
        $this->registerTestAnalyzers();

        config(['shieldci.report.send_to_api' => true]);

        \Illuminate\Support\Facades\Http::fake([
            'api.test.shieldci.com/api/reports' => \Illuminate\Support\Facades\Http::response([
                'success' => true,
            ]),
        ]);

        // Console format triggers streaming mode
        $this->artisan('shield:analyze', ['--format' => 'console'])
            ->assertSuccessful()
            ->expectsOutputToContain('Report sent successfully');
    }

    /**
     * Register test analyzers that produce failures.
     */
    private function registerFailedAnalyzers(): void
    {
        $failedAnalyzer = $this->createMockAnalyzer(
            'test-security-failed',
            'Test Security Failed',
            Category::Security,
            Severity::High,
            Status::Failed,
            'Found 1 security issue',
            [
                new Issue(
                    message: 'SQL Injection vulnerability',
                    location: new \ShieldCI\AnalyzersCore\ValueObjects\Location('/app/Vulnerable.php', 42),
                    severity: Severity::High,
                    recommendation: 'Use prepared statements',
                ),
            ]
        );

        /** @phpstan-ignore-next-line */
        $this->app->singleton(AnalyzerManager::class, function ($app) use ($failedAnalyzer) {
            /** @var \Mockery\MockInterface&AnalyzerManager $manager */
            $manager = Mockery::mock(AnalyzerManager::class);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getAnalyzers')
                ->andReturn(collect([$failedAnalyzer]));

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getByCategory')
                ->with(Mockery::any())
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getSkippedAnalyzers')
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with('test-security-failed')
                ->andReturn($failedAnalyzer->analyze());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with(Mockery::any())
                ->andReturn(null);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('runAll')
                ->andReturn(collect([$failedAnalyzer->analyze()]));

            return $manager;
        });
    }

    /**
     * Register test analyzers with multiple issues (for partial-filter testing).
     */
    private function registerMultiIssueAnalyzers(string $message = 'Found 2 security issues'): void
    {
        $failedAnalyzer = $this->createMockAnalyzer(
            'test-multi-issues',
            'Test Multi Issues',
            Category::Security,
            Severity::High,
            Status::Failed,
            $message,
            [
                new Issue(
                    message: 'SQL Injection vulnerability',
                    location: new \ShieldCI\AnalyzersCore\ValueObjects\Location('/app/Vulnerable.php', 42),
                    severity: Severity::High,
                    recommendation: 'Use prepared statements',
                ),
                new Issue(
                    message: 'XSS vulnerability',
                    location: new \ShieldCI\AnalyzersCore\ValueObjects\Location('/app/Other.php', 10),
                    severity: Severity::High,
                    recommendation: 'Escape output',
                ),
            ]
        );

        /** @phpstan-ignore-next-line */
        $this->app->singleton(AnalyzerManager::class, function ($app) use ($failedAnalyzer) {
            /** @var \Mockery\MockInterface&AnalyzerManager $manager */
            $manager = Mockery::mock(AnalyzerManager::class);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getAnalyzers')
                ->andReturn(collect([$failedAnalyzer]));

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getByCategory')
                ->with(Mockery::any())
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getSkippedAnalyzers')
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with('test-multi-issues')
                ->andReturn($failedAnalyzer->analyze());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with(Mockery::any())
                ->andReturn(null);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('runAll')
                ->andReturn(collect([$failedAnalyzer->analyze()]));

            return $manager;
        });
    }

    /**
     * Register test analyzers that produce warnings.
     */
    private function registerWarningAnalyzers(): void
    {
        $warningAnalyzer = $this->createMockAnalyzer(
            'test-warning-analyzer',
            'Test Warning Analyzer',
            Category::Security,
            Severity::Low,
            Status::Warning,
            'Found 1 warning',
            [
                new Issue(
                    message: 'Minor concern',
                    location: new \ShieldCI\AnalyzersCore\ValueObjects\Location('/app/Minor.php', 5),
                    severity: Severity::Low,
                    recommendation: 'Consider fixing',
                ),
            ]
        );

        /** @phpstan-ignore-next-line */
        $this->app->singleton(AnalyzerManager::class, function ($app) use ($warningAnalyzer) {
            /** @var \Mockery\MockInterface&AnalyzerManager $manager */
            $manager = Mockery::mock(AnalyzerManager::class);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getAnalyzers')
                ->andReturn(collect([$warningAnalyzer]));

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getByCategory')
                ->with(Mockery::any())
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getSkippedAnalyzers')
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with('test-warning-analyzer')
                ->andReturn($warningAnalyzer->analyze());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with(Mockery::any())
                ->andReturn(null);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('runAll')
                ->andReturn(collect([$warningAnalyzer->analyze()]));

            return $manager;
        });
    }

    /**
     * Register test analyzers that produce failures with a specific severity.
     */
    private function registerFailedAnalyzersWithSeverity(Severity $severity): void
    {
        $failedAnalyzer = $this->createMockAnalyzer(
            'test-severity-failed',
            'Test Severity Failed',
            Category::Security,
            $severity,
            Status::Failed,
            'Found 1 security issue',
            [
                new Issue(
                    message: 'Test vulnerability',
                    location: new \ShieldCI\AnalyzersCore\ValueObjects\Location('/app/Test.php', 10),
                    severity: $severity,
                    recommendation: 'Fix it',
                ),
            ]
        );

        /** @phpstan-ignore-next-line */
        $this->app->singleton(AnalyzerManager::class, function ($app) use ($failedAnalyzer) {
            /** @var \Mockery\MockInterface&AnalyzerManager $manager */
            $manager = Mockery::mock(AnalyzerManager::class);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getAnalyzers')
                ->andReturn(collect([$failedAnalyzer]));

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getByCategory')
                ->with(Mockery::any())
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getSkippedAnalyzers')
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with('test-severity-failed')
                ->andReturn($failedAnalyzer->analyze());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with(Mockery::any())
                ->andReturn(null);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('runAll')
                ->andReturn(collect([$failedAnalyzer->analyze()]));

            return $manager;
        });
    }

    /**
     * Register test analyzers in the service container.
     */
    private function registerTestAnalyzers(): void
    {
        // Create mock analyzers
        $securityAnalyzer = $this->createMockAnalyzer(
            'test-security-analyzer',
            'Test Security Analyzer',
            Category::Security,
            Severity::High,
            Status::Passed,
            'No security issues'
        );

        $performanceAnalyzer = $this->createMockAnalyzer(
            'test-performance-analyzer',
            'Test Performance Analyzer',
            Category::Performance,
            Severity::Medium,
            Status::Passed,
            'No performance issues'
        );

        // Bind to container
        /** @phpstan-ignore-next-line */
        $this->app->singleton(AnalyzerManager::class, function ($app) use ($securityAnalyzer, $performanceAnalyzer) {
            /** @var MockInterface&AnalyzerManager $manager */
            $manager = Mockery::mock(AnalyzerManager::class);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getAnalyzers')
                ->andReturn(collect([$securityAnalyzer, $performanceAnalyzer]));

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getByCategory')
                ->with('security')
                ->andReturn(collect([$securityAnalyzer]));

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getByCategory')
                ->with('performance')
                ->andReturn(collect([$performanceAnalyzer]));

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getByCategory')
                ->with(Mockery::any())
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getSkippedAnalyzers')
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with('test-security-analyzer')
                ->andReturn($securityAnalyzer->analyze());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with('test-performance-analyzer')
                ->andReturn($performanceAnalyzer->analyze());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with(Mockery::any())
                ->andReturn(null);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('runAll')
                ->andReturn(collect([
                    $securityAnalyzer->analyze(),
                    $performanceAnalyzer->analyze(),
                ]));

            return $manager;
        });
    }

    /**
     * Register test analyzers that produce warnings with a specific severity.
     */
    private function registerWarningAnalyzersWithSeverity(Severity $severity): void
    {
        $warningAnalyzer = $this->createMockAnalyzer(
            'test-warning-severity',
            'Test Warning Severity',
            Category::Security,
            $severity,
            Status::Warning,
            'Found 1 warning',
            [
                new Issue(
                    message: 'Warning issue',
                    location: new \ShieldCI\AnalyzersCore\ValueObjects\Location('/app/Warn.php', 5),
                    severity: $severity,
                    recommendation: 'Consider fixing',
                ),
            ]
        );

        /** @phpstan-ignore-next-line */
        $this->app->singleton(AnalyzerManager::class, function ($app) use ($warningAnalyzer) {
            /** @var \Mockery\MockInterface&AnalyzerManager $manager */
            $manager = Mockery::mock(AnalyzerManager::class);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getAnalyzers')
                ->andReturn(collect([$warningAnalyzer]));

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getByCategory')
                ->with(Mockery::any())
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getSkippedAnalyzers')
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with('test-warning-severity')
                ->andReturn($warningAnalyzer->analyze());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with(Mockery::any())
                ->andReturn(null);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('runAll')
                ->andReturn(collect([$warningAnalyzer->analyze()]));

            return $manager;
        });
    }

    /**
     * Register test analyzers with some skipped (for streaming/JSON mode coverage).
     */
    private function registerAnalyzersWithSkipped(): void
    {
        $passedAnalyzer = $this->createMockAnalyzer(
            'test-security-passed',
            'Test Security Passed',
            Category::Security,
            Severity::High,
            Status::Passed,
            'No security issues'
        );

        // Create a skipped result (simulating what getSkippedAnalyzers returns)
        $skippedResult = AnalysisResult::skipped(
            'test-skipped-analyzer',
            'Not applicable for this project',
            0.0,
            [
                'id' => 'test-skipped-analyzer',
                'name' => 'Test Skipped Analyzer',
                'description' => 'A skipped analyzer',
                'category' => Category::Security,
                'severity' => Severity::Medium,
            ],
        );

        /** @phpstan-ignore-next-line */
        $this->app->singleton(AnalyzerManager::class, function ($app) use ($passedAnalyzer, $skippedResult) {
            /** @var \Mockery\MockInterface&AnalyzerManager $manager */
            $manager = Mockery::mock(AnalyzerManager::class);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getAnalyzers')
                ->andReturn(collect([$passedAnalyzer]));

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getByCategory')
                ->with('security')
                ->andReturn(collect([$passedAnalyzer]));

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getByCategory')
                ->with(Mockery::any())
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getSkippedAnalyzers')
                ->andReturn(collect([$skippedResult]));

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with('test-security-passed')
                ->andReturn($passedAnalyzer->analyze());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with(Mockery::any())
                ->andReturn(null);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('runAll')
                ->andReturn(collect([$passedAnalyzer->analyze()]));

            return $manager;
        });
    }

    /**
     * Register analyzers where result metadata contains a string category (not enum).
     */
    private function registerAnalyzersWithStringCategory(): void
    {
        $result = new AnalysisResult(
            analyzerId: 'test-string-cat',
            status: Status::Passed,
            message: 'All good',
            issues: [],
            executionTime: 0.1,
            metadata: [
                'id' => 'test-string-cat',
                'name' => 'String Category Test',
                'description' => 'Test',
                'category' => 'security', // String, not Category enum
                'severity' => Severity::Low,
            ],
        );

        $this->registerManagerWithResults([$result]);
    }

    /**
     * Register analyzers where result metadata has an invalid category enum value.
     */
    private function registerAnalyzersWithInvalidCategory(): void
    {
        $result = new AnalysisResult(
            analyzerId: 'test-invalid-cat',
            status: Status::Passed,
            message: 'All good',
            issues: [],
            executionTime: 0.1,
            metadata: [
                'id' => 'test-invalid-cat',
                'name' => 'Invalid Category Test',
                'description' => 'Test',
                'category' => 'not_a_real_category', // Invalid enum value
                'severity' => Severity::Low,
            ],
        );

        $this->registerManagerWithResults([$result]);
    }

    /**
     * Register analyzers where result metadata has null category.
     */
    private function registerAnalyzersWithNullCategory(): void
    {
        $result = new AnalysisResult(
            analyzerId: 'test-null-cat',
            status: Status::Passed,
            message: 'All good',
            issues: [],
            executionTime: 0.1,
            metadata: [
                'id' => 'test-null-cat',
                'name' => 'Null Category Test',
                'description' => 'Test',
                // No 'category' key — triggers null path
                'severity' => Severity::Low,
            ],
        );

        $this->registerManagerWithResults([$result]);
    }

    /**
     * Register analyzers where all results are skipped (for fallback coverage).
     */
    private function registerAllSkippedAnalyzers(): void
    {
        $skipped = AnalysisResult::skipped(
            'test-all-skipped',
            'Not applicable',
            0.0,
            [
                'id' => 'test-all-skipped',
                'name' => 'All Skipped Test',
                'description' => 'Test',
                'category' => Category::Security,
                'severity' => Severity::Low,
            ],
        );

        /** @phpstan-ignore-next-line */
        $this->app->singleton(AnalyzerManager::class, function ($app) use ($skipped) {
            /** @var \Mockery\MockInterface&AnalyzerManager $manager */
            $manager = Mockery::mock(AnalyzerManager::class);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getAnalyzers')
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getByCategory')
                ->with(Mockery::any())
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getSkippedAnalyzers')
                ->andReturn(collect([$skipped]));

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('runAll')
                ->andReturn(collect([$skipped]));

            return $manager;
        });
    }

    /**
     * Register analyzers with a skipped result that has string category metadata.
     */
    private function registerAnalyzersWithStringCategorySkipped(): void
    {
        $passedAnalyzer = $this->createMockAnalyzer(
            'test-passed-scs',
            'Test Passed SCS',
            Category::Security,
            Severity::High,
            Status::Passed,
            'No issues'
        );

        $skippedResult = AnalysisResult::skipped(
            'test-skipped-str-cat',
            'Not applicable',
            0.0,
            [
                'id' => 'test-skipped-str-cat',
                'name' => 'Skipped String Cat',
                'description' => 'Test',
                'category' => 'security', // String, not Category enum
                'severity' => Severity::Low,
            ],
        );

        /** @phpstan-ignore-next-line */
        $this->app->singleton(AnalyzerManager::class, function ($app) use ($passedAnalyzer, $skippedResult) {
            /** @var \Mockery\MockInterface&AnalyzerManager $manager */
            $manager = Mockery::mock(AnalyzerManager::class);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getAnalyzers')
                ->andReturn(collect([$passedAnalyzer]));

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getByCategory')
                ->with(Mockery::any())
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getSkippedAnalyzers')
                ->andReturn(collect([$skippedResult]));

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with('test-passed-scs')
                ->andReturn($passedAnalyzer->analyze());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with(Mockery::any())
                ->andReturn(null);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('runAll')
                ->andReturn(collect([$passedAnalyzer->analyze()]));

            return $manager;
        });
    }

    /**
     * Helper to register a manager with pre-built results.
     *
     * @param  array<int, AnalysisResult>  $results
     */
    private function registerManagerWithResults(array $results): void
    {
        $analyzers = [];
        foreach ($results as $result) {
            $metadata = $result->getMetadata();
            $id = $result->getAnalyzerId();

            /** @var AnalyzerInterface&MockInterface $analyzer */
            $analyzer = Mockery::mock(AnalyzerInterface::class);
            /** @phpstan-ignore-next-line */
            $analyzer->shouldReceive('getId')->andReturn($id);
            $categoryValue = $metadata['category'] ?? null;
            $severityValue = $metadata['severity'] ?? null;

            /** @phpstan-ignore-next-line */
            $analyzer->shouldReceive('getMetadata')->andReturn(new AnalyzerMetadata(
                id: $id,
                name: is_string($metadata['name'] ?? null) ? $metadata['name'] : $id,
                description: is_string($metadata['description'] ?? null) ? $metadata['description'] : 'Test',
                category: $categoryValue instanceof Category ? $categoryValue : Category::Security,
                severity: $severityValue instanceof Severity ? $severityValue : Severity::Low,
            ));
            /** @phpstan-ignore-next-line */
            $analyzer->shouldReceive('analyze')->andReturn($result);
            /** @phpstan-ignore-next-line */
            $analyzer->shouldReceive('shouldRun')->andReturn(true);
            /** @phpstan-ignore-next-line */
            $analyzer->shouldReceive('getSkipReason')->andReturn('');

            $analyzers[] = $analyzer;
        }

        /** @phpstan-ignore-next-line */
        $this->app->singleton(AnalyzerManager::class, function ($app) use ($analyzers, $results) {
            /** @var \Mockery\MockInterface&AnalyzerManager $manager */
            $manager = Mockery::mock(AnalyzerManager::class);

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getAnalyzers')
                ->andReturn(collect($analyzers));

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getByCategory')
                ->with(Mockery::any())
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('getSkippedAnalyzers')
                ->andReturn(collect());

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('runAll')
                ->andReturn(collect($results));

            foreach ($analyzers as $analyzer) {
                /** @phpstan-ignore-next-line */
                $manager->shouldReceive('run')
                    ->with($analyzer->getId())
                    ->andReturn($analyzer->analyze());
            }

            /** @phpstan-ignore-next-line */
            $manager->shouldReceive('run')
                ->with(Mockery::any())
                ->andReturn(null);

            return $manager;
        });
    }

    /**
     * @param  array<int, Issue>  $issues
     * @return AnalyzerInterface&MockInterface
     */
    private function createMockAnalyzer(
        string $id,
        string $name,
        Category $category,
        Severity $severity,
        Status $status,
        string $message,
        array $issues = []
    ): AnalyzerInterface {
        /** @var AnalyzerInterface&MockInterface $analyzer */
        $analyzer = Mockery::mock(AnalyzerInterface::class);

        $metadata = new AnalyzerMetadata(
            id: $id,
            name: $name,
            description: "Test analyzer: {$name}",
            category: $category,
            severity: $severity,
        );

        $result = new AnalysisResult(
            analyzerId: $id,
            status: $status,
            message: $message,
            issues: $issues,
            executionTime: 0.1,
            metadata: [
                'id' => $metadata->id,
                'name' => $metadata->name,
                'description' => $metadata->description,
                'category' => $metadata->category,
                'severity' => $metadata->severity,
                'docsUrl' => $metadata->docsUrl,
            ],
        );

        /** @phpstan-ignore-next-line */
        $analyzer->shouldReceive('getId')->andReturn($id);
        /** @phpstan-ignore-next-line */
        $analyzer->shouldReceive('getMetadata')->andReturn($metadata);
        /** @phpstan-ignore-next-line */
        $analyzer->shouldReceive('analyze')->andReturn($result);
        /** @phpstan-ignore-next-line */
        $analyzer->shouldReceive('shouldRun')->andReturn(true);
        /** @phpstan-ignore-next-line */
        $analyzer->shouldReceive('getSkipReason')->andReturn('');

        return $analyzer;
    }
}
