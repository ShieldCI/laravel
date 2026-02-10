<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Commands;

use Mockery;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\AnalyzerManager;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Enums\Status;
use ShieldCI\AnalyzersCore\Results\AnalysisResult;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Tests\TestCase;

class BaselineCommandTest extends TestCase
{
    private string $baselinePath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->baselinePath = base_path('.shieldci-baseline-test.json');

        // Clean up any existing baseline file
        if (file_exists($this->baselinePath)) {
            unlink($this->baselinePath);
        }
    }

    protected function tearDown(): void
    {
        // Clean up baseline file
        if (file_exists($this->baselinePath)) {
            unlink($this->baselinePath);
        }

        Mockery::close();
        parent::tearDown();
    }

    #[Test]
    public function it_generates_baseline_file(): void
    {
        $this->registerMockAnalyzerManager([]);

        config(['shieldci.baseline_file' => $this->baselinePath]);

        $this->artisan('shield:baseline')
            ->assertSuccessful()
            ->expectsOutputToContain('Baseline file generated successfully');

        $this->assertFileExists($this->baselinePath);
    }

    #[Test]
    public function it_generates_baseline_with_issues(): void
    {
        $issues = [
            new Issue(
                message: 'Test issue',
                location: new Location('/app/Test.php', 10),
                severity: Severity::High,
                recommendation: 'Fix this issue',
            ),
        ];

        $this->registerMockAnalyzerManager($issues);

        config(['shieldci.baseline_file' => $this->baselinePath]);

        $this->artisan('shield:baseline')
            ->assertSuccessful()
            ->expectsOutputToContain('Total issues');

        $this->assertFileExists($this->baselinePath);

        // Verify baseline content
        $content = json_decode(file_get_contents($this->baselinePath), true);
        $this->assertArrayHasKey('errors', $content);
        $this->assertArrayHasKey('generated_at', $content);
        $this->assertArrayHasKey('version', $content);
    }

    #[Test]
    public function it_supports_ci_mode_flag(): void
    {
        $this->registerMockAnalyzerManager([]);

        config(['shieldci.baseline_file' => $this->baselinePath]);

        $this->artisan('shield:baseline', ['--ci' => true])
            ->assertSuccessful()
            ->expectsOutputToContain('CI mode');
    }

    #[Test]
    public function it_can_merge_with_existing_baseline(): void
    {
        // Create an existing baseline
        $existingBaseline = [
            'generated_at' => date('c'),
            'version' => '1.0.0',
            'errors' => [
                'existing-analyzer' => [
                    [
                        'type' => 'hash',
                        'path' => '/app/Existing.php',
                        'line' => 5,
                        'message' => 'Existing issue',
                        'hash' => 'abc123',
                    ],
                ],
            ],
            'dont_report' => [],
        ];

        config(['shieldci.baseline_file' => $this->baselinePath]);
        file_put_contents($this->baselinePath, json_encode($existingBaseline, JSON_PRETTY_PRINT));

        $this->registerMockAnalyzerManager([
            new Issue(
                message: 'New issue',
                location: new Location('/app/New.php', 20),
                severity: Severity::Medium,
                recommendation: 'Fix this',
            ),
        ]);

        $this->artisan('shield:baseline', ['--merge' => true])
            ->assertSuccessful()
            ->expectsOutputToContain('Merging with existing baseline');

        // Verify merged content
        $content = json_decode(file_get_contents($this->baselinePath), true);
        $this->assertArrayHasKey('errors', $content);
    }

    #[Test]
    public function it_adds_failed_analyzers_without_issues_to_dont_report(): void
    {
        // Create an analyzer that fails but has no specific issues
        $manager = Mockery::mock(AnalyzerManager::class);

        $result = new AnalysisResult(
            analyzerId: 'failed-no-issues',
            status: Status::Failed,
            message: 'Failed with no specific issues',
            issues: [], // No issues despite being failed
            executionTime: 0.1,
            metadata: [
                'name' => 'Failed No Issues Analyzer',
            ],
        );

        $manager->shouldReceive('runAll')->andReturn(collect([$result]));

        $this->app->singleton(AnalyzerManager::class, fn () => $manager);

        config(['shieldci.baseline_file' => $this->baselinePath]);

        $this->artisan('shield:baseline')
            ->assertSuccessful()
            ->expectsOutputToContain('dont_report');

        // Verify dont_report contains the analyzer
        $content = json_decode(file_get_contents($this->baselinePath), true);
        $this->assertArrayHasKey('dont_report', $content);
        $this->assertContains('failed-no-issues', $content['dont_report']);
    }

    #[Test]
    public function it_skips_passed_analyzers(): void
    {
        $manager = Mockery::mock(AnalyzerManager::class);

        $result = new AnalysisResult(
            analyzerId: 'passed-analyzer',
            status: Status::Passed,
            message: 'All checks passed',
            issues: [],
            executionTime: 0.1,
            metadata: [],
        );

        $manager->shouldReceive('runAll')->andReturn(collect([$result]));

        $this->app->singleton(AnalyzerManager::class, fn () => $manager);

        config(['shieldci.baseline_file' => $this->baselinePath]);

        $this->artisan('shield:baseline')
            ->assertSuccessful();

        // Verify no errors for passed analyzer
        $content = json_decode(file_get_contents($this->baselinePath), true);
        $this->assertArrayNotHasKey('passed-analyzer', $content['errors']);
    }

    #[Test]
    public function it_skips_skipped_analyzers(): void
    {
        $manager = Mockery::mock(AnalyzerManager::class);

        $result = new AnalysisResult(
            analyzerId: 'skipped-analyzer',
            status: Status::Skipped,
            message: 'Skipped',
            issues: [],
            executionTime: 0.0,
            metadata: [],
        );

        $manager->shouldReceive('runAll')->andReturn(collect([$result]));

        $this->app->singleton(AnalyzerManager::class, fn () => $manager);

        config(['shieldci.baseline_file' => $this->baselinePath]);

        $this->artisan('shield:baseline')
            ->assertSuccessful();

        // Verify no errors for skipped analyzer
        $content = json_decode(file_get_contents($this->baselinePath), true);
        $this->assertArrayNotHasKey('skipped-analyzer', $content['errors']);
    }

    #[Test]
    public function it_preserves_existing_dont_report_when_merging(): void
    {
        // Create existing baseline with dont_report
        $existingBaseline = [
            'generated_at' => date('c'),
            'version' => '1.0.0',
            'errors' => [],
            'dont_report' => ['existing-dont-report-analyzer'],
        ];

        config(['shieldci.baseline_file' => $this->baselinePath]);
        file_put_contents($this->baselinePath, json_encode($existingBaseline, JSON_PRETTY_PRINT));

        $this->registerMockAnalyzerManager([]);

        $this->artisan('shield:baseline', ['--merge' => true])
            ->assertSuccessful();

        $content = json_decode(file_get_contents($this->baselinePath), true);
        $this->assertContains('existing-dont-report-analyzer', $content['dont_report']);
    }

    #[Test]
    public function it_generates_unique_hashes_for_issues(): void
    {
        $issues = [
            new Issue(
                message: 'Issue 1',
                location: new Location('/app/Test.php', 10),
                severity: Severity::High,
                recommendation: 'Fix 1',
            ),
            new Issue(
                message: 'Issue 2',
                location: new Location('/app/Test.php', 20),
                severity: Severity::High,
                recommendation: 'Fix 2',
            ),
        ];

        $this->registerMockAnalyzerManager($issues);

        config(['shieldci.baseline_file' => $this->baselinePath]);

        $this->artisan('shield:baseline')
            ->assertSuccessful();

        $content = json_decode(file_get_contents($this->baselinePath), true);

        // Verify hashes are present and unique
        $hashes = [];
        foreach ($content['errors'] as $analyzer => $analyzerIssues) {
            foreach ($analyzerIssues as $issue) {
                $this->assertArrayHasKey('hash', $issue);
                $hashes[] = $issue['hash'];
            }
        }

        $this->assertCount(count($hashes), array_unique($hashes), 'Hashes should be unique');
    }

    #[Test]
    public function it_does_not_duplicate_issues_when_merging(): void
    {
        // Create an existing baseline with an issue
        $existingBaseline = [
            'generated_at' => date('c'),
            'version' => '1.0.0',
            'errors' => [
                'test-analyzer' => [
                    [
                        'type' => 'hash',
                        'path' => '/app/Test.php',
                        'line' => 10,
                        'message' => 'Test issue',
                        'hash' => hash('sha256', json_encode([
                            'file' => '/app/Test.php',
                            'line' => 10,
                            'message' => 'Test issue',
                        ])),
                    ],
                ],
            ],
            'dont_report' => [],
        ];

        config(['shieldci.baseline_file' => $this->baselinePath]);
        file_put_contents($this->baselinePath, json_encode($existingBaseline, JSON_PRETTY_PRINT));

        // Register analyzer with same issue
        $manager = Mockery::mock(AnalyzerManager::class);

        $result = new AnalysisResult(
            analyzerId: 'test-analyzer',
            status: Status::Failed,
            message: 'Found issues',
            issues: [
                new Issue(
                    message: 'Test issue',
                    location: new Location('/app/Test.php', 10),
                    severity: Severity::High,
                    recommendation: 'Fix it',
                ),
            ],
            executionTime: 0.1,
            metadata: ['name' => 'Test Analyzer'],
        );

        $manager->shouldReceive('runAll')->andReturn(collect([$result]));
        $this->app->singleton(AnalyzerManager::class, fn () => $manager);

        $this->artisan('shield:baseline', ['--merge' => true])
            ->assertSuccessful();

        $content = json_decode(file_get_contents($this->baselinePath), true);

        // Should not have duplicate issues
        $this->assertCount(1, $content['errors']['test-analyzer']);
    }

    #[Test]
    public function it_merges_with_baseline_missing_errors_key(): void
    {
        $existingBaseline = [
            'generated_at' => date('c'),
            'version' => '1.0.0',
            'dont_report' => ['some-analyzer'],
        ];

        config(['shieldci.baseline_file' => $this->baselinePath]);
        file_put_contents($this->baselinePath, json_encode($existingBaseline, JSON_PRETTY_PRINT));

        $this->registerMockAnalyzerManager([]);

        $this->artisan('shield:baseline', ['--merge' => true])
            ->assertSuccessful();

        $content = json_decode(file_get_contents($this->baselinePath), true);
        $this->assertArrayHasKey('errors', $content);
        $this->assertContains('some-analyzer', $content['dont_report']);
    }

    #[Test]
    public function it_merges_with_baseline_missing_dont_report_key(): void
    {
        $existingBaseline = [
            'generated_at' => date('c'),
            'version' => '1.0.0',
            'errors' => [
                'old-analyzer' => [
                    ['type' => 'hash', 'path' => '/app/Old.php', 'line' => 1, 'message' => 'old', 'hash' => 'xyz'],
                ],
            ],
        ];

        config(['shieldci.baseline_file' => $this->baselinePath]);
        file_put_contents($this->baselinePath, json_encode($existingBaseline, JSON_PRETTY_PRINT));

        $this->registerMockAnalyzerManager([]);

        $this->artisan('shield:baseline', ['--merge' => true])
            ->assertSuccessful();

        $content = json_decode(file_get_contents($this->baselinePath), true);
        $this->assertArrayHasKey('errors', $content);
        $this->assertArrayHasKey('old-analyzer', $content['errors']);
    }

    #[Test]
    public function it_uses_analyzer_id_when_metadata_has_no_name(): void
    {
        $manager = Mockery::mock(AnalyzerManager::class);

        $result = new AnalysisResult(
            analyzerId: 'unnamed-analyzer',
            status: Status::Failed,
            message: 'Failed check',
            issues: [],
            executionTime: 0.1,
            metadata: [],
        );

        $manager->shouldReceive('runAll')->andReturn(collect([$result]));

        $this->app->singleton(AnalyzerManager::class, fn () => $manager);

        config(['shieldci.baseline_file' => $this->baselinePath]);

        $this->artisan('shield:baseline')
            ->assertSuccessful()
            ->expectsOutputToContain('dont_report');

        $content = json_decode(file_get_contents($this->baselinePath), true);
        $this->assertContains('unnamed-analyzer', $content['dont_report']);
    }

    /**
     * Register a mock AnalyzerManager with the given issues.
     */
    private function registerMockAnalyzerManager(array $issues): void
    {
        $manager = Mockery::mock(AnalyzerManager::class);

        $result = new AnalysisResult(
            analyzerId: 'test-analyzer',
            status: empty($issues) ? Status::Passed : Status::Failed,
            message: empty($issues) ? 'No issues' : 'Found issues',
            issues: $issues,
            executionTime: 0.1,
            metadata: [
                'name' => 'Test Analyzer',
            ],
        );

        $manager->shouldReceive('runAll')->andReturn(collect([$result]));

        $this->app->singleton(AnalyzerManager::class, fn () => $manager);
    }
}
