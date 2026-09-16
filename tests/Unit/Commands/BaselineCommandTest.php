<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Commands;

use Illuminate\Support\Facades\Artisan;
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

    /** @test */
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

    /** @test */
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
        $this->assertIsArray($content);
        $this->assertArrayHasKey('errors', $content);
        $this->assertArrayHasKey('generated_at', $content);
        $this->assertArrayHasKey('version', $content);
    }

    /** @test */
    #[Test]
    public function it_supports_ci_mode_flag(): void
    {
        $this->registerMockAnalyzerManager([]);

        config(['shieldci.baseline_file' => $this->baselinePath]);

        $this->artisan('shield:baseline', ['--ci' => true])
            ->assertSuccessful()
            ->expectsOutputToContain('CI mode');
    }

    /** @test */
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
        $this->assertIsArray($content);
        $this->assertArrayHasKey('errors', $content);
    }

    /** @test */
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
        $this->assertIsArray($content);
        $this->assertArrayHasKey('dont_report', $content);
        $this->assertContains('failed-no-issues', $content['dont_report']);
    }

    /** @test */
    #[Test]
    public function it_does_not_add_an_errored_analyzer_to_dont_report(): void
    {
        // An errored analyzer has no issues by construction, so it used to land in the
        // dont_report branch alongside a genuine issueless failure. One baseline taken while
        // an analyzer was broken then waived it for good, outliving the fix.
        $manager = Mockery::mock(AnalyzerManager::class);

        $result = new AnalysisResult(
            analyzerId: 'broken-analyzer',
            status: Status::Error,
            message: 'Analysis failed: parser exploded',
            issues: [],
            executionTime: 0.1,
            metadata: [
                'name' => 'Broken Analyzer',
            ],
        );

        $manager->shouldReceive('runAll')->andReturn(collect([$result]));

        $this->app->singleton(AnalyzerManager::class, fn () => $manager);

        config(['shieldci.baseline_file' => $this->baselinePath]);

        $this->artisan('shield:baseline')->assertSuccessful();

        $content = json_decode((string) file_get_contents($this->baselinePath), true);
        $this->assertIsArray($content);

        $dontReport = $content['dont_report'] ?? null;
        $this->assertIsArray($dontReport);
        $this->assertNotContains('broken-analyzer', $dontReport);
        $this->assertArrayNotHasKey('broken-analyzer', $content['errors']);
    }

    /** @test */
    #[Test]
    public function it_reports_an_analyzer_that_could_not_run(): void
    {
        // The baseline file cannot record that it is incomplete, so the command has to say so.
        $manager = Mockery::mock(AnalyzerManager::class);

        $result = new AnalysisResult(
            analyzerId: 'broken-analyzer',
            status: Status::Error,
            message: 'Analysis failed: parser exploded',
            issues: [],
            executionTime: 0.1,
            metadata: [
                'name' => 'Broken Analyzer',
            ],
        );

        $manager->shouldReceive('runAll')->andReturn(collect([$result]));

        $this->app->singleton(AnalyzerManager::class, fn () => $manager);

        config(['shieldci.baseline_file' => $this->baselinePath]);

        $exitCode = Artisan::call('shield:baseline');
        $output = Artisan::output();

        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString('could not run', $output);
        $this->assertStringContainsString('broken-analyzer', $output);
        $this->assertStringContainsString('Broken Analyzer', $output);
    }

    /** @test */
    #[Test]
    public function it_still_adds_an_issueless_failure_to_dont_report_alongside_an_errored_analyzer(): void
    {
        // The two shapes both reach the command with no issues, and only one of them is a
        // verdict the user can choose to waive.
        $manager = Mockery::mock(AnalyzerManager::class);

        $manager->shouldReceive('runAll')->andReturn(collect([
            new AnalysisResult(
                analyzerId: 'broken-analyzer',
                status: Status::Error,
                message: 'Analysis failed: parser exploded',
                issues: [],
                executionTime: 0.1,
                metadata: ['name' => 'Broken Analyzer'],
            ),
            new AnalysisResult(
                analyzerId: 'issueless-analyzer',
                status: Status::Failed,
                message: 'Configuration is invalid',
                issues: [],
                executionTime: 0.1,
                metadata: ['name' => 'Issueless Analyzer'],
            ),
        ]));

        $this->app->singleton(AnalyzerManager::class, fn () => $manager);

        config(['shieldci.baseline_file' => $this->baselinePath]);

        $this->artisan('shield:baseline')->assertSuccessful();

        $content = json_decode((string) file_get_contents($this->baselinePath), true);
        $this->assertIsArray($content);

        $dontReport = $content['dont_report'] ?? null;
        $this->assertIsArray($dontReport);
        $this->assertContains('issueless-analyzer', $dontReport);
        $this->assertNotContains('broken-analyzer', $dontReport);
    }

    /** @test */
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

    /** @test */
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

    /** @test */
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

    /** @test */
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
        $this->assertIsArray($content);

        // Verify hashes are present and unique
        $hashes = [];
        $errors = $content['errors'] ?? [];
        $this->assertIsArray($errors);
        foreach ($errors as $analyzerIssues) {
            $this->assertIsArray($analyzerIssues);
            foreach ($analyzerIssues as $issue) {
                $this->assertIsArray($issue);
                $this->assertArrayHasKey('hash', $issue);
                $hashes[] = $issue['hash'];
            }
        }

        $this->assertCount(count($hashes), array_unique(array_values(array_filter($hashes, 'is_string'))), 'Hashes should be unique');
    }

    /** @test */
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

    /** @test */
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
        $this->assertIsArray($content);
        $this->assertArrayHasKey('errors', $content);
        $this->assertContains('some-analyzer', $content['dont_report']);
    }

    /** @test */
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
        $this->assertIsArray($content);
        $this->assertArrayHasKey('errors', $content);
        $this->assertIsArray($content['errors']);
        $this->assertArrayHasKey('old-analyzer', $content['errors']);
    }

    /** @test */
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
     *
     * @param  array<int, Issue>  $issues
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
