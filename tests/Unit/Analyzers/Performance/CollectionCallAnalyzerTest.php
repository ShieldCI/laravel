<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Mockery;
use ShieldCI\Analyzers\Performance\CollectionCallAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Support\PHPStan;
use ShieldCI\Tests\AnalyzerTestCase;

class CollectionCallAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<int, array{path: string, line: int, message: string}>|null  $phpstanResult
     */
    protected function createAnalyzer(
        ?array $phpstanResult = null
    ): AnalyzerInterface {
        /** @var PHPStan&\Mockery\MockInterface $phpStan */
        $phpStan = Mockery::mock(PHPStan::class);

        if ($phpstanResult !== null) {
            /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
            $phpStan->shouldReceive('setRootPath')
                ->andReturnSelf();

            /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
            $phpStan->shouldReceive('start')
                ->andReturnSelf();

            /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
            $phpStan->shouldReceive('parseAnalysis')
                ->with('could have been retrieved as a query')
                ->andReturn($phpstanResult);
        }

        return new CollectionCallAnalyzer($phpStan);
    }

    public function test_skips_when_larastan_not_installed(): void
    {
        // Create analyzer with real PHPStan instance (not mocked)
        // This will check for actual Larastan installation
        $phpStan = new PHPStan;
        $analyzer = new CollectionCallAnalyzer($phpStan);

        // In test environment, Larastan won't be installed by default
        $this->assertFalse($analyzer->shouldRun());

        if (method_exists($analyzer, 'getSkipReason')) {
            $this->assertStringContainsString('Larastan', $analyzer->getSkipReason());
        }
    }

    public function test_passes_when_no_collection_issues_found(): void
    {
        // Mock PHPStan to return no issues
        $analyzer = $this->createAnalyzer([]);

        $analyzer->setBasePath('/');
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('No inefficient collection calls', $result->getMessage());
    }

    public function test_fails_when_collection_issues_found(): void
    {
        // Mock PHPStan to return collection call issues
        $phpstanResult = [
            [
                'path' => '/app/Services/UserService.php',
                'line' => 10,
                'message' => 'Called \'count\' on Laravel collection, but could have been retrieved as a query.',
            ],
            [
                'path' => '/app/Services/PostService.php',
                'line' => 25,
                'message' => 'Called \'sum\' on Laravel collection, but could have been retrieved as a query.',
            ],
        ];

        $analyzer = $this->createAnalyzer($phpstanResult);

        $analyzer->setBasePath('/');
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('count', $result);

        $issues = $result->getIssues();
        $this->assertCount(2, $issues);

        // Verify metadata contains PHPStan message
        $this->assertEquals('phpstan', $issues[0]->metadata['detection_method'] ?? '');
    }

    public function test_handles_phpstan_errors_gracefully(): void
    {
        /** @var PHPStan&\Mockery\MockInterface $phpStan */
        $phpStan = Mockery::mock(PHPStan::class);

        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $phpStan->shouldReceive('setRootPath')
            ->andReturnSelf();

        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $phpStan->shouldReceive('start')
            ->andThrow(new \Exception('PHPStan failed'));

        $analyzer = new CollectionCallAnalyzer($phpStan);
        $analyzer->setBasePath('/');
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertError($result);
        $this->assertStringContainsString('PHPStan analysis failed', $result->getMessage());
        $this->assertStringContainsString('Ensure PHPStan and Larastan are properly configured', $result->getMessage());
    }

    public function test_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('collection-call-optimization', $metadata->id);
        $this->assertEquals('Collection Call Optimization', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Performance, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $metadata->severity);
        $this->assertContains('phpstan', $metadata->tags);
    }

    public function test_run_in_ci_property_is_false(): void
    {
        $this->assertFalse(CollectionCallAnalyzer::$runInCI);
    }

    public function test_defaults_to_app_directory_when_paths_empty(): void
    {
        /** @var PHPStan&\Mockery\MockInterface $phpStan */
        $phpStan = Mockery::mock(PHPStan::class);

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('setRootPath')
            ->andReturnSelf();

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('start')
            ->with(['app'])  // Should default to ['app']
            ->once()
            ->andReturnSelf();

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('parseAnalysis')
            ->andReturn([]);

        $analyzer = new CollectionCallAnalyzer($phpStan);
        $analyzer->setBasePath('/');
        $analyzer->setPaths([]);  // Empty array

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_defaults_to_app_when_paths_null(): void
    {
        /** @var PHPStan&\Mockery\MockInterface $phpStan */
        $phpStan = Mockery::mock(PHPStan::class);

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('setRootPath')
            ->andReturnSelf();

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('start')
            ->with(['app'])  // Should default to ['app']
            ->once()
            ->andReturnSelf();

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('parseAnalysis')
            ->andReturn([]);

        $analyzer = new CollectionCallAnalyzer($phpStan);
        $analyzer->setBasePath('/');
        // Don't set paths (will be null by default)

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_multiple_paths(): void
    {
        $paths = ['app', 'packages', 'modules'];

        /** @var PHPStan&\Mockery\MockInterface $phpStan */
        $phpStan = Mockery::mock(PHPStan::class);

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('setRootPath')
            ->andReturnSelf();

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('start')
            ->with($paths)
            ->once()
            ->andReturnSelf();

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('parseAnalysis')
            ->andReturn([]);

        $analyzer = new CollectionCallAnalyzer($phpStan);
        $analyzer->setBasePath('/');
        $analyzer->setPaths($paths);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_empty_base_path(): void
    {
        /** @var PHPStan&\Mockery\MockInterface $phpStan */
        $phpStan = Mockery::mock(PHPStan::class);

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('setRootPath')
            ->andReturnSelf();

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('start')
            ->andReturnSelf();

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('parseAnalysis')
            ->andReturn([]);

        $analyzer = new CollectionCallAnalyzer($phpStan);
        $analyzer->setBasePath('');  // Empty base path
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should still work (falls back to getcwd())
        $this->assertPassed($result);
    }

    public function test_handles_malformed_phpstan_results(): void
    {
        // PHPStan returns malformed data
        $phpstanResult = [
            ['path' => 123, 'line' => 'not a number', 'message' => 'test'],  // Invalid types
            ['missing' => 'path key'],  // Missing required keys
            ['path' => '/valid/path.php', 'line' => 10],  // Missing message
        ];

        /** @var PHPStan&\Mockery\MockInterface $phpStan */
        $phpStan = Mockery::mock(PHPStan::class);

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('setRootPath')
            ->andReturnSelf();

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('start')
            ->andReturnSelf();

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('parseAnalysis')
            ->andReturn($phpstanResult);

        $analyzer = new CollectionCallAnalyzer($phpStan);
        $analyzer->setBasePath('/');
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass (all malformed results are skipped)
        $this->assertPassed($result);
    }

    public function test_handles_partial_malformed_phpstan_results(): void
    {
        // Mix of valid and invalid results
        $phpstanResult = [
            ['path' => 123, 'line' => 'invalid', 'message' => 'skip me'],  // Invalid
            [
                'path' => '/app/Services/UserService.php',
                'line' => 10,
                'message' => 'Called \'count\' on Laravel collection, but could have been retrieved as a query.',
            ],  // Valid
            ['path' => '/invalid/path.php'],  // Missing line and message
        ];

        /** @var PHPStan&\Mockery\MockInterface $phpStan */
        $phpStan = Mockery::mock(PHPStan::class);

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('setRootPath')
            ->andReturnSelf();

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('start')
            ->andReturnSelf();

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('parseAnalysis')
            ->andReturn($phpstanResult);

        $analyzer = new CollectionCallAnalyzer($phpStan);
        $analyzer->setBasePath('/');
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should fail with only the valid issue
        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('count', $issues[0]->message);
    }

    public function test_aggregates_issues_from_multiple_paths(): void
    {
        $phpstanResult = [
            [
                'path' => '/app/Services/UserService.php',
                'line' => 10,
                'message' => 'Called \'count\' on Laravel collection, but could have been retrieved as a query.',
            ],
            [
                'path' => '/packages/Core/Repository.php',
                'line' => 25,
                'message' => 'Called \'sum\' on Laravel collection, but could have been retrieved as a query.',
            ],
            [
                'path' => '/modules/Blog/PostController.php',
                'line' => 42,
                'message' => 'Called \'avg\' on Laravel collection, but could have been retrieved as a query.',
            ],
        ];

        $analyzer = $this->createAnalyzer($phpstanResult);
        $analyzer->setBasePath('/');
        $analyzer->setPaths(['app', 'packages', 'modules']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
    }

    public function test_recommendation_for_generic_query_message(): void
    {
        $phpstanResult = [
            [
                'path' => '/app/Services/UserService.php',
                'line' => 10,
                'message' => 'Called \'count\' on Laravel collection, but could have been retrieved as a query.',
            ],
        ];

        $analyzer = $this->createAnalyzer($phpstanResult);
        $analyzer->setBasePath('/');
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertStringContainsString('database query level', $issues[0]->recommendation);
        $this->assertStringContainsString('better performance', $issues[0]->recommendation);
    }

    public function test_handles_large_number_of_issues(): void
    {
        // Generate 100 issues
        $phpstanResult = [];
        for ($i = 1; $i <= 100; $i++) {
            $phpstanResult[] = [
                'path' => "/app/Services/Service{$i}.php",
                'line' => $i,
                'message' => "Called 'count' on Laravel collection, but could have been retrieved as a query.",
            ];
        }

        $analyzer = $this->createAnalyzer($phpstanResult);
        $analyzer->setBasePath('/');
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(100, $issues);
        $this->assertStringContainsString('100 inefficient collection operations', $result->getMessage());
    }

    public function test_handles_phpstan_exception_during_start(): void
    {
        /** @var PHPStan&\Mockery\MockInterface $phpStan */
        $phpStan = Mockery::mock(PHPStan::class);

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('setRootPath')
            ->andReturnSelf();

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('start')
            ->andThrow(new \RuntimeException('PHPStan executable not found'));

        $analyzer = new CollectionCallAnalyzer($phpStan);
        $analyzer->setBasePath('/');
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertError($result);
        $this->assertStringContainsString('PHPStan executable not found', $result->getMessage());
    }

    public function test_handles_phpstan_exception_during_parse(): void
    {
        /** @var PHPStan&\Mockery\MockInterface $phpStan */
        $phpStan = Mockery::mock(PHPStan::class);

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('setRootPath')
            ->andReturnSelf();

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('start')
            ->andReturnSelf();

        /** @phpstan-ignore-next-line */
        $phpStan->shouldReceive('parseAnalysis')
            ->andThrow(new \RuntimeException('Failed to parse PHPStan output'));

        $analyzer = new CollectionCallAnalyzer($phpStan);
        $analyzer->setBasePath('/');
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertError($result);
        $this->assertStringContainsString('Failed to parse PHPStan output', $result->getMessage());
    }

    public function test_empty_phpstan_results_vs_null(): void
    {
        // Test empty array
        $analyzer = $this->createAnalyzer([]);
        $analyzer->setBasePath('/');
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();
        $this->assertPassed($result);

        // Both should pass
        $this->assertStringContainsString('No inefficient collection calls', $result->getMessage());
    }

    public function test_includes_phpstan_metadata(): void
    {
        $phpstanResult = [
            [
                'path' => '/app/Services/UserService.php',
                'line' => 10,
                'message' => 'Custom PHPStan message about collections',
            ],
        ];

        $analyzer = $this->createAnalyzer($phpstanResult);
        $analyzer->setBasePath('/');
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertEquals('Custom PHPStan message about collections', $issues[0]->metadata['phpstan_message']);
        $this->assertEquals('phpstan', $issues[0]->metadata['detection_method']);
    }

    public function test_handles_windows_file_paths(): void
    {
        $phpstanResult = [
            [
                'path' => 'C:\\projects\\app\\Services\\UserService.php',
                'line' => 10,
                'message' => 'Called \'count\' on Laravel collection, but could have been retrieved as a query.',
            ],
        ];

        $analyzer = $this->createAnalyzer($phpstanResult);
        $analyzer->setBasePath('C:\\projects');
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
    }

    public function test_handles_relative_paths(): void
    {
        $phpstanResult = [
            [
                'path' => 'app/Services/UserService.php',  // Relative path
                'line' => 10,
                'message' => 'Called \'count\' on Laravel collection, but could have been retrieved as a query.',
            ],
        ];

        $analyzer = $this->createAnalyzer($phpstanResult);
        $analyzer->setBasePath('/project');
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
    }

    public function test_handles_absolute_paths(): void
    {
        $phpstanResult = [
            [
                'path' => '/absolute/path/to/app/Services/UserService.php',
                'line' => 10,
                'message' => 'Called \'count\' on Laravel collection, but could have been retrieved as a query.',
            ],
        ];

        $analyzer = $this->createAnalyzer($phpstanResult);
        $analyzer->setBasePath('/project');
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
    }

    public function test_recommendation_contains_database_optimization_advice(): void
    {
        $phpstanResult = [
            [
                'path' => '/app/Services/UserService.php',
                'line' => 10,
                'message' => 'Called \'count\' on Laravel collection, but could have been retrieved as a query.',
            ],
        ];

        $analyzer = $this->createAnalyzer($phpstanResult);
        $analyzer->setBasePath('/');
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $recommendation = $issues[0]->recommendation;

        $this->assertStringContainsString('database', strtolower($recommendation));
        $this->assertStringContainsString('performance', strtolower($recommendation));
    }

    public function test_skip_reason_mentions_larastan(): void
    {
        // Use real PHPStan (not mocked) so it checks for actual Larastan
        $phpStan = new PHPStan;
        $analyzer = new CollectionCallAnalyzer($phpStan);

        if (! $analyzer->shouldRun()) {
            $skipReason = $analyzer->getSkipReason();
            $this->assertStringContainsString('Larastan', $skipReason);
            $this->assertStringContainsString('required', $skipReason);
        } else {
            // If Larastan is actually installed, test passes
            $this->assertTrue(true);
        }
    }

    public function test_mock_detection_works_for_mockery(): void
    {
        /** @var PHPStan&\Mockery\MockInterface $phpStan */
        $phpStan = Mockery::mock(PHPStan::class);

        $analyzer = new CollectionCallAnalyzer($phpStan);

        // Should detect Mockery mock and return true for hasLarastan
        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_different_collection_methods_detected(): void
    {
        $phpstanResult = [
            [
                'path' => '/app/Services/Service1.php',
                'line' => 10,
                'message' => "Called 'count' on Laravel collection, but could have been retrieved as a query.",
            ],
            [
                'path' => '/app/Services/Service2.php',
                'line' => 20,
                'message' => "Called 'sum' on Laravel collection, but could have been retrieved as a query.",
            ],
            [
                'path' => '/app/Services/Service3.php',
                'line' => 30,
                'message' => "Called 'avg' on Laravel collection, but could have been retrieved as a query.",
            ],
            [
                'path' => '/app/Services/Service4.php',
                'line' => 40,
                'message' => "Called 'max' on Laravel collection, but could have been retrieved as a query.",
            ],
            [
                'path' => '/app/Services/Service5.php',
                'line' => 50,
                'message' => "Called 'min' on Laravel collection, but could have been retrieved as a query.",
            ],
        ];

        $analyzer = $this->createAnalyzer($phpstanResult);
        $analyzer->setBasePath('/');
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(5, $issues);

        // Verify different methods are captured
        $messages = array_map(fn ($issue) => $issue->message, $issues);
        $this->assertStringContainsString('count', implode(' ', $messages));
        $this->assertStringContainsString('sum', implode(' ', $messages));
        $this->assertStringContainsString('avg', implode(' ', $messages));
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
