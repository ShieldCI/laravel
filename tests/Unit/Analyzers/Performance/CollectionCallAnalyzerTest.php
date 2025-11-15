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

        $this->assertFailed($result);
        $this->assertStringContainsString('PHPStan analysis failed', $result->getMessage());
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

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
