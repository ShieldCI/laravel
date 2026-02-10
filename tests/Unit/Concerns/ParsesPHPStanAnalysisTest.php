<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Concerns;

use Mockery;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\ParsesPHPStanAnalysis;
use ShieldCI\Support\PHPStan;
use ShieldCI\Tests\TestCase;

class ParsesPHPStanAnalysisTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    #[Test]
    public function it_parses_phpstan_analysis_with_search(): void
    {
        $class = $this->createAnalysisClass();

        $phpStan = Mockery::mock(PHPStan::class);
        $phpStan->shouldReceive('parseAnalysis')
            ->with('deprecated')
            ->andReturn([
                ['message' => 'Using deprecated method', 'path' => '/app/Test.php', 'line' => 10],
                ['message' => 'Another deprecated call', 'path' => '/app/Service.php', 'line' => 25],
            ]);

        $issues = [];
        $class->publicParsePHPStanAnalysis($phpStan, 'deprecated', $issues);

        $this->assertCount(2, $issues);
        $this->assertInstanceOf(Issue::class, $issues[0]);
    }

    #[Test]
    public function it_skips_malformed_traces_in_parse(): void
    {
        $class = $this->createAnalysisClass();

        $phpStan = Mockery::mock(PHPStan::class);
        $phpStan->shouldReceive('parseAnalysis')
            ->andReturn([
                ['message' => 'Valid', 'path' => '/app/Test.php', 'line' => 10],
                ['message' => 'Missing path'], // Missing path and line
                ['path' => '/app/Test.php', 'line' => 5], // Missing message
                ['message' => 123, 'path' => '/app/Test.php', 'line' => 5], // Non-string message
            ]);

        $issues = [];
        $class->publicParsePHPStanAnalysis($phpStan, 'search', $issues);

        $this->assertCount(1, $issues);
    }

    #[Test]
    public function it_matches_phpstan_analysis_with_pattern(): void
    {
        $class = $this->createAnalysisClass();

        $phpStan = Mockery::mock(PHPStan::class);
        $phpStan->shouldReceive('match')
            ->with('collection method')
            ->andReturn([
                ['message' => 'Collection method used', 'path' => '/app/Repo.php', 'line' => 15],
            ]);

        $issues = [];
        $class->publicMatchPHPStanAnalysis($phpStan, 'collection method', $issues);

        $this->assertCount(1, $issues);
    }

    #[Test]
    public function it_preg_matches_phpstan_analysis(): void
    {
        $class = $this->createAnalysisClass();

        $phpStan = Mockery::mock(PHPStan::class);
        $phpStan->shouldReceive('pregMatch')
            ->with('/Model::all/')
            ->andReturn([
                ['message' => 'Model::all() usage', 'path' => '/app/Controller.php', 'line' => 30],
            ]);

        $issues = [];
        $class->publicPregMatchPHPStanAnalysis($phpStan, '/Model::all/', $issues);

        $this->assertCount(1, $issues);
    }

    #[Test]
    public function it_skips_malformed_traces_in_preg_match(): void
    {
        $class = $this->createAnalysisClass();

        $phpStan = Mockery::mock(PHPStan::class);
        $phpStan->shouldReceive('pregMatch')
            ->andReturn([
                ['message' => 'Valid', 'path' => '/app/Test.php', 'line' => 10],
                ['invalid' => 'trace'],
                ['message' => null, 'path' => '/app/Test.php', 'line' => 5],
            ]);

        $issues = [];
        $class->publicPregMatchPHPStanAnalysis($phpStan, '/pattern/', $issues);

        $this->assertCount(1, $issues);
    }

    #[Test]
    public function it_generates_recommendation_for_collection_method(): void
    {
        $class = $this->createAnalysisClass();

        $recommendation = $class->publicGetRecommendationFromMessage(
            'Method App\Models\User::count() should be used instead'
        );

        $this->assertStringContainsString('database level', $recommendation);
    }

    #[Test]
    public function it_generates_recommendation_for_query_aggregation(): void
    {
        $class = $this->createAnalysisClass();

        $recommendation = $class->publicGetRecommendationFromMessage(
            'This count could have been retrieved as a query instead of collection operation'
        );

        $this->assertStringContainsString('database query level', $recommendation);
    }

    #[Test]
    public function it_generates_default_recommendation_for_unknown_messages(): void
    {
        $class = $this->createAnalysisClass();

        $recommendation = $class->publicGetRecommendationFromMessage('Some unknown PHPStan message');

        $this->assertStringContainsString('Optimize', $recommendation);
    }

    /**
     * @return object
     */
    private function createAnalysisClass()
    {
        return new class
        {
            use ParsesPHPStanAnalysis;

            public function publicParsePHPStanAnalysis(PHPStan $phpStan, string|array $search, array &$issues): void
            {
                $this->parsePHPStanAnalysis($phpStan, $search, $issues);
            }

            public function publicMatchPHPStanAnalysis(PHPStan $phpStan, string|array $pattern, array &$issues): void
            {
                $this->matchPHPStanAnalysis($phpStan, $pattern, $issues);
            }

            public function publicPregMatchPHPStanAnalysis(PHPStan $phpStan, string $pattern, array &$issues): void
            {
                $this->pregMatchPHPStanAnalysis($phpStan, $pattern, $issues);
            }

            public function publicGetRecommendationFromMessage(string $message): string
            {
                return $this->getRecommendationFromMessage($message);
            }

            protected function createIssueWithSnippet(
                string $message,
                string $filePath,
                int $lineNumber,
                Severity $severity,
                string $recommendation,
                ?int $column = null,
                ?int $contextLines = null,
                ?string $code = null,
                array $metadata = []
            ): Issue {
                return new Issue(
                    message: $message,
                    location: new Location($filePath, $lineNumber),
                    severity: $severity,
                    recommendation: $recommendation,
                    code: $code,
                    metadata: $metadata,
                );
            }
        };
    }
}
