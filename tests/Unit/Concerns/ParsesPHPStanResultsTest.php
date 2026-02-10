<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Concerns;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\ParsesPHPStanResults;
use ShieldCI\Tests\TestCase;

class ParsesPHPStanResultsTest extends TestCase
{
    #[Test]
    public function it_creates_issues_from_phpstan_results(): void
    {
        $class = $this->createParsesPHPStanResultsClass();

        $issues = collect([
            ['file' => '/app/Test.php', 'line' => 10, 'message' => 'Unused method call'],
            ['file' => '/app/Service.php', 'line' => 25, 'message' => 'Undefined variable'],
        ]);

        $result = $class->publicCreateIssuesFromPHPStanResults(
            $issues,
            'PHPStan issue detected',
            Severity::High,
            fn (string $msg) => "Fix: {$msg}"
        );

        $this->assertCount(2, $result);
        $this->assertInstanceOf(Issue::class, $result[0]);
        $this->assertEquals('PHPStan issue detected', $result[0]->message);
        $this->assertEquals(Severity::High, $result[0]->severity);
    }

    #[Test]
    public function it_limits_issues_to_50(): void
    {
        $class = $this->createParsesPHPStanResultsClass();

        // Create 60 issues
        $issues = collect(array_map(fn ($i) => [
            'file' => "/app/Test{$i}.php",
            'line' => $i,
            'message' => "Issue {$i}",
        ], range(1, 60)));

        $result = $class->publicCreateIssuesFromPHPStanResults(
            $issues,
            'PHPStan issue',
            Severity::Medium,
            fn (string $msg) => 'Fix it'
        );

        $this->assertCount(50, $result);
    }

    #[Test]
    public function it_skips_issues_with_missing_fields(): void
    {
        $class = $this->createParsesPHPStanResultsClass();

        $issues = collect([
            ['file' => '/app/Test.php', 'line' => 10], // Missing message
            ['file' => '/app/Test.php', 'message' => 'Error'], // Missing line
            ['line' => 10, 'message' => 'Error'], // Missing file
            ['file' => '/app/Valid.php', 'line' => 5, 'message' => 'Valid issue'],
        ]);

        $result = $class->publicCreateIssuesFromPHPStanResults(
            $issues,
            'PHPStan issue',
            Severity::High,
            fn (string $msg) => 'Fix it'
        );

        $this->assertCount(1, $result);
    }

    #[Test]
    public function it_handles_non_string_file_or_message(): void
    {
        $class = $this->createParsesPHPStanResultsClass();

        $issues = collect([
            ['file' => 123, 'line' => 10, 'message' => 'Error'], // Non-string file
            ['file' => '/app/Test.php', 'line' => 10, 'message' => ['array']], // Non-string message
            ['file' => '/app/Valid.php', 'line' => 5, 'message' => 'Valid'],
        ]);

        $result = $class->publicCreateIssuesFromPHPStanResults(
            $issues,
            'PHPStan issue',
            Severity::High,
            fn (string $msg) => 'Fix it'
        );

        $this->assertCount(1, $result);
    }

    #[Test]
    public function it_normalizes_invalid_line_numbers(): void
    {
        $class = $this->createParsesPHPStanResultsClass();

        $issues = collect([
            ['file' => '/app/Test1.php', 'line' => 0, 'message' => 'Issue 1'],
            ['file' => '/app/Test2.php', 'line' => -5, 'message' => 'Issue 2'],
            ['file' => '/app/Test3.php', 'line' => 10, 'message' => 'Issue 3'],
        ]);

        $result = $class->publicCreateIssuesFromPHPStanResults(
            $issues,
            'PHPStan issue',
            Severity::Medium,
            fn (string $msg) => 'Fix it'
        );

        // Invalid line numbers should be normalized to 1
        $this->assertCount(3, $result);
        $this->assertEquals(1, $result[0]->location->line);
        $this->assertEquals(1, $result[1]->location->line);
        $this->assertEquals(10, $result[2]->location->line);
    }

    #[Test]
    public function it_formats_issue_count_message_when_truncated(): void
    {
        $class = $this->createParsesPHPStanResultsClass();

        $message = $class->publicFormatIssueCountMessage(100, 50, 'dead code issues');

        $this->assertEquals('Found 100 dead code issues (showing first 50)', $message);
    }

    #[Test]
    public function it_formats_issue_count_message_when_not_truncated(): void
    {
        $class = $this->createParsesPHPStanResultsClass();

        $message = $class->publicFormatIssueCountMessage(25, 25, 'deprecated code usages');

        $this->assertEquals('Found 25 deprecated code usages', $message);
    }

    #[Test]
    public function it_formats_issue_count_message_for_zero_issues(): void
    {
        $class = $this->createParsesPHPStanResultsClass();

        $message = $class->publicFormatIssueCountMessage(0, 0, 'issues');

        $this->assertEquals('Found 0 issues', $message);
    }

    #[Test]
    public function it_calls_recommendation_callback_with_message(): void
    {
        $class = $this->createParsesPHPStanResultsClass();
        $callbackMessages = [];

        $issues = collect([
            ['file' => '/app/Test.php', 'line' => 10, 'message' => 'First error message'],
            ['file' => '/app/Test2.php', 'line' => 20, 'message' => 'Second error message'],
        ]);

        $class->publicCreateIssuesFromPHPStanResults(
            $issues,
            'PHPStan issue',
            Severity::High,
            function (string $msg) use (&$callbackMessages) {
                $callbackMessages[] = $msg;

                return "Recommendation for: {$msg}";
            }
        );

        $this->assertCount(2, $callbackMessages);
        $this->assertEquals('First error message', $callbackMessages[0]);
        $this->assertEquals('Second error message', $callbackMessages[1]);
    }

    /**
     * @return object
     */
    private function createParsesPHPStanResultsClass()
    {
        return new class
        {
            use ParsesPHPStanResults;

            /**
             * @param  \Illuminate\Support\Collection<int, array{file: string, line: int, message: string}>  $issues
             * @return array<int, Issue>
             */
            public function publicCreateIssuesFromPHPStanResults(
                \Illuminate\Support\Collection $issues,
                string $issueMessage,
                Severity $severity,
                callable $recommendationCallback
            ): array {
                return $this->createIssuesFromPHPStanResults($issues, $issueMessage, $severity, $recommendationCallback);
            }

            public function publicFormatIssueCountMessage(int $totalCount, int $displayedCount, string $issueType): string
            {
                return $this->formatIssueCountMessage($totalCount, $displayedCount, $issueType);
            }

            /**
             * @param  array<string, mixed>  $metadata
             */
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
