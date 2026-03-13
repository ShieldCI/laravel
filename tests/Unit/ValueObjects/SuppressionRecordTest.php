<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\ValueObjects;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Enums\SuppressionType;
use ShieldCI\Tests\TestCase;
use ShieldCI\ValueObjects\SuppressionRecord;

class SuppressionRecordTest extends TestCase
{
    private Issue $issue;

    protected function setUp(): void
    {
        parent::setUp();

        $this->issue = new Issue(
            message: 'SQL Injection detected',
            location: new Location('/app/Vulnerable.php', 42),
            severity: Severity::Critical,
            recommendation: 'Use prepared statements',
        );
    }

    #[Test]
    public function it_stores_all_properties(): void
    {
        $record = new SuppressionRecord(
            $this->issue,
            SuppressionType::Config,
            'path_pattern: app/Legacy/*.php',
        );

        $this->assertSame($this->issue, $record->issue);
        $this->assertSame(SuppressionType::Config, $record->type);
        $this->assertSame('path_pattern: app/Legacy/*.php', $record->description);
    }

    #[Test]
    public function to_array_includes_all_issue_fields_and_suppression_block(): void
    {
        $record = new SuppressionRecord(
            $this->issue,
            SuppressionType::Config,
            'path_pattern: app/Legacy/*.php',
        );

        $arr = $record->toArray();

        $this->assertSame('SQL Injection detected', $arr['message']);
        $this->assertSame('critical', $arr['severity']);
        $this->assertSame('Use prepared statements', $arr['recommendation']);
        $this->assertArrayHasKey('location', $arr);
        $this->assertArrayHasKey('suppression', $arr);
        $this->assertSame('config', $arr['suppression']['type']);
        $this->assertSame('path_pattern: app/Legacy/*.php', $arr['suppression']['description']);
    }

    #[Test]
    public function to_array_serializes_inline_type_as_string(): void
    {
        $record = new SuppressionRecord(
            $this->issue,
            SuppressionType::Inline,
            '@shieldci-ignore at /app/Vulnerable.php:42',
        );

        $arr = $record->toArray();

        $this->assertSame('inline', $arr['suppression']['type']);
    }

    #[Test]
    public function to_array_serializes_baseline_type_as_string(): void
    {
        $record = new SuppressionRecord(
            $this->issue,
            SuppressionType::Baseline,
            'baseline hash: abc12345...',
        );

        $arr = $record->toArray();

        $this->assertSame('baseline', $arr['suppression']['type']);
    }
}
