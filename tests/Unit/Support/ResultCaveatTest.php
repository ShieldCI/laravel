<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\AnalyzersCore\Enums\Status;
use ShieldCI\Support\ResultCaveat;
use ShieldCI\Tests\TestCase;

class ResultCaveatTest extends TestCase
{
    /** @test */
    #[Test]
    public function it_round_trips_the_text_and_status(): void
    {
        $caveat = ResultCaveat::from(ResultCaveat::metadata('Example probe not verified', Status::Error));

        $this->assertNotNull($caveat);
        $this->assertSame('Example probe not verified', $caveat->text);
        $this->assertSame(Status::Error, $caveat->status);
    }

    /** @test */
    #[Test]
    public function the_status_defaults_to_warning(): void
    {
        $metadata = ResultCaveat::metadata('Example probe not verified');

        $this->assertSame(
            [ResultCaveat::METADATA_KEY => 'Example probe not verified', ResultCaveat::STATUS_KEY => 'warning'],
            $metadata
        );
        $this->assertSame(Status::Warning, ResultCaveat::from($metadata)?->status);
    }

    /**
     * @return array<string, array{0: array<string, mixed>}>
     */
    public static function metadataWithoutCaveat(): array
    {
        return [
            'no key' => [[]],
            'empty text' => [[ResultCaveat::METADATA_KEY => '', ResultCaveat::STATUS_KEY => 'error']],
            'non-string text' => [[ResultCaveat::METADATA_KEY => ['Example'], ResultCaveat::STATUS_KEY => 'error']],
            'null text' => [[ResultCaveat::METADATA_KEY => null]],
        ];
    }

    /**
     * @dataProvider metadataWithoutCaveat
     *
     * @param  array<string, mixed>  $metadata
     */
    #[Test]
    #[DataProvider('metadataWithoutCaveat')]
    public function it_reads_no_caveat_from_malformed_text(array $metadata): void
    {
        $this->assertNull(ResultCaveat::from($metadata));
    }

    /**
     * @return array<string, array{0: mixed, 1: Status}>
     */
    public static function storedStatuses(): array
    {
        return [
            'warning' => ['warning', Status::Warning],
            'failed' => ['failed', Status::Failed],
            'error' => ['error', Status::Error],
            'missing' => [null, Status::Warning],
            'unknown value' => ['example', Status::Warning],
            'non-string' => [3, Status::Warning],
            'passed is not a caveat outcome' => ['passed', Status::Warning],
            'skipped is not a caveat outcome' => ['skipped', Status::Warning],
        ];
    }

    /**
     * A caveat exists because part of the check was not done, so it can never read as a
     * pass or a skip: an unusable status falls back to warning.
     *
     * @dataProvider storedStatuses
     */
    #[Test]
    #[DataProvider('storedStatuses')]
    public function it_reads_the_stored_status_or_falls_back_to_warning(mixed $stored, Status $expected): void
    {
        $caveat = ResultCaveat::from([
            ResultCaveat::METADATA_KEY => 'Example probe not verified',
            ResultCaveat::STATUS_KEY => $stored,
        ]);

        $this->assertSame($expected, $caveat?->status);
    }
}
