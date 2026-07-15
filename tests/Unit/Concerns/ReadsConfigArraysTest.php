<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Concerns;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Concerns\ReadsConfigArrays;
use ShieldCI\Tests\TestCase;

class ReadsConfigArraysTest extends TestCase
{
    /** @test */
    #[Test]
    public function to_string_keyed_array_returns_empty_for_non_array(): void
    {
        $reader = new class
        {
            use ReadsConfigArrays;

            /**
             * @return array<string, mixed>
             */
            public function call(mixed $value): array
            {
                return $this->toStringKeyedArray($value);
            }
        };

        $this->assertSame([], $reader->call('not-an-array'));
        $this->assertSame([], $reader->call(null));
        $this->assertSame([], $reader->call(42));
    }

    /** @test */
    #[Test]
    public function to_string_keyed_array_keeps_string_keys_and_drops_non_string_keys(): void
    {
        $reader = new class
        {
            use ReadsConfigArrays;

            /**
             * @return array<string, mixed>
             */
            public function call(mixed $value): array
            {
                return $this->toStringKeyedArray($value);
            }
        };

        $result = $reader->call([
            'driver' => 'redis',
            0 => 'dropped',
            'timeout' => 30,
        ]);

        $this->assertSame(['driver' => 'redis', 'timeout' => 30], $result);
    }

    /** @test */
    #[Test]
    public function config_int_reads_integers_and_falls_back_otherwise(): void
    {
        $reader = new class
        {
            use ReadsConfigArrays;

            public function call(mixed $config, string $key, int $default): int
            {
                return $this->configInt($config, $key, $default);
            }
        };

        $this->assertSame(15, $reader->call(['threshold' => 15], 'threshold', 10));
        $this->assertSame(10, $reader->call(['threshold' => '15'], 'threshold', 10));
        $this->assertSame(10, $reader->call(['other' => 15], 'threshold', 10));
        $this->assertSame(10, $reader->call('not-an-array', 'threshold', 10));
    }

    /** @test */
    #[Test]
    public function config_bool_reads_booleans_and_falls_back_otherwise(): void
    {
        $reader = new class
        {
            use ReadsConfigArrays;

            public function call(mixed $config, string $key, bool $default): bool
            {
                return $this->configBool($config, $key, $default);
            }
        };

        $this->assertTrue($reader->call(['enabled' => true], 'enabled', false));
        $this->assertFalse($reader->call(['enabled' => 1], 'enabled', false));
        $this->assertFalse($reader->call(['other' => true], 'enabled', false));
        $this->assertFalse($reader->call(null, 'enabled', false));
    }

    /** @test */
    #[Test]
    public function config_string_list_keeps_strings_and_falls_back_otherwise(): void
    {
        $reader = new class
        {
            use ReadsConfigArrays;

            /**
             * @param  array<int, string>  $default
             * @return array<int, string>
             */
            public function call(mixed $config, string $key, array $default): array
            {
                return $this->configStringList($config, $key, $default);
            }
        };

        $this->assertSame(
            ['App\\Models\\User', 'App\\Models\\Post'],
            $reader->call(['classes' => ['App\\Models\\User', 42, 'App\\Models\\Post']], 'classes', [])
        );
        $this->assertSame(['default'], $reader->call(['other' => ['x']], 'classes', ['default']));
        $this->assertSame(['default'], $reader->call('not-an-array', 'classes', ['default']));
    }
}
