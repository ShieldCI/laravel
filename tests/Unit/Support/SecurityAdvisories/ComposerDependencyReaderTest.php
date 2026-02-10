<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support\SecurityAdvisories;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Support\SecurityAdvisories\ComposerDependencyReader;
use ShieldCI\Tests\TestCase;

class ComposerDependencyReaderTest extends TestCase
{
    private ComposerDependencyReader $reader;

    private string $fixturesPath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->reader = new ComposerDependencyReader;
        $this->fixturesPath = __DIR__.'/../../../Fixtures/composer-lock';

        // Create fixtures directory if it doesn't exist
        if (! is_dir($this->fixturesPath)) {
            mkdir($this->fixturesPath, 0755, true);
        }
    }

    protected function tearDown(): void
    {
        // Clean up fixture files
        $files = glob($this->fixturesPath.'/*.json');
        if ($files) {
            foreach ($files as $file) {
                unlink($file);
            }
        }
        if (is_dir($this->fixturesPath)) {
            @rmdir($this->fixturesPath);
        }

        parent::tearDown();
    }

    #[Test]
    public function it_reads_packages_from_composer_lock(): void
    {
        $this->createComposerLock([
            'packages' => [
                [
                    'name' => 'laravel/framework',
                    'version' => 'v10.0.0',
                    'time' => '2024-01-01T00:00:00+00:00',
                ],
                [
                    'name' => 'guzzlehttp/guzzle',
                    'version' => '7.5.0',
                    'time' => '2024-01-02T00:00:00+00:00',
                ],
            ],
        ]);

        $packages = $this->reader->read($this->fixturesPath.'/composer.lock');

        $this->assertCount(2, $packages);
        $this->assertArrayHasKey('laravel/framework', $packages);
        $this->assertArrayHasKey('guzzlehttp/guzzle', $packages);
        $this->assertEquals('10.0.0', $packages['laravel/framework']['version']);
        $this->assertEquals('7.5.0', $packages['guzzlehttp/guzzle']['version']);
    }

    #[Test]
    public function it_reads_packages_dev_from_composer_lock(): void
    {
        $this->createComposerLock([
            'packages' => [
                [
                    'name' => 'laravel/framework',
                    'version' => 'v10.0.0',
                ],
            ],
            'packages-dev' => [
                [
                    'name' => 'phpunit/phpunit',
                    'version' => '10.5.0',
                ],
                [
                    'name' => 'mockery/mockery',
                    'version' => '1.6.0',
                ],
            ],
        ]);

        $packages = $this->reader->read($this->fixturesPath.'/composer.lock');

        $this->assertCount(3, $packages);
        $this->assertArrayHasKey('phpunit/phpunit', $packages);
        $this->assertArrayHasKey('mockery/mockery', $packages);
    }

    #[Test]
    public function it_strips_v_prefix_from_versions(): void
    {
        $this->createComposerLock([
            'packages' => [
                [
                    'name' => 'test/package',
                    'version' => 'v1.2.3',
                ],
            ],
        ]);

        $packages = $this->reader->read($this->fixturesPath.'/composer.lock');

        $this->assertEquals('1.2.3', $packages['test/package']['version']);
    }

    #[Test]
    public function it_includes_time_when_available(): void
    {
        $this->createComposerLock([
            'packages' => [
                [
                    'name' => 'test/with-time',
                    'version' => '1.0.0',
                    'time' => '2024-06-15T10:30:00+00:00',
                ],
                [
                    'name' => 'test/without-time',
                    'version' => '2.0.0',
                ],
            ],
        ]);

        $packages = $this->reader->read($this->fixturesPath.'/composer.lock');

        $this->assertEquals('2024-06-15T10:30:00+00:00', $packages['test/with-time']['time']);
        $this->assertNull($packages['test/without-time']['time']);
    }

    #[Test]
    public function it_throws_exception_for_missing_file(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('composer.lock file not found');

        $this->reader->read('/non/existent/composer.lock');
    }

    #[Test]
    public function it_throws_exception_for_invalid_json(): void
    {
        file_put_contents($this->fixturesPath.'/invalid.lock', 'not valid json {{{');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('invalid JSON');

        $this->reader->read($this->fixturesPath.'/invalid.lock');
    }

    #[Test]
    public function it_handles_missing_packages_section(): void
    {
        $this->createComposerLock([
            'content-hash' => 'abc123',
            // No packages or packages-dev
        ]);

        $packages = $this->reader->read($this->fixturesPath.'/composer.lock');

        $this->assertCount(0, $packages);
    }

    #[Test]
    public function it_skips_packages_without_name(): void
    {
        $this->createComposerLock([
            'packages' => [
                [
                    'version' => '1.0.0', // No name
                ],
                [
                    'name' => 'valid/package',
                    'version' => '2.0.0',
                ],
            ],
        ]);

        $packages = $this->reader->read($this->fixturesPath.'/composer.lock');

        $this->assertCount(1, $packages);
        $this->assertArrayHasKey('valid/package', $packages);
    }

    #[Test]
    public function it_skips_packages_without_version(): void
    {
        $this->createComposerLock([
            'packages' => [
                [
                    'name' => 'no/version',
                    // No version
                ],
                [
                    'name' => 'valid/package',
                    'version' => '2.0.0',
                ],
            ],
        ]);

        $packages = $this->reader->read($this->fixturesPath.'/composer.lock');

        $this->assertCount(1, $packages);
        $this->assertArrayHasKey('valid/package', $packages);
    }

    #[Test]
    public function it_skips_non_array_package_entries(): void
    {
        $this->createComposerLock([
            'packages' => [
                'not-an-array',
                null,
                123,
                [
                    'name' => 'valid/package',
                    'version' => '1.0.0',
                ],
            ],
        ]);

        $packages = $this->reader->read($this->fixturesPath.'/composer.lock');

        $this->assertCount(1, $packages);
        $this->assertArrayHasKey('valid/package', $packages);
    }

    #[Test]
    public function it_handles_non_string_name_or_version(): void
    {
        $this->createComposerLock([
            'packages' => [
                [
                    'name' => 123, // Non-string name
                    'version' => '1.0.0',
                ],
                [
                    'name' => 'test/package',
                    'version' => ['invalid'], // Non-string version
                ],
                [
                    'name' => 'valid/package',
                    'version' => '2.0.0',
                ],
            ],
        ]);

        $packages = $this->reader->read($this->fixturesPath.'/composer.lock');

        $this->assertCount(1, $packages);
        $this->assertArrayHasKey('valid/package', $packages);
    }

    #[Test]
    public function it_handles_non_string_time(): void
    {
        $this->createComposerLock([
            'packages' => [
                [
                    'name' => 'test/package',
                    'version' => '1.0.0',
                    'time' => ['not', 'a', 'string'],
                ],
            ],
        ]);

        $packages = $this->reader->read($this->fixturesPath.'/composer.lock');

        $this->assertNull($packages['test/package']['time']);
    }

    #[Test]
    public function it_throws_exception_for_unreadable_file(): void
    {
        $tempFile = tempnam(sys_get_temp_dir(), 'shieldci-unreadable-');
        file_put_contents($tempFile, '{}');
        chmod($tempFile, 0000);

        try {
            $this->expectException(InvalidArgumentException::class);
            $this->expectExceptionMessage('Unable to read');

            $this->reader->read($tempFile);
        } finally {
            chmod($tempFile, 0644);
            unlink($tempFile);
        }
    }

    /**
     * @param  array<string, mixed>  $content
     */
    private function createComposerLock(array $content): void
    {
        file_put_contents(
            $this->fixturesPath.'/composer.lock',
            json_encode($content, JSON_PRETTY_PRINT)
        );
    }
}
