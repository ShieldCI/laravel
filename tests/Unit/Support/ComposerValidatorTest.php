<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Support\ComposerValidator;
use ShieldCI\Support\ComposerValidatorResult;
use ShieldCI\Tests\TestCase;

class ComposerValidatorTest extends TestCase
{
    #[Test]
    public function it_validates_valid_composer_json(): void
    {
        $validator = new ComposerValidator;

        // Use the package's own directory which has a valid composer.json
        $result = $validator->validate(base_path());

        $this->assertInstanceOf(ComposerValidatorResult::class, $result);
        $this->assertTrue($result->successful);
    }

    #[Test]
    public function it_returns_failure_for_invalid_working_directory(): void
    {
        $validator = new ComposerValidator;

        // Create a temp directory without composer.json
        $tempDir = sys_get_temp_dir().'/shieldci-test-'.uniqid();
        mkdir($tempDir);

        try {
            $result = $validator->validate($tempDir);

            // Should fail because there's no composer.json
            $this->assertFalse($result->successful);
            $this->assertNotEmpty($result->output);
        } finally {
            rmdir($tempDir);
        }
    }

    #[Test]
    public function it_returns_failure_for_malformed_composer_json(): void
    {
        $validator = new ComposerValidator;

        // Create a temp directory with invalid composer.json
        $tempDir = sys_get_temp_dir().'/shieldci-test-'.uniqid();
        mkdir($tempDir);
        file_put_contents($tempDir.'/composer.json', '{ invalid json }');

        try {
            $result = $validator->validate($tempDir);

            $this->assertFalse($result->successful);
            $this->assertNotEmpty($result->output);
        } finally {
            unlink($tempDir.'/composer.json');
            rmdir($tempDir);
        }
    }

    #[Test]
    public function it_returns_output_with_result(): void
    {
        $validator = new ComposerValidator;

        $result = $validator->validate(base_path());

        $this->assertIsString($result->output);
    }

    #[Test]
    public function it_uses_composer_phar_when_present(): void
    {
        $validator = new ComposerValidator;

        $reflection = new \ReflectionMethod($validator, 'findComposerBinary');
        $reflection->setAccessible(true);

        // Create a temp directory with a composer.phar
        $tempDir = sys_get_temp_dir().'/shieldci-phar-test-'.uniqid();
        mkdir($tempDir);
        file_put_contents($tempDir.'/composer.phar', '<?php echo "fake composer";');

        $originalDir = (string) getcwd();

        try {
            chdir($tempDir);
            /** @var array<int, string> $binary */
            $binary = $reflection->invoke($validator);

            $this->assertCount(2, $binary);
            $this->assertEquals(PHP_BINARY, $binary[0]);
            $this->assertStringContainsString('composer.phar', $binary[1]);
        } finally {
            chdir($originalDir);
            unlink($tempDir.'/composer.phar');
            rmdir($tempDir);
        }
    }

    #[Test]
    public function it_validates_composer_json_with_missing_fields(): void
    {
        $validator = new ComposerValidator;

        // Create a temp directory with minimal composer.json
        $tempDir = sys_get_temp_dir().'/shieldci-test-'.uniqid();
        mkdir($tempDir);
        file_put_contents($tempDir.'/composer.json', json_encode([
            'name' => 'test/package',
            'description' => 'Test package',
        ]));

        try {
            $result = $validator->validate($tempDir);

            // Minimal composer.json should be valid
            $this->assertInstanceOf(ComposerValidatorResult::class, $result);
        } finally {
            unlink($tempDir.'/composer.json');
            rmdir($tempDir);
        }
    }
}
