<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use ShieldCI\Support\Composer;

/**
 * @covers \ShieldCI\Support\Composer
 */
class ComposerTest extends TestCase
{
    public function test_find_package_line_number_in_composer_lock(): void
    {
        // Create a composer.lock with package on specific line
        $composerLock = <<<'JSON'
        {
            "packages": [
                {
                    "name": "vendor/first-package",
                    "version": "1.0.0"
                },
                {
                    "name": "vendor/target-package",
                    "version": "2.0.0"
                }
            ]
        }
        JSON;

        $tempFile = tempnam(sys_get_temp_dir(), 'composer-lock-test');
        file_put_contents($tempFile, $composerLock);

        try {
            $lineNumber = Composer::findPackageLineNumber($tempFile, 'vendor/target-package');

            // The package "vendor/target-package" is on line 8
            $this->assertEquals(8, $lineNumber);
        } finally {
            unlink($tempFile);
        }
    }

    public function test_find_package_line_number_returns_one_when_not_found(): void
    {
        $composerLock = json_encode([
            'packages' => [
                ['name' => 'vendor/other-package', 'version' => '1.0.0'],
            ],
        ]);

        $tempFile = tempnam(sys_get_temp_dir(), 'composer-lock-test');
        file_put_contents($tempFile, $composerLock);

        try {
            $lineNumber = Composer::findPackageLineNumber($tempFile, 'vendor/nonexistent');

            $this->assertEquals(1, $lineNumber);
        } finally {
            unlink($tempFile);
        }
    }

    public function test_find_package_line_number_handles_missing_file(): void
    {
        $lineNumber = Composer::findPackageLineNumber('/nonexistent/composer.lock', 'vendor/package');

        $this->assertEquals(1, $lineNumber);
    }

    public function test_find_package_line_in_json_finds_package_in_require_section(): void
    {
        $composerJson = <<<'JSON'
        {
            "name": "test/app",
            "require": {
                "php": "^8.1",
                "vendor/target-package": "^2.0"
            }
        }
        JSON;

        $tempFile = tempnam(sys_get_temp_dir(), 'composer-json-test');
        file_put_contents($tempFile, $composerJson);

        try {
            $lineNumber = Composer::findPackageLineInJson($tempFile, 'vendor/target-package', 'require');

            // The package is on line 5
            $this->assertEquals(5, $lineNumber);
        } finally {
            unlink($tempFile);
        }
    }

    public function test_find_package_line_in_json_finds_package_in_require_dev_section(): void
    {
        $composerJson = <<<'JSON'
        {
            "name": "test/app",
            "require": {
                "php": "^8.1"
            },
            "require-dev": {
                "phpunit/phpunit": "^10.0",
                "vendor/dev-tool": "^1.0"
            }
        }
        JSON;

        $tempFile = tempnam(sys_get_temp_dir(), 'composer-json-test');
        file_put_contents($tempFile, $composerJson);

        try {
            $lineNumber = Composer::findPackageLineInJson($tempFile, 'vendor/dev-tool', 'require-dev');

            // The package is on line 8
            $this->assertEquals(8, $lineNumber);
        } finally {
            unlink($tempFile);
        }
    }

    public function test_find_package_line_in_json_handles_nested_objects(): void
    {
        // Some composer.json files might have nested configuration
        $composerJson = <<<'JSON'
        {
            "name": "test/app",
            "require": {
                "vendor/package-with-config": {
                    "version": "^2.0",
                    "options": {
                        "nested": "value"
                    }
                },
                "vendor/simple-package": "^1.0"
            }
        }
        JSON;

        $tempFile = tempnam(sys_get_temp_dir(), 'composer-json-test');
        file_put_contents($tempFile, $composerJson);

        try {
            // Should still find the simple package after the nested structure
            $lineNumber = Composer::findPackageLineInJson($tempFile, 'vendor/simple-package', 'require');

            // The package is on line 10
            $this->assertEquals(10, $lineNumber);
        } finally {
            unlink($tempFile);
        }
    }

    public function test_find_package_line_in_json_returns_one_when_not_found(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'require' => [
                'php' => '^8.1',
            ],
        ], JSON_PRETTY_PRINT);

        $tempFile = tempnam(sys_get_temp_dir(), 'composer-json-test');
        file_put_contents($tempFile, $composerJson);

        try {
            $lineNumber = Composer::findPackageLineInJson($tempFile, 'vendor/nonexistent', 'require');

            $this->assertEquals(1, $lineNumber);
        } finally {
            unlink($tempFile);
        }
    }

    public function test_find_package_line_in_json_handles_missing_file(): void
    {
        $lineNumber = Composer::findPackageLineInJson('/nonexistent/composer.json', 'vendor/package', 'require');

        $this->assertEquals(1, $lineNumber);
    }

    public function test_find_package_line_in_json_doesnt_match_across_sections(): void
    {
        $composerJson = <<<'JSON'
        {
            "name": "test/app",
            "require": {
                "php": "^8.1"
            },
            "require-dev": {
                "vendor/dev-package": "^1.0"
            }
        }
        JSON;

        $tempFile = tempnam(sys_get_temp_dir(), 'composer-json-test');
        file_put_contents($tempFile, $composerJson);

        try {
            // Looking in 'require' section should not find package in 'require-dev'
            $lineNumber = Composer::findPackageLineInJson($tempFile, 'vendor/dev-package', 'require');

            $this->assertEquals(1, $lineNumber); // Not found
        } finally {
            unlink($tempFile);
        }
    }

    public function test_get_lock_file_returns_path_when_exists(): void
    {
        $tempDir = sys_get_temp_dir().'/composer-test-'.uniqid();
        mkdir($tempDir);
        file_put_contents($tempDir.'/composer.lock', '{}');

        try {
            $composer = new Composer(new \Illuminate\Filesystem\Filesystem, $tempDir);

            $this->assertEquals($tempDir.'/composer.lock', $composer->getLockFile());
        } finally {
            unlink($tempDir.'/composer.lock');
            rmdir($tempDir);
        }
    }

    public function test_get_lock_file_returns_null_when_missing(): void
    {
        $tempDir = sys_get_temp_dir().'/composer-test-'.uniqid();
        mkdir($tempDir);

        try {
            $composer = new Composer(new \Illuminate\Filesystem\Filesystem, $tempDir);

            $this->assertNull($composer->getLockFile());
        } finally {
            rmdir($tempDir);
        }
    }

    public function test_get_json_file_returns_path_when_exists(): void
    {
        $tempDir = sys_get_temp_dir().'/composer-test-'.uniqid();
        mkdir($tempDir);
        file_put_contents($tempDir.'/composer.json', '{}');

        try {
            $composer = new Composer(new \Illuminate\Filesystem\Filesystem, $tempDir);

            $this->assertEquals($tempDir.'/composer.json', $composer->getJsonFile());
        } finally {
            unlink($tempDir.'/composer.json');
            rmdir($tempDir);
        }
    }

    public function test_get_json_file_returns_null_when_missing(): void
    {
        $tempDir = sys_get_temp_dir().'/composer-test-'.uniqid();
        mkdir($tempDir);

        try {
            $composer = new Composer(new \Illuminate\Filesystem\Filesystem, $tempDir);

            $this->assertNull($composer->getJsonFile());
        } finally {
            rmdir($tempDir);
        }
    }

    public function test_get_json_returns_parsed_content(): void
    {
        $tempDir = sys_get_temp_dir().'/composer-test-'.uniqid();
        mkdir($tempDir);
        file_put_contents($tempDir.'/composer.json', json_encode([
            'name' => 'test/package',
            'require' => ['php' => '^8.1'],
        ]));

        try {
            $composer = new Composer(new \Illuminate\Filesystem\Filesystem, $tempDir);
            $json = $composer->getJson();

            $this->assertIsArray($json);
            $this->assertEquals('test/package', $json['name']);
            $this->assertArrayHasKey('require', $json);
        } finally {
            unlink($tempDir.'/composer.json');
            rmdir($tempDir);
        }
    }

    public function test_get_json_returns_null_when_no_file(): void
    {
        $tempDir = sys_get_temp_dir().'/composer-test-'.uniqid();
        mkdir($tempDir);

        try {
            $composer = new Composer(new \Illuminate\Filesystem\Filesystem, $tempDir);

            $this->assertNull($composer->getJson());
        } finally {
            rmdir($tempDir);
        }
    }

    public function test_run_command_returns_output(): void
    {
        $composer = new Composer(new \Illuminate\Filesystem\Filesystem, __DIR__.'/../../../');

        $output = $composer->runCommand(['--version']);

        $this->assertIsString($output);
        $this->assertStringContainsString('Composer', $output);
    }

    public function test_run_command_without_error_output(): void
    {
        $composer = new Composer(new \Illuminate\Filesystem\Filesystem, __DIR__.'/../../../');

        $output = $composer->runCommand(['--version'], false);

        $this->assertIsString($output);
    }

    public function test_install_dry_run_returns_string(): void
    {
        $composer = new Composer(new \Illuminate\Filesystem\Filesystem, __DIR__.'/../../../');

        $output = $composer->installDryRun(['--no-interaction']);

        $this->assertIsString($output);
    }

    public function test_update_dry_run_returns_string(): void
    {
        $composer = new Composer(new \Illuminate\Filesystem\Filesystem, __DIR__.'/../../../');

        $output = $composer->updateDryRun(['--no-interaction']);

        $this->assertIsString($output);
    }

    public function test_find_package_line_number_returns_one_for_empty_file(): void
    {
        $tempFile = tempnam(sys_get_temp_dir(), 'composer-lock-empty');
        file_put_contents($tempFile, '');

        try {
            $lineNumber = Composer::findPackageLineNumber($tempFile, 'vendor/package');

            $this->assertEquals(1, $lineNumber);
        } finally {
            unlink($tempFile);
        }
    }

    public function test_find_package_line_in_json_returns_one_for_empty_file(): void
    {
        $tempFile = tempnam(sys_get_temp_dir(), 'composer-json-empty');
        file_put_contents($tempFile, '');

        try {
            $lineNumber = Composer::findPackageLineInJson($tempFile, 'vendor/package', 'require');

            $this->assertEquals(1, $lineNumber);
        } finally {
            unlink($tempFile);
        }
    }
}
