<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ShieldCI\Support\PHPStanRunner;

class PHPStanRunnerTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tempDir = sys_get_temp_dir().'/phpstan_runner_test_'.uniqid();
        mkdir($this->tempDir, 0755, true);
    }

    protected function tearDown(): void
    {
        $this->recursiveDelete($this->tempDir);
        parent::tearDown();
    }

    private function recursiveDelete(string $dir): void
    {
        if (! is_dir($dir)) {
            return;
        }

        $items = scandir($dir);
        if ($items === false) {
            return;
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }

            $path = $dir.'/'.$item;
            if (is_dir($path)) {
                $this->recursiveDelete($path);
            } else {
                unlink($path);
            }
        }

        rmdir($dir);
    }

    public function test_filters_higher_order_proxy_false_positive(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Call to an undefined method Illuminate\Support\HigherOrderCollectionProxy::something()',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Undefined variable: $realIssue',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        // Should only have the real issue, not the HigherOrderProxy false positive
        $this->assertCount(1, $issues);
        $firstIssue = $issues->first();
        $this->assertNotNull($firstIssue);
        $this->assertStringContainsString('Undefined variable', $firstIssue['message']);
    }

    public function test_filters_higher_order_when_proxy_false_positive(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Call to an undefined method Illuminate\Support\HigherOrderWhenProxy::doSomething()',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        $this->assertCount(0, $issues);
    }

    public function test_does_not_filter_real_issues(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/Services/PaymentService.php',
                'line' => 20,
                'message' => 'Call to an undefined static method App\Models\Payment::customNonExistentMethod()',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Undefined variable: $realIssue',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        // Both are real issues (not HigherOrderProxy)
        $this->assertCount(2, $issues);
    }

    public function test_filters_faker_generator_unknown_class_false_positive(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Call to method unique() on an unknown class Faker\Generator.',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Undefined variable: $realIssue',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        $this->assertCount(1, $issues);
        $firstIssue = $issues->first();
        $this->assertNotNull($firstIssue);
        $this->assertStringContainsString('Undefined variable', $firstIssue['message']);
    }

    public function test_filters_faker_undefined_method_false_positive(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Call to an undefined method Faker\Generator::randomNumber().',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        $this->assertCount(0, $issues);
    }

    public function test_filters_faker_proxy_generators_false_positives(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Call to method randomNumber() on an unknown class Faker\UniqueGenerator.',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Call to method name() on an unknown class Faker\ValidGenerator.',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 20,
                'message' => 'Call to method boolean() on an unknown class Faker\ChanceGenerator.',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        $this->assertCount(0, $issues);
    }

    public function test_filters_faker_property_access_false_positives(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Access to property $name on an unknown class Faker\Generator.',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Access to an undefined property Faker\Generator::$name.',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        $this->assertCount(0, $issues);
    }

    public function test_does_not_filter_non_faker_namespace_issues(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Call to an undefined method App\Services\FakerService::generate().',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Call to an undefined method App\Models\User::fake().',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 20,
                'message' => 'Class Faker\Generator not found.',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        // All three are real issues — none should be filtered
        $this->assertCount(3, $issues);
    }

    public function test_filters_faker_false_positives_while_keeping_real_issues(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Call to method unique() on an unknown class Faker\Generator.',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Undefined variable: $faker',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 20,
                'message' => 'Call to an undefined method Faker\Generator::randomNumber().',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 25,
                'message' => 'Method App\Services\UserService::create() has no return type specified.',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        // 2 Faker FPs removed, 2 real issues kept
        $this->assertCount(2, $issues);

        $messages = $issues->pluck('message')->toArray();
        $this->assertContains('Undefined variable: $faker', $messages);
        $this->assertContains('Method App\Services\UserService::create() has no return type specified.', $messages);
    }

    public function test_generates_config_with_larastan_extension(): void
    {
        // Create mock Larastan extension
        $larastanDir = $this->tempDir.'/vendor/larastan/larastan';
        mkdir($larastanDir, 0755, true);
        file_put_contents($larastanDir.'/extension.neon', "# Larastan extension\n");

        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        // Read the captured config from the mock script
        $capturedConfig = $this->getCapturedConfig();

        $this->assertStringContainsString('includes:', $capturedConfig);
        $this->assertStringContainsString('larastan/larastan/extension.neon', $capturedConfig);
    }

    public function test_generates_config_with_carbon_extension(): void
    {
        // Create mock Carbon extension
        $carbonDir = $this->tempDir.'/vendor/nesbot/carbon';
        mkdir($carbonDir, 0755, true);
        file_put_contents($carbonDir.'/extension.neon', "# Carbon extension\n");

        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        // Read the captured config from the mock script
        $capturedConfig = $this->getCapturedConfig();

        $this->assertStringContainsString('includes:', $capturedConfig);
        $this->assertStringContainsString('nesbot/carbon/extension.neon', $capturedConfig);
    }

    public function test_generates_config_with_user_phpstan_neon(): void
    {
        // Create user's phpstan.neon
        file_put_contents($this->tempDir.'/phpstan.neon', "# User config\n");

        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        // Read the captured config from the mock script
        $capturedConfig = $this->getCapturedConfig();

        $this->assertStringContainsString('includes:', $capturedConfig);
        $this->assertStringContainsString('phpstan.neon', $capturedConfig);
    }

    public function test_generates_config_with_user_phpstan_neon_dist(): void
    {
        // Create user's phpstan.neon.dist (without phpstan.neon)
        file_put_contents($this->tempDir.'/phpstan.neon.dist', "# User config dist\n");

        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        // Read the captured config from the mock script
        $capturedConfig = $this->getCapturedConfig();

        $this->assertStringContainsString('includes:', $capturedConfig);
        $this->assertStringContainsString('phpstan.neon.dist', $capturedConfig);
    }

    public function test_prefers_phpstan_neon_over_dist(): void
    {
        // Create both files
        file_put_contents($this->tempDir.'/phpstan.neon', "# Primary config\n");
        file_put_contents($this->tempDir.'/phpstan.neon.dist', "# Dist config\n");

        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        // Read the captured config from the mock script
        $capturedConfig = $this->getCapturedConfig();

        // Should only include phpstan.neon, not .dist
        $this->assertStringContainsString('phpstan.neon', $capturedConfig);
        $this->assertStringNotContainsString('phpstan.neon.dist', $capturedConfig);
    }

    public function test_generates_config_without_extensions_when_not_available(): void
    {
        // Don't create any extension files
        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        // Read the captured config from the mock script
        $capturedConfig = $this->getCapturedConfig();

        // Should have parameters but no includes
        $this->assertStringContainsString('parameters:', $capturedConfig);
        $this->assertStringContainsString('level:', $capturedConfig);
        $this->assertStringNotContainsString('includes:', $capturedConfig);
    }

    public function test_config_includes_correct_level(): void
    {
        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app'], 9);

        // Read the captured config from the mock script
        $capturedConfig = $this->getCapturedConfig();

        $this->assertStringContainsString('level: 9', $capturedConfig);
    }

    public function test_cleans_up_temp_config_file(): void
    {
        $this->createMockPHPStan([]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        // Use reflection to access private property
        $reflection = new ReflectionClass($runner);
        $property = $reflection->getProperty('tempConfigFile');
        $property->setAccessible(true);
        $tempConfigFile = $property->getValue($runner);

        // Temp config file should be null (cleaned up)
        $this->assertNull($tempConfigFile);
    }

    public function test_is_available_returns_true_when_phpstan_exists(): void
    {
        $this->createMockPHPStan([]);

        $runner = new PHPStanRunner($this->tempDir);

        $this->assertTrue($runner->isAvailable());
    }

    public function test_is_available_returns_false_when_phpstan_missing(): void
    {
        // Don't create mock PHPStan
        $runner = new PHPStanRunner($this->tempDir);

        $this->assertFalse($runner->isAvailable());
    }

    public function test_get_issues_returns_empty_collection_without_analysis(): void
    {
        $runner = new PHPStanRunner($this->tempDir);

        $issues = $runner->getIssues();

        $this->assertTrue($issues->isEmpty());
    }

    public function test_filter_by_pattern_works(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Undefined variable: $foo',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Method has no return type',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->filterByPattern('*variable*');

        $this->assertCount(1, $issues);
        $firstIssue = $issues->first();
        $this->assertNotNull($firstIssue);
        $this->assertStringContainsString('variable', $firstIssue['message']);
    }

    public function test_filter_by_regex_works(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Undefined variable: $foo',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Method has no return type',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->filterByRegex('/variable.*\$\w+/');

        $this->assertCount(1, $issues);
    }

    public function test_filter_by_text_works(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Undefined variable: $foo',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Method has no return type',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->filterByText('return type');

        $this->assertCount(1, $issues);
        $firstIssue = $issues->first();
        $this->assertNotNull($firstIssue);
        $this->assertStringContainsString('return type', $firstIssue['message']);
    }

    public function test_handles_invalid_json_output_from_phpstan(): void
    {
        $vendorBinDir = $this->tempDir.'/vendor/bin';
        mkdir($vendorBinDir, 0755, true);

        // Create a mock PHPStan that outputs invalid JSON
        $script = <<<'BASH'
#!/bin/bash
echo "This is not valid JSON"
BASH;

        file_put_contents($vendorBinDir.'/phpstan', $script);
        chmod($vendorBinDir.'/phpstan', 0755);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        // When JSON is invalid, result should fall back to ['files' => []]
        $issues = $runner->getIssues();
        $this->assertTrue($issues->isEmpty());
    }

    public function test_get_issues_skips_non_array_file_data(): void
    {
        $runner = new PHPStanRunner($this->tempDir);

        // Use reflection to set result with non-array file data
        $reflection = new ReflectionClass($runner);
        $property = $reflection->getProperty('result');
        $property->setAccessible(true);
        $property->setValue($runner, [
            'files' => [
                '/app/valid.php' => [
                    'messages' => [
                        ['line' => 10, 'message' => 'Valid issue'],
                    ],
                ],
                42 => 'not-an-array', // Non-string key, non-array value
                '/app/missing.php' => 'string-not-array', // String key but non-array value
            ],
        ]);

        $issues = $runner->getIssues();

        // Only the valid file data should produce issues
        $this->assertCount(1, $issues);
        $firstIssue = $issues->first();
        $this->assertNotNull($firstIssue);
        $this->assertEquals('Valid issue', $firstIssue['message']);
    }

    public function test_get_issues_skips_non_array_message_entries(): void
    {
        $runner = new PHPStanRunner($this->tempDir);

        // Use reflection to set result with non-array message entries
        $reflection = new ReflectionClass($runner);
        $property = $reflection->getProperty('result');
        $property->setAccessible(true);
        $property->setValue($runner, [
            'files' => [
                '/app/test.php' => [
                    'messages' => [
                        'string-not-array',
                        ['line' => 10, 'message' => 'Real issue'],
                        42,
                    ],
                ],
            ],
        ]);

        $issues = $runner->getIssues();

        // Only the valid message entry should produce issues
        $this->assertCount(1, $issues);
        $firstIssue = $issues->first();
        $this->assertNotNull($firstIssue);
        $this->assertEquals('Real issue', $firstIssue['message']);
    }

    /**
     * Create a mock PHPStan script that returns predefined issues.
     *
     * @param  array<array{file: string, line: int, message: string}>  $issues
     */
    private function createMockPHPStan(array $issues): void
    {
        $vendorBinDir = $this->tempDir.'/vendor/bin';
        mkdir($vendorBinDir, 0755, true);

        $files = [];
        foreach ($issues as $issue) {
            $file = $issue['file'];
            if (! isset($files[$file])) {
                $files[$file] = ['messages' => []];
            }

            $files[$file]['messages'][] = [
                'message' => $issue['message'],
                'line' => $issue['line'],
                'ignorable' => true,
            ];
        }

        $output = [
            'totals' => [
                'errors' => 0,
                'file_errors' => count($issues),
            ],
            'files' => $files,
            'errors' => [],
        ];

        $json = json_encode($output, JSON_PRETTY_PRINT);

        $script = <<<BASH
#!/bin/bash
cat <<'EOF'
{$json}
EOF
BASH;

        file_put_contents($vendorBinDir.'/phpstan', $script);
        chmod($vendorBinDir.'/phpstan', 0755);
    }

    /**
     * Create a mock PHPStan script that captures the config file content.
     */
    private function createMockPHPStanWithConfigCapture(): void
    {
        $vendorBinDir = $this->tempDir.'/vendor/bin';
        mkdir($vendorBinDir, 0755, true);

        $output = [
            'totals' => [
                'errors' => 0,
                'file_errors' => 0,
            ],
            'files' => [],
            'errors' => [],
        ];

        $json = json_encode($output, JSON_PRETTY_PRINT);
        $capturedConfigPath = $this->tempDir.'/captured_config.neon';

        // Script that captures the config file content before outputting JSON
        $script = <<<BASH
#!/bin/bash

# Parse the --configuration flag to get the config file path
for arg in "\$@"; do
    case \$arg in
        --configuration=*)
            CONFIG_FILE="\${arg#*=}"
            if [ -f "\$CONFIG_FILE" ]; then
                cp "\$CONFIG_FILE" "{$capturedConfigPath}"
            fi
            ;;
    esac
done

cat <<'EOF'
{$json}
EOF
BASH;

        file_put_contents($vendorBinDir.'/phpstan', $script);
        chmod($vendorBinDir.'/phpstan', 0755);
    }

    /**
     * Read the captured config file content.
     */
    private function getCapturedConfig(): string
    {
        $path = $this->tempDir.'/captured_config.neon';
        $this->assertFileExists($path, 'Captured config file should exist');

        $content = file_get_contents($path);
        $this->assertIsString($content, 'Captured config file should be readable');

        return $content;
    }
}
