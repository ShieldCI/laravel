<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Support\PHPStan;
use ShieldCI\Tests\TestCase;

class PHPStanTest extends TestCase
{
    #[Test]
    public function it_can_set_root_path(): void
    {
        $phpstan = new PHPStan;
        $result = $phpstan->setRootPath('/tmp');

        $this->assertInstanceOf(PHPStan::class, $result);
    }

    #[Test]
    public function it_can_set_config_path(): void
    {
        $phpstan = new PHPStan;
        $result = $phpstan->setConfigPath('/path/to/phpstan.neon');

        $this->assertInstanceOf(PHPStan::class, $result);
    }

    #[Test]
    public function it_parses_analysis_with_search_string(): void
    {
        $phpstan = new PHPStan;
        $phpstan->result = [
            'files' => [
                '/app/Test.php' => [
                    'messages' => [
                        ['line' => 10, 'message' => 'Method call on undefined variable'],
                        ['line' => 20, 'message' => 'Unused import statement'],
                    ],
                ],
            ],
        ];

        $results = $phpstan->parseAnalysis('undefined');

        $this->assertCount(1, $results);
        $this->assertEquals('/app/Test.php', $results[0]['path']);
        $this->assertEquals(10, $results[0]['line']);
        $this->assertStringContainsString('undefined', $results[0]['message']);
    }

    #[Test]
    public function it_parses_analysis_with_array_of_search_strings(): void
    {
        $phpstan = new PHPStan;
        $phpstan->result = [
            'files' => [
                '/app/Test.php' => [
                    'messages' => [
                        ['line' => 10, 'message' => 'Method call on undefined variable'],
                        ['line' => 20, 'message' => 'Unused import statement'],
                        ['line' => 30, 'message' => 'Type mismatch error'],
                    ],
                ],
            ],
        ];

        $results = $phpstan->parseAnalysis(['undefined', 'Unused']);

        $this->assertCount(2, $results);
    }

    #[Test]
    public function it_returns_empty_array_when_no_matches(): void
    {
        $phpstan = new PHPStan;
        $phpstan->result = [
            'files' => [
                '/app/Test.php' => [
                    'messages' => [
                        ['line' => 10, 'message' => 'Some error'],
                    ],
                ],
            ],
        ];

        $results = $phpstan->parseAnalysis('nonexistent');

        $this->assertEmpty($results);
    }

    #[Test]
    public function it_returns_empty_array_when_result_is_null(): void
    {
        $phpstan = new PHPStan;
        $phpstan->result = null;

        $results = $phpstan->parseAnalysis('anything');

        $this->assertEmpty($results);
    }

    #[Test]
    public function it_returns_empty_array_when_no_files_key(): void
    {
        $phpstan = new PHPStan;
        $phpstan->result = ['errors' => []];

        $results = $phpstan->parseAnalysis('anything');

        $this->assertEmpty($results);
    }

    #[Test]
    public function it_matches_using_wildcard_pattern(): void
    {
        $phpstan = new PHPStan;
        $phpstan->result = [
            'files' => [
                '/app/Test.php' => [
                    'messages' => [
                        ['line' => 10, 'message' => 'Method call on $this->something()'],
                        ['line' => 20, 'message' => 'Variable assignment is unused'],
                    ],
                ],
            ],
        ];

        $results = $phpstan->match('Method call on *');

        $this->assertCount(1, $results);
        $this->assertEquals(10, $results[0]['line']);
    }

    #[Test]
    public function it_matches_using_array_of_patterns(): void
    {
        $phpstan = new PHPStan;
        $phpstan->result = [
            'files' => [
                '/app/Test.php' => [
                    'messages' => [
                        ['line' => 10, 'message' => 'Method call on $this'],
                        ['line' => 20, 'message' => 'Variable $foo is unused'],
                    ],
                ],
            ],
        ];

        $results = $phpstan->match(['Method call *', 'Variable * is unused']);

        $this->assertCount(2, $results);
    }

    #[Test]
    public function it_matches_using_regex_pattern(): void
    {
        $phpstan = new PHPStan;
        $phpstan->result = [
            'files' => [
                '/app/Test.php' => [
                    'messages' => [
                        ['line' => 10, 'message' => 'Method foo() is deprecated'],
                        ['line' => 20, 'message' => 'Method bar() is deprecated'],
                        ['line' => 30, 'message' => 'Variable is unused'],
                    ],
                ],
            ],
        ];

        $results = $phpstan->pregMatch('/^Method \w+\(\) is deprecated$/');

        $this->assertCount(2, $results);
    }

    #[Test]
    public function it_returns_empty_for_preg_match_when_no_result(): void
    {
        $phpstan = new PHPStan;
        $phpstan->result = null;

        $results = $phpstan->pregMatch('/pattern/');

        $this->assertEmpty($results);
    }

    #[Test]
    public function it_handles_multiple_files(): void
    {
        $phpstan = new PHPStan;
        $phpstan->result = [
            'files' => [
                '/app/Controller.php' => [
                    'messages' => [
                        ['line' => 10, 'message' => 'Undefined variable $user'],
                    ],
                ],
                '/app/Service.php' => [
                    'messages' => [
                        ['line' => 20, 'message' => 'Undefined method call'],
                    ],
                ],
            ],
        ];

        $results = $phpstan->parseAnalysis('Undefined');

        $this->assertCount(2, $results);

        $paths = array_column($results, 'path');
        $this->assertContains('/app/Controller.php', $paths);
        $this->assertContains('/app/Service.php', $paths);
    }

    #[Test]
    public function it_preserves_line_numbers(): void
    {
        $phpstan = new PHPStan;
        $phpstan->result = [
            'files' => [
                '/app/Test.php' => [
                    'messages' => [
                        ['line' => 42, 'message' => 'Error on line 42'],
                        ['line' => 100, 'message' => 'Error on line 100'],
                    ],
                ],
            ],
        ];

        $results = $phpstan->parseAnalysis('Error');

        $this->assertEquals(42, $results[0]['line']);
        $this->assertEquals(100, $results[1]['line']);
    }

    #[Test]
    public function it_returns_fluent_interface_from_setters(): void
    {
        $phpstan = new PHPStan;

        $result1 = $phpstan->setRootPath('/tmp');
        $result2 = $result1->setConfigPath('/config.neon');

        $this->assertSame($phpstan, $result1);
        $this->assertSame($phpstan, $result2);
    }

    #[Test]
    public function it_resolves_real_path_when_setting_root_path(): void
    {
        $phpstan = new PHPStan;
        $phpstan->setRootPath(sys_get_temp_dir());

        // The root path should be set (we can verify by running findPHPStan via reflection)
        $reflection = new \ReflectionClass($phpstan);
        $property = $reflection->getProperty('rootPath');
        $property->setAccessible(true);

        $this->assertNotNull($property->getValue($phpstan));
    }

    #[Test]
    public function it_gets_default_phpstan_options(): void
    {
        $phpstan = new TestablePHPStan;
        $options = $phpstan->publicGetPHPStanOptions();

        $this->assertIsArray($options);
    }

    #[Test]
    public function it_gets_default_config_path(): void
    {
        $phpstan = new TestablePHPStan;
        $configPath = $phpstan->publicGetDefaultConfigPath();

        $this->assertStringContainsString('phpstan-analyzers.neon', $configPath);
    }

    #[Test]
    public function it_finds_phpstan_binary(): void
    {
        $phpstan = new TestablePHPStan;
        $phpstan->setRootPath(base_path());
        $binary = $phpstan->publicFindPHPStan();

        $this->assertIsArray($binary);
        $this->assertStringContainsString('phpstan', $binary[0]);
    }

    #[Test]
    public function it_creates_process_instance(): void
    {
        $phpstan = new TestablePHPStan;
        $phpstan->setRootPath(base_path());
        $process = $phpstan->publicGetProcess(['--version']);

        $this->assertInstanceOf(\Symfony\Component\Process\Process::class, $process);
    }

    #[Test]
    public function it_runs_command_and_returns_output(): void
    {
        $phpstan = new PHPStan;
        $phpstan->setRootPath(__DIR__.'/../../../');

        $output = $phpstan->runCommand(['--version']);

        $this->assertIsString($output);
    }

    #[Test]
    public function it_runs_command_without_error_output(): void
    {
        $phpstan = new PHPStan;
        $phpstan->setRootPath(__DIR__.'/../../../');

        $output = $phpstan->runCommand(['--version'], false);

        $this->assertIsString($output);
    }

    #[Test]
    public function it_can_start_analysis_on_a_path(): void
    {
        $phpstan = new PHPStan;
        $phpstan->setRootPath(__DIR__.'/../../../');

        // Use the package's own phpstan.neon to run analysis on a small fixture
        $configPath = __DIR__.'/../../../phpstan.neon';

        // Start analysis - may fail but should still return the PHPStan instance
        $result = $phpstan->start(
            [__DIR__.'/../../Fixtures/inspects-code/sample_functions.php'],
            $configPath
        );

        $this->assertInstanceOf(PHPStan::class, $result);
    }

    #[Test]
    public function it_returns_empty_for_match_when_no_result(): void
    {
        $phpstan = new PHPStan;
        $phpstan->result = null;

        $results = $phpstan->match('*');

        $this->assertEmpty($results);
    }

    #[Test]
    public function it_returns_empty_for_match_when_no_files_key(): void
    {
        $phpstan = new PHPStan;
        $phpstan->result = ['errors' => []];

        $results = $phpstan->match('*');

        $this->assertEmpty($results);
    }
}

/**
 * Testable subclass to expose protected methods.
 */
class TestablePHPStan extends PHPStan
{
    /**
     * @return array<int, string>
     */
    public function publicGetPHPStanOptions(): array
    {
        return $this->getPHPStanOptions();
    }

    public function publicGetDefaultConfigPath(): string
    {
        return $this->getDefaultConfigPath();
    }

    /**
     * @return array<int, string>
     */
    public function publicFindPHPStan(): array
    {
        return $this->findPHPStan();
    }

    /**
     * @param  array<int, string>  $command
     */
    public function publicGetProcess(array $command): \Symfony\Component\Process\Process
    {
        return $this->getProcess($command);
    }
}
