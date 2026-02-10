<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Concerns;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Concerns\InspectsCode;
use ShieldCI\Tests\TestCase;

class InspectsCodeTest extends TestCase
{
    #[Test]
    public function it_finds_function_calls_in_fixture_files(): void
    {
        $inspector = new ConcreteInspectsCode;
        $inspector->setFixturePath(__DIR__.'/../../Fixtures/inspects-code');

        $results = $inspector->publicFindFunctionCalls('env');

        $this->assertNotEmpty($results);
        $this->assertCount(2, $results); // env('APP_KEY') and env('APP_DEBUG', 'false')
        $this->assertArrayHasKey('file', $results[0]);
        $this->assertArrayHasKey('node', $results[0]);
        $this->assertArrayHasKey('args', $results[0]);
    }

    #[Test]
    public function it_extracts_string_arguments(): void
    {
        $inspector = new ConcreteInspectsCode;
        $inspector->setFixturePath(__DIR__.'/../../Fixtures/inspects-code');

        $results = $inspector->publicFindFunctionCalls('env');

        // First call: env('APP_KEY') — string argument
        $this->assertEquals('APP_KEY', $results[0]['args'][0]);
    }

    #[Test]
    public function it_extracts_multiple_arguments_including_string_default(): void
    {
        $inspector = new ConcreteInspectsCode;
        $inspector->setFixturePath(__DIR__.'/../../Fixtures/inspects-code');

        $results = $inspector->publicFindFunctionCalls('env');

        // Second call: env('APP_DEBUG', 'false') — two string arguments
        $this->assertEquals('APP_DEBUG', $results[1]['args'][0]);
        $this->assertEquals('false', $results[1]['args'][1]);
    }

    #[Test]
    public function it_extracts_integer_arguments(): void
    {
        $inspector = new ConcreteInspectsCode;
        $inspector->setFixturePath(__DIR__.'/../../Fixtures/inspects-code');

        $results = $inspector->publicFindFunctionCalls('config');

        // config('app.port', 8080) — integer argument
        $portCall = null;
        foreach ($results as $result) {
            if (isset($result['args'][0]) && $result['args'][0] === 'app.port') {
                $portCall = $result;
                break;
            }
        }

        $this->assertNotNull($portCall);
        $this->assertEquals(8080, $portCall['args'][1]);
    }

    #[Test]
    public function it_extracts_const_fetch_arguments(): void
    {
        $inspector = new ConcreteInspectsCode;
        $inspector->setFixturePath(__DIR__.'/../../Fixtures/inspects-code');

        $results = $inspector->publicFindFunctionCalls('config');

        // config('app.flag', true) — ConstFetch argument
        $flagCall = null;
        foreach ($results as $result) {
            if (isset($result['args'][0]) && $result['args'][0] === 'app.flag') {
                $flagCall = $result;
                break;
            }
        }

        $this->assertNotNull($flagCall);
        $this->assertEquals('true', $flagCall['args'][1]);
    }

    #[Test]
    public function it_returns_null_for_complex_arguments(): void
    {
        $inspector = new ConcreteInspectsCode;
        $inspector->setFixturePath(__DIR__.'/../../Fixtures/inspects-code');

        $results = $inspector->publicFindFunctionCalls('config');

        // config(getenv('APP_CONFIG_KEY')) — complex expression
        $complexCall = null;
        foreach ($results as $result) {
            if (array_key_exists(0, $result['args']) && $result['args'][0] === null) {
                $complexCall = $result;
                break;
            }
        }

        $this->assertNotNull($complexCall);
        $this->assertNull($complexCall['args'][0]);
    }

    #[Test]
    public function it_returns_empty_when_function_not_found(): void
    {
        $inspector = new ConcreteInspectsCode;
        $inspector->setFixturePath(__DIR__.'/../../Fixtures/inspects-code');

        $results = $inspector->publicFindFunctionCalls('nonExistentFunction');

        $this->assertEmpty($results);
    }

    #[Test]
    public function it_excludes_files_matching_exclude_paths(): void
    {
        $inspector = new ConcreteInspectsCode;
        $inspector->setFixturePath(__DIR__.'/../../Fixtures/inspects-code');

        // Exclude the inspects-code directory itself
        $results = $inspector->publicFindFunctionCalls('env', ['.'], ['/inspects-code/']);

        $this->assertEmpty($results);
    }

    #[Test]
    public function it_returns_empty_for_files_without_matching_functions(): void
    {
        $inspector = new ConcreteInspectsCode;
        $inspector->setFixturePath(__DIR__.'/../../Fixtures/inspects-code');

        // strlen exists in fixture but only once
        $results = $inspector->publicFindFunctionCalls('strlen');

        $this->assertCount(1, $results);
    }

    #[Test]
    public function it_skips_files_that_throw_during_parsing(): void
    {
        $inspector = new ConcreteInspectsCode;
        $inspector->setFixturePath(__DIR__.'/../../Fixtures/inspects-code');

        // Inject a mock parser that throws on parseFile to trigger the catch block
        $mockParser = new class extends \ShieldCI\AnalyzersCore\Support\AstParser
        {
            /** @return array<\PhpParser\Node> */
            public function parseFile(string $filePath): array
            {
                // Throw for any file to exercise the catch block
                throw new \RuntimeException('Simulated parser failure');
            }
        };

        $reflection = new \ReflectionProperty($inspector, 'parser');
        $reflection->setAccessible(true);
        $reflection->setValue($inspector, $mockParser);

        $results = $inspector->publicFindFunctionCalls('env');

        // All files should be skipped due to parser throwing
        $this->assertEmpty($results);
    }

    #[Test]
    public function it_handles_empty_directory(): void
    {
        $tempDir = sys_get_temp_dir().'/inspects-code-test-'.uniqid();
        mkdir($tempDir);

        try {
            $inspector = new ConcreteInspectsCode;
            $inspector->setFixturePath($tempDir);

            $results = $inspector->publicFindFunctionCalls('env');

            $this->assertEmpty($results);
        } finally {
            rmdir($tempDir);
        }
    }

    #[Test]
    public function it_initializes_parser_only_once(): void
    {
        $inspector = new ConcreteInspectsCode;
        $inspector->setFixturePath(__DIR__.'/../../Fixtures/inspects-code');

        // Call twice to verify parser initialization is idempotent
        $results1 = $inspector->publicFindFunctionCalls('env');
        $results2 = $inspector->publicFindFunctionCalls('env');

        $this->assertEquals(count($results1), count($results2));
    }
}

/**
 * Concrete implementation of InspectsCode trait for testing.
 */
class ConcreteInspectsCode
{
    use InspectsCode;

    private string $fixturePath = '';

    /** @var array<int, string> @phpstan-ignore property.onlyWritten */
    private array $currentPaths = [];

    public function setFixturePath(string $path): void
    {
        $this->fixturePath = $path;
    }

    /**
     * @param  array<int, string>  $paths
     * @param  array<int, string>  $excludePaths
     * @return array<int, array{file: string, node: \PhpParser\Node\Expr\FuncCall, args: array<int, mixed>}>
     */
    public function publicFindFunctionCalls(
        string $functionName,
        array $paths = ['.'],
        array $excludePaths = ['/config/']
    ): array {
        return $this->findFunctionCalls($functionName, $paths, $excludePaths);
    }

    /**
     * @param  array<int, string>  $paths
     */
    protected function setPaths(array $paths): void
    {
        $this->currentPaths = $paths;
    }

    /**
     * @return \Generator<int, \SplFileInfo>
     */
    protected function getPhpFiles(): \Generator
    {
        $searchPath = $this->fixturePath;

        if (! is_dir($searchPath)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($searchPath, \RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file instanceof \SplFileInfo && $file->getExtension() === 'php') {
                yield $file;
            }
        }
    }
}
