<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Concerns;

use PhpParser\Node\ArrayItem;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Scalar\String_;
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

    #[Test]
    public function parse_config_array_extracts_string_int_float_bool_null_values(): void
    {
        $inspector = new ConcreteInspectsCode;
        $result = $inspector->publicParseConfigArray(__DIR__.'/../../Fixtures/inspects-code-config/config_standard.php');

        $this->assertArrayHasKey('name', $result);
        $this->assertSame('MyApp', $result['name']['value']);
        $this->assertFalse($result['name']['isEnvCall']);

        $this->assertArrayHasKey('debug', $result);
        $this->assertFalse($result['debug']['value']);

        $this->assertArrayHasKey('port', $result);
        $this->assertSame(8080, $result['port']['value']);

        $this->assertArrayHasKey('rate', $result);
        $this->assertSame(1.5, $result['rate']['value']);

        $this->assertArrayHasKey('nullable', $result);
        $this->assertNull($result['nullable']['value']);
    }

    #[Test]
    public function parse_config_array_detects_env_calls_without_default(): void
    {
        $inspector = new ConcreteInspectsCode;
        $result = $inspector->publicParseConfigArray(__DIR__.'/../../Fixtures/inspects-code-config/config_standard.php');

        $this->assertArrayHasKey('key', $result);
        $this->assertTrue($result['key']['isEnvCall']);
        $this->assertNull($result['key']['value']);
        $this->assertNull($result['key']['envDefault']);
    }

    #[Test]
    public function parse_config_array_detects_env_calls_with_default(): void
    {
        $inspector = new ConcreteInspectsCode;
        $result = $inspector->publicParseConfigArray(__DIR__.'/../../Fixtures/inspects-code-config/config_standard.php');

        $this->assertArrayHasKey('debug_env', $result);
        $this->assertTrue($result['debug_env']['isEnvCall']);
        $this->assertNull($result['debug_env']['value']);
        $this->assertFalse($result['debug_env']['envDefault']);

        $this->assertArrayHasKey('url', $result);
        $this->assertTrue($result['url']['isEnvCall']);
        $this->assertSame('http://localhost', $result['url']['envDefault']);
    }

    #[Test]
    public function parse_config_array_returns_null_for_complex_expressions(): void
    {
        $inspector = new ConcreteInspectsCode;
        $result = $inspector->publicParseConfigArray(__DIR__.'/../../Fixtures/inspects-code-config/config_standard.php');

        $this->assertArrayHasKey('complex', $result);
        $this->assertNull($result['complex']['value']);
        $this->assertFalse($result['complex']['isEnvCall']);
    }

    #[Test]
    public function parse_config_array_returns_empty_for_unparseable_file(): void
    {
        $inspector = new ConcreteInspectsCode;
        $result = $inspector->publicParseConfigArray(__DIR__.'/../../Fixtures/inspects-code-config/syntax_error.php');

        $this->assertSame([], $result);
    }

    #[Test]
    public function parse_config_array_returns_empty_when_no_return_statement(): void
    {
        $inspector = new ConcreteInspectsCode;
        $result = $inspector->publicParseConfigArray(__DIR__.'/../../Fixtures/inspects-code-config/config_no_return.php');

        $this->assertSame([], $result);
    }

    #[Test]
    public function parse_config_array_skips_integer_keyed_items(): void
    {
        $inspector = new ConcreteInspectsCode;
        $result = $inspector->publicParseConfigArray(__DIR__.'/../../Fixtures/inspects-code-config/config_mixed_keys.php');

        // String keys should be present
        $this->assertArrayHasKey('named_key', $result);
        $this->assertArrayHasKey('another', $result);
        $this->assertArrayHasKey('last', $result);

        // Integer key (0) should be skipped
        $this->assertCount(3, $result);
    }

    #[Test]
    public function parse_config_array_skips_spread_operator_items(): void
    {
        $inspector = new ConcreteInspectsCode;
        $result = $inspector->publicParseConfigArray(__DIR__.'/../../Fixtures/inspects-code-config/config_with_spread.php');

        // Spread operator items (...$defaults) are ArrayItem with unpack=true, so they
        // pass the instanceof check but their key is null (not String_), skipped at line 122
        $this->assertArrayHasKey('name', $result);
        $this->assertArrayHasKey('debug', $result);
        $this->assertCount(2, $result);
    }

    #[Test]
    public function parse_config_array_skips_null_array_items(): void
    {
        // php-parser's Array_::$items is typed as (ArrayItem|null)[] — null items
        // only occur in list() destructuring, never in real config files.
        // Test by injecting a mock parser that returns an AST with a null item.
        $inspector = new ConcreteInspectsCode;

        // Build a minimal AST: return ['key' => 'value', null]
        $items = [
            new ArrayItem(new String_('value'), new String_('key')),
            null, // The null item that exercises the guard on line 118
        ];
        /** @phpstan-ignore argument.type (Intentionally injecting null to test defensive guard) */
        $returnStmt = new \PhpParser\Node\Stmt\Return_(new Array_($items));

        // Create a mock parser that returns our crafted AST
        $mockParser = new class($returnStmt) extends \ShieldCI\AnalyzersCore\Support\AstParser
        {
            private \PhpParser\Node\Stmt\Return_ $ast;

            public function __construct(\PhpParser\Node\Stmt\Return_ $ast)
            {
                $this->ast = $ast;
            }

            /** @return array<\PhpParser\Node> */
            public function parseFile(string $filePath): array
            {
                return [$this->ast];
            }
        };

        // Inject the mock parser via reflection
        $reflection = new \ReflectionProperty($inspector, 'parser');
        $reflection->setAccessible(true);
        $reflection->setValue($inspector, $mockParser);

        $result = $inspector->publicParseConfigArray('/dev/null');

        // Only 'key' should be present, null item should be skipped
        $this->assertCount(1, $result);
        $this->assertArrayHasKey('key', $result);
        $this->assertSame('value', $result['key']['value']);
    }

    #[Test]
    public function resolve_config_value_returns_literal_for_non_env_entries(): void
    {
        $inspector = new ConcreteInspectsCode;

        $this->assertSame('lax', $inspector->publicResolveConfigValue([
            'value' => 'lax', 'line' => 1, 'isEnvCall' => false, 'envDefault' => null, 'envHasDefault' => false,
        ]));
        $this->assertFalse($inspector->publicResolveConfigValue([
            'value' => false, 'line' => 1, 'isEnvCall' => false, 'envDefault' => null, 'envHasDefault' => false,
        ]));
        $this->assertNull($inspector->publicResolveConfigValue([
            'value' => null, 'line' => 1, 'isEnvCall' => false, 'envDefault' => null, 'envHasDefault' => false,
        ]));
    }

    #[Test]
    public function resolve_config_value_returns_env_default_for_env_entries(): void
    {
        $inspector = new ConcreteInspectsCode;

        $this->assertSame('lax', $inspector->publicResolveConfigValue([
            'value' => null, 'line' => 1, 'isEnvCall' => true, 'envDefault' => 'lax', 'envHasDefault' => true,
        ]));
        $this->assertFalse($inspector->publicResolveConfigValue([
            'value' => null, 'line' => 1, 'isEnvCall' => true, 'envDefault' => false, 'envHasDefault' => true,
        ]));
        $this->assertTrue($inspector->publicResolveConfigValue([
            'value' => null, 'line' => 1, 'isEnvCall' => true, 'envDefault' => true, 'envHasDefault' => true,
        ]));
    }

    #[Test]
    public function resolve_config_value_returns_null_for_env_without_default(): void
    {
        $inspector = new ConcreteInspectsCode;

        $this->assertNull($inspector->publicResolveConfigValue([
            'value' => null, 'line' => 1, 'isEnvCall' => true, 'envDefault' => null, 'envHasDefault' => false,
        ]));
    }

    #[Test]
    public function parse_config_array_includes_line_numbers(): void
    {
        $inspector = new ConcreteInspectsCode;
        $result = $inspector->publicParseConfigArray(__DIR__.'/../../Fixtures/inspects-code-config/config_standard.php');

        foreach ($result as $entry) {
            $this->assertArrayHasKey('line', $entry);
            $this->assertIsInt($entry['line']);
            $this->assertGreaterThan(0, $entry['line']);
        }
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
     * @return array<string, array{value: mixed, line: int, isEnvCall: bool, envDefault: mixed, envHasDefault: bool}>
     */
    public function publicParseConfigArray(string $filePath): array
    {
        return $this->parseConfigArray($filePath);
    }

    /**
     * @param  array{value: mixed, line: int, isEnvCall: bool, envDefault: mixed, envHasDefault: bool}  $entry
     */
    public function publicResolveConfigValue(array $entry): mixed
    {
        return $this->resolveConfigValue($entry);
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
