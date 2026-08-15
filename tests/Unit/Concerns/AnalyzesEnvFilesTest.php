<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Concerns;

use ShieldCI\Concerns\AnalyzesEnvFiles;
use ShieldCI\Tests\TestCase;

class AnalyzesEnvFilesTest extends TestCase
{
    public function test_parse_env_file_reports_nonexistent_file(): void
    {
        $harness = new ConcreteAnalyzesEnvFiles;

        $result = $harness->publicParseEnvFileWithErrors('/nonexistent/path/.env');

        $this->assertSame('File does not exist', $result['error']);
        $this->assertSame([], $result['variables']);
        $this->assertSame([], $result['values']);
    }

    public function test_parse_commented_variables_tolerates_nonexistent_file(): void
    {
        $harness = new ConcreteAnalyzesEnvFiles;

        $result = $harness->publicParseCommentedVariablesWithErrors('/nonexistent/path/.env');

        $this->assertNull($result['error']);
        $this->assertSame([], $result['variables']);
    }

    public function test_vendor_key_harvest_returns_empty_without_base_path(): void
    {
        $harness = new ConcreteAnalyzesEnvFiles;

        $this->assertSame([], $harness->publicCollectVendorConfigEnvKeys());
    }

    public function test_vendor_file_name_harvest_returns_empty_without_base_path(): void
    {
        $harness = new ConcreteAnalyzesEnvFiles;

        $this->assertSame([], $harness->publicCollectVendorConfigFileNames());
    }
}

class ConcreteAnalyzesEnvFiles
{
    use AnalyzesEnvFiles;

    /**
     * @return array{variables: array<string, string>, values: array<string, string>, error: string|null}
     */
    public function publicParseEnvFileWithErrors(string $filePath): array
    {
        return $this->parseEnvFileWithErrors($filePath);
    }

    /**
     * @return array{variables: array<string, string>, error: string|null}
     */
    public function publicParseCommentedVariablesWithErrors(string $filePath): array
    {
        return $this->parseCommentedVariablesWithErrors($filePath);
    }

    /**
     * @return array<string, true>
     */
    public function publicCollectVendorConfigEnvKeys(): array
    {
        return $this->collectVendorConfigEnvKeys();
    }

    /**
     * @return array<string, true>
     */
    public function publicCollectVendorConfigFileNames(): array
    {
        return $this->collectVendorConfigFileNames();
    }

    protected function getBasePath(): string
    {
        return '';
    }

    /**
     * @param  array<int, string>  $paths
     */
    protected function setPaths(array $paths): void {}

    /**
     * @return array<int, string>
     */
    protected function getPhpFiles(): array
    {
        return [];
    }
}
