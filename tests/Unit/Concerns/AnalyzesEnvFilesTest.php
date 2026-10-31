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

    public function test_parses_names_the_way_dotenv_reads_them(): void
    {
        $result = $this->parse(implode("\n", [
            'export EXPORTED_NAME=one',
            "export\tTABBED_NAME=two",
            '"DOUBLE_QUOTED"=three',
            "'SINGLE_QUOTED'=four",
            'export "EXPORTED_QUOTED"=five',
            'lower_name=six',
            'dotted.name=seven',
            '1LEADING_DIGIT=eight',
            'ÜNICODE_NAME=nine',
            'export=ten',
            '  INDENTED_NAME = eleven',
        ]));

        $this->assertSame([
            'EXPORTED_NAME',
            'TABBED_NAME',
            'DOUBLE_QUOTED',
            'SINGLE_QUOTED',
            'EXPORTED_QUOTED',
            'lower_name',
            'dotted.name',
            '1LEADING_DIGIT',
            'ÜNICODE_NAME',
            'export',
            'INDENTED_NAME',
        ], array_keys($result['variables']));
        $this->assertSame('one', $result['values']['EXPORTED_NAME']);
        $this->assertSame('three', $result['values']['DOUBLE_QUOTED']);
    }

    public function test_skips_names_dotenv_rejects(): void
    {
        $result = $this->parse(implode("\n", [
            '"MISMATCHED\'=1',
            '""=2',
            'TWO WORDS=3',
            'exportNO_SPACE_IS_A_NAME=4',
            'NO_EQUALS_SIGN',
            '=5',
        ]));

        $this->assertSame(['exportNO_SPACE_IS_A_NAME'], array_keys($result['variables']));
    }

    public function test_multiline_value_lines_are_not_definitions(): void
    {
        $result = $this->parse(implode("\n", [
            'FIRST_KEY="-----BEGIN KEY-----',
            'abcDEF12==',
            'other=line',
            '# COMMENT_INSIDE=value',
            '-----END KEY-----"',
            'AFTER_FIRST=1',
            'SECOND_KEY="open',
            'escaped \" quote=still inside',
            '"',
            'AFTER_SECOND=2',
        ]));

        $this->assertSame(['FIRST_KEY', 'AFTER_FIRST', 'SECOND_KEY', 'AFTER_SECOND'], array_keys($result['variables']));
        $this->assertSame([], $this->parseCommented(implode("\n", [
            'FIRST_KEY="open',
            '# COMMENT_INSIDE=value',
            'close"',
        ]))['variables']);
    }

    public function test_multiline_value_closes_on_a_crlf_quote_line(): void
    {
        $result = $this->parse("OPENED=\"start\r\nmiddle=line\r\n\"\r\nAFTER=1");

        $this->assertSame(['OPENED', 'AFTER'], array_keys($result['variables']));
    }

    public function test_quoted_value_on_one_line_or_after_a_hash_does_not_open_a_multiline_value(): void
    {
        $result = $this->parse(implode("\n", [
            'ONE_LINE="closed"',
            'NEXT_ONE=1',
            '# NOTE="never closed',
            'NEXT_TWO=2',
        ]));

        $this->assertSame(['ONE_LINE', 'NEXT_ONE', 'NEXT_TWO'], array_keys($result['variables']));
    }

    public function test_unclosed_multiline_value_drops_the_rest_of_the_file(): void
    {
        $result = $this->parse(implode("\n", [
            'BEFORE=1',
            'UNCLOSED="starts here',
            'AFTER=2',
        ]));

        $this->assertSame(['BEFORE'], array_keys($result['variables']));
    }

    public function test_commented_variables_use_dotenv_name_rules(): void
    {
        $result = $this->parseCommented(implode("\n", [
            '# export EXPORTED_NAME=1',
            '#"QUOTED_NAME"=2',
            '# lower_name=3',
            '# A sentence with words=4',
            'ACTIVE_NAME=5',
        ]));

        $this->assertSame(['EXPORTED_NAME', 'QUOTED_NAME', 'lower_name'], array_keys($result['variables']));
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

    /**
     * @return array{variables: array<string, string>, values: array<string, string>, error: string|null}
     */
    private function parse(string $contents): array
    {
        return (new ConcreteAnalyzesEnvFiles)->publicParseEnvFileWithErrors($this->writeEnvFile($contents));
    }

    /**
     * @return array{variables: array<string, string>, error: string|null}
     */
    private function parseCommented(string $contents): array
    {
        return (new ConcreteAnalyzesEnvFiles)->publicParseCommentedVariablesWithErrors($this->writeEnvFile($contents));
    }

    private function writeEnvFile(string $contents): string
    {
        $path = $this->makeTempDirectory().'/.env';
        file_put_contents($path, $contents."\n");

        return $path;
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
