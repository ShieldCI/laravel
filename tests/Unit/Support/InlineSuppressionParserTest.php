<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Support\InlineSuppressionParser;
use ShieldCI\Tests\TestCase;

class InlineSuppressionParserTest extends TestCase
{
    private InlineSuppressionParser $parser;

    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->parser = new InlineSuppressionParser;
        $this->tempDir = sys_get_temp_dir().'/shieldci-suppression-test-'.uniqid();
        mkdir($this->tempDir, 0755, true);
    }

    protected function tearDown(): void
    {
        // Clean up temp files
        $files = glob($this->tempDir.'/*');
        if ($files !== false) {
            array_map('unlink', $files);
        }
        if (is_dir($this->tempDir)) {
            rmdir($this->tempDir);
        }
        parent::tearDown();
    }

    private function createTempFile(string $content): string
    {
        $path = $this->tempDir.'/test_'.uniqid().'.php';
        file_put_contents($path, $content);

        return $path;
    }

    // ==========================================
    // Bare @shieldci-ignore (suppress all analyzers)
    // ==========================================

    #[Test]
    public function bare_ignore_on_previous_line_suppresses_any_analyzer(): void
    {
        $file = $this->createTempFile(<<<'PHP'
<?php
// @shieldci-ignore
Route::post('/webhook', [WebhookController::class, 'handle']);
PHP);

        $this->assertTrue($this->parser->isLineSuppressed($file, 3, 'authentication-authorization'));
        $this->assertTrue($this->parser->isLineSuppressed($file, 3, 'sql-injection'));
        $this->assertTrue($this->parser->isLineSuppressed($file, 3, 'any-analyzer'));
    }

    #[Test]
    public function bare_ignore_on_same_line_suppresses_any_analyzer(): void
    {
        $file = $this->createTempFile(<<<'PHP'
<?php
$result = DB::select("SELECT * FROM users"); // @shieldci-ignore
PHP);

        $this->assertTrue($this->parser->isLineSuppressed($file, 2, 'sql-injection'));
        $this->assertTrue($this->parser->isLineSuppressed($file, 2, 'xss-detection'));
    }

    // ==========================================
    // Specific analyzer ID suppression
    // ==========================================

    #[Test]
    public function specific_analyzer_id_on_previous_line_suppresses_only_that_analyzer(): void
    {
        $file = $this->createTempFile(<<<'PHP'
<?php
// @shieldci-ignore sql-injection
$result = DB::select("SELECT * FROM users WHERE id = $id");
PHP);

        $this->assertTrue($this->parser->isLineSuppressed($file, 3, 'sql-injection'));
        $this->assertFalse($this->parser->isLineSuppressed($file, 3, 'xss-detection'));
    }

    #[Test]
    public function specific_analyzer_id_on_same_line_suppresses_only_that_analyzer(): void
    {
        $file = $this->createTempFile(<<<'PHP'
<?php
echo $userInput; // @shieldci-ignore xss-detection
PHP);

        $this->assertTrue($this->parser->isLineSuppressed($file, 2, 'xss-detection'));
        $this->assertFalse($this->parser->isLineSuppressed($file, 2, 'sql-injection'));
    }

    // ==========================================
    // Comma-separated multiple analyzer IDs
    // ==========================================

    #[Test]
    public function comma_separated_ids_suppress_all_listed_analyzers(): void
    {
        $file = $this->createTempFile(<<<'PHP'
<?php
// @shieldci-ignore sql-injection,xss-detection
echo DB::select("SELECT * FROM users WHERE name = '$name'");
PHP);

        $this->assertTrue($this->parser->isLineSuppressed($file, 3, 'sql-injection'));
        $this->assertTrue($this->parser->isLineSuppressed($file, 3, 'xss-detection'));
        $this->assertFalse($this->parser->isLineSuppressed($file, 3, 'authentication-authorization'));
    }

    // ==========================================
    // No suppression
    // ==========================================

    #[Test]
    public function line_without_suppression_comment_is_not_suppressed(): void
    {
        $file = $this->createTempFile(<<<'PHP'
<?php
// This is a normal comment
$result = DB::select("SELECT * FROM users");
PHP);

        $this->assertFalse($this->parser->isLineSuppressed($file, 3, 'sql-injection'));
    }

    #[Test]
    public function suppression_on_unrelated_line_does_not_affect_other_lines(): void
    {
        $file = $this->createTempFile(<<<'PHP'
<?php
// @shieldci-ignore sql-injection
$safe = DB::select("SELECT 1");

$unsafe = DB::select("SELECT * FROM users WHERE id = $id");
PHP);

        // Line 3 is suppressed (line 2 is the comment)
        $this->assertTrue($this->parser->isLineSuppressed($file, 3, 'sql-injection'));

        // Line 5 is NOT suppressed (the comment on line 2 only covers line 2 and 3)
        $this->assertFalse($this->parser->isLineSuppressed($file, 5, 'sql-injection'));
    }

    // ==========================================
    // Edge cases
    // ==========================================

    #[Test]
    public function nonexistent_file_returns_not_suppressed(): void
    {
        $this->assertFalse($this->parser->isLineSuppressed('/nonexistent/path.php', 1, 'sql-injection'));
    }

    #[Test]
    public function line_zero_returns_not_suppressed(): void
    {
        $file = $this->createTempFile("<?php\n// @shieldci-ignore\n\$x = 1;");

        $this->assertFalse($this->parser->isLineSuppressed($file, 0, 'sql-injection'));
    }

    #[Test]
    public function negative_line_returns_not_suppressed(): void
    {
        $file = $this->createTempFile("<?php\n// @shieldci-ignore\n\$x = 1;");

        $this->assertFalse($this->parser->isLineSuppressed($file, -1, 'sql-injection'));
    }

    #[Test]
    public function first_line_of_file_can_be_suppressed(): void
    {
        $file = $this->createTempFile('<?php // @shieldci-ignore');

        $this->assertTrue($this->parser->isLineSuppressed($file, 1, 'any-analyzer'));
    }

    #[Test]
    public function case_insensitive_matching(): void
    {
        $file = $this->createTempFile(<<<'PHP'
<?php
// @SHIELDCI-IGNORE sql-injection
$result = DB::select("SELECT 1");
PHP);

        $this->assertTrue($this->parser->isLineSuppressed($file, 3, 'sql-injection'));
    }

    #[Test]
    public function file_reads_are_cached(): void
    {
        $file = $this->createTempFile(<<<'PHP'
<?php
// @shieldci-ignore
$a = 1;
$b = 2;
PHP);

        // First call reads the file
        $this->assertTrue($this->parser->isLineSuppressed($file, 3, 'x'));

        // Second call should use cache (same parser instance)
        $this->assertFalse($this->parser->isLineSuppressed($file, 4, 'x'));
    }

    // ==========================================
    // Comment styles
    // ==========================================

    #[Test]
    public function hash_comment_style_works(): void
    {
        $file = $this->createTempFile(<<<'PHP'
<?php
# @shieldci-ignore sql-injection
$result = DB::select("SELECT 1");
PHP);

        $this->assertTrue($this->parser->isLineSuppressed($file, 3, 'sql-injection'));
    }

    #[Test]
    public function block_comment_style_works(): void
    {
        $file = $this->createTempFile(<<<'PHP'
<?php
/* @shieldci-ignore sql-injection */
$result = DB::select("SELECT 1");
PHP);

        $this->assertTrue($this->parser->isLineSuppressed($file, 3, 'sql-injection'));
    }

    #[Test]
    public function docblock_comment_style_works(): void
    {
        $file = $this->createTempFile(<<<'PHP'
<?php
/** @shieldci-ignore sql-injection */
$result = DB::select("SELECT 1");
PHP);

        $this->assertTrue($this->parser->isLineSuppressed($file, 3, 'sql-injection'));
    }

    // ==========================================
    // Additional edge cases
    // ==========================================

    #[Test]
    public function empty_file_returns_not_suppressed(): void
    {
        $file = $this->createTempFile('');

        $this->assertFalse($this->parser->isLineSuppressed($file, 1, 'sql-injection'));
    }

    #[Test]
    public function line_beyond_file_length_returns_not_suppressed(): void
    {
        $file = $this->createTempFile("<?php\n\$a = 1;\n\$b = 2;");

        $this->assertFalse($this->parser->isLineSuppressed($file, 10, 'sql-injection'));
    }

    #[Test]
    public function whitespace_around_comma_separated_ids_prevents_match(): void
    {
        // The regex `[\w,-]+` stops at whitespace, so " xss-detection" won't be captured
        $file = $this->createTempFile(<<<'PHP'
<?php
// @shieldci-ignore sql-injection, xss-detection
$result = DB::select("SELECT 1");
PHP);

        // sql-injection should match (it's before the space)
        $this->assertTrue($this->parser->isLineSuppressed($file, 3, 'sql-injection'));

        // xss-detection should NOT match because the regex captures "sql-injection,"
        // and the space before "xss-detection" terminates the regex capture group
        $this->assertFalse($this->parser->isLineSuppressed($file, 3, 'xss-detection'));
    }

    #[Test]
    public function unreadable_file_returns_not_suppressed(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('chmod not supported on Windows');
        }

        $file = $this->createTempFile("<?php\n// @shieldci-ignore\n\$x = 1;");
        chmod($file, 0000);

        $this->assertFalse($this->parser->isLineSuppressed($file, 3, 'sql-injection'));

        // Restore permissions for cleanup
        chmod($file, 0644);
    }
}
