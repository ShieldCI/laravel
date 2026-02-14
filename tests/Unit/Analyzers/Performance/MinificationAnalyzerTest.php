<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use ShieldCI\Analyzers\Performance\MinificationAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class MinificationAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        $analyzer = new MinificationAnalyzer;
        $analyzer->setRelevantEnvironments(null);

        return $analyzer;
    }

    public function test_passes_with_minified_assets(): void
    {
        // Minified file: single line with long content
        $minifiedCss = str_repeat('body{color:red;}', 100); // Long single line
        $minifiedJs = str_repeat('function test(){console.log("x");}', 100);

        $tempDir = $this->createTempDirectory([
            'public/css/app.css' => $minifiedCss,
            'public/js/app.js' => $minifiedJs,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_unminified_assets(): void
    {
        // Unminified file: multiple lines with normal formatting
        $unminifiedCss = <<<'CSS'
body {
    color: red;
    background: blue;
    margin: 0;
    padding: 0;
    font-size: 16px;
    line-height: 1.5;
    font-family: sans-serif;
    display: block;
    position: relative;
    width: 100%;
    height: 100%;
    overflow: auto;
    z-index: 1;
    box-sizing: border-box;
    text-align: left;
}
CSS;

        $tempDir = $this->createTempDirectory([
            'public/css/app.css' => $unminifiedCss,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('unminified', $result);
    }

    public function test_detects_unminified_files_even_with_source_map(): void
    {
        // File with source map reference but unminified code should still be detected as unminified
        // Source maps are present in both dev and production builds
        $jsWithSourceMap = <<<'JS'
/**
 * Test function with JSDoc comment
 * indicating unminified source code
 */
function test() {
    console.log("test");
}


function another() {
    return true;
}
//# sourceMappingURL=app.js.map
JS;

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $jsWithSourceMap,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail because the code is unminified (JSDoc comments, blank lines)
        $this->assertWarning($result);
    }

    public function test_detects_unminified_css_even_with_source_map(): void
    {
        // CSS file with source map reference but unminified formatting
        $cssWithSourceMap = <<<'CSS'
body {
    color: red;
}
.container {
    width: 100%;
}
/*# sourceMappingURL=app.css.map */
CSS;

        $tempDir = $this->createTempDirectory([
            'public/css/app.css' => $cssWithSourceMap,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail because the CSS is unminified (indented, multiple lines)
        $this->assertWarning($result);
    }

    public function test_minified_code_with_source_map_passes(): void
    {
        // Properly minified code with source map should still pass
        $minifiedJs = str_repeat('function x(){return 1;}', 100)."\n//# sourceMappingURL=app.js.map";

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $minifiedJs,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass because the code is actually minified
        $this->assertPassed($result);
    }

    public function test_unminified_code_with_jsdoc_comments(): void
    {
        // File with unminified code should fail (JSDoc comments indicate unminified)
        // Need enough content to exceed MIN_FILE_SIZE_FOR_SIZE_CHECKS (1024 bytes)
        $content = <<<'JS'
/**
 * Calculate the total price of items
 * @param {Array} items - Array of items with price property
 * @returns {number} Total price
 */
function calculateTotal(items) {
    let total = 0;

    for (let i = 0; i < items.length; i++) {
        total += items[i].price;
    }

    return total;
}

/**
 * Format amount as currency
 * @param {number} amount - The amount to format
 * @returns {string} Formatted currency string
 */
function formatCurrency(amount) {
    return '$' + amount.toFixed(2);
}

function displayTotal(items) {
    const total = calculateTotal(items);
    const formatted = formatCurrency(total);
    console.log(formatted);
}

module.exports = { calculateTotal, formatCurrency, displayTotal };
JS;

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail: JSDoc comments indicate unminified code
        $this->assertWarning($result);
    }

    public function test_passes_with_15_lines_or_less(): void
    {
        // File with exactly 15 lines but long average line length should pass
        $lines = [];
        for ($i = 1; $i <= 15; $i++) {
            $lines[] = str_repeat('x', 600); // Long lines
        }
        $content = implode("\n", $lines);

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_mix_manifest_assets(): void
    {
        $unminifiedCss = str_repeat("body {\n    color: red;\n}\n", 10);

        $mixManifest = json_encode([
            '/css/app.css' => '/css/app.css?id=abc123',
        ]);

        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => $mixManifest,
            'public/css/app.css' => $unminifiedCss,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Mix', $result);
    }

    public function test_detects_nested_unminified_assets(): void
    {
        // Realistic unminified code with JSDoc comments
        $unminifiedJs = <<<'JS'
/**
 * Nested module for example functionality
 * @module nested
 */
function example() {
    console.log('nested');
}


function anotherFunction() {
    return true;
}


module.exports = { example, anotherFunction };
JS;

        $tempDir = $this->createTempDirectory([
            'public/js/nested/app.js' => $unminifiedJs,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('unminified assets', $result);
    }

    public function test_honors_custom_build_path_configuration(): void
    {
        $unminifiedCss = "body {\n    color: blue;\n}\n";

        $tempDir = $this->createTempDirectory([
            'custom_build/css/app.css' => $unminifiedCss,
        ]);

        config(['shieldci.analyzers.performance.asset-minification.build_path' => 'custom_build']);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('unminified assets', $result);
    }

    public function test_detects_vite_manifest_assets(): void
    {
        // Realistic unminified code with JSDoc comments
        $unminifiedJs = <<<'JS'
/**
 * Test module for application
 * @module test
 */
function test() {
    console.log('x');
}


function another() {
    return 42;
}


module.exports = { test, another };
JS;

        $viteManifest = json_encode([
            'resources/js/app.js' => [
                'file' => 'assets/app.abc123.js',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'public/build/manifest.json' => $viteManifest,
            'public/build/assets/app.abc123.js' => $unminifiedJs,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Vite', $result);
    }

    public function test_skips_minified_files_with_min_in_name(): void
    {
        $unminifiedCss = str_repeat("body {\n    color: red;\n}\n", 10);
        $minifiedCss = str_repeat('body{color:red;}', 100);

        $tempDir = $this->createTempDirectory([
            'public/css/app.css' => $unminifiedCss,
            'public/css/app.min.css' => $minifiedCss,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should only report app.css, not app.min.css
        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
    }

    public function test_skips_when_public_directory_missing(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\Models; class User {}',
        ]);

        // Set config to use temp directory's public path (which doesn't exist)
        config(['shieldci.analyzers.performance.asset-minification.build_path' => $tempDir.'/public']);

        /** @var MinificationAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertFalse($analyzer->shouldRun());
        $this->assertStringContainsString('Build directory not found', $analyzer->getSkipReason());
    }

    public function test_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('asset-minification', $metadata->id);
        $this->assertEquals('Asset Minification Analyzer', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Performance, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $metadata->severity);
        $this->assertContains('minification', $metadata->tags);
    }

    public function test_run_in_ci_property_is_false(): void
    {
        $this->assertFalse(MinificationAnalyzer::$runInCI);
    }

    // Category 1: Boundary Tests for Minification Constants

    public function test_file_with_jsdoc_is_unminified(): void
    {
        // File with unminified code (JSDoc comments)
        // Should fail due to formatted multi-line comments
        $content = <<<'JS'
/**
 * User management functions
 * @module users
 */

/**
 * Get user by ID
 * @param {number} id - User ID
 * @returns {Object} User object
 */
function getUserById(id) {
    return database.users.find(u => u.id === id);
}

function updateUser(id, data) {
    const user = getUserById(id);
    if (!user) {
        throw new Error('User not found');
    }

    Object.assign(user, data);
    return user;
}

function deleteUser(id) {
    const index = database.users.findIndex(u => u.id === id);
    if (index !== -1) {
        database.users.splice(index, 1);
    }
}

module.exports = { getUserById, updateUser, deleteUser };
JS;

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail: JSDoc comments indicate unminified code
        $this->assertWarning($result);
    }

    public function test_file_with_exactly_500_char_avg_line_length_passes(): void
    {
        // File with exactly MIN_AVG_LINE_LENGTH_FOR_MINIFIED (500 chars)
        $line = str_repeat('x', 500);
        $content = $line; // Single line

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_file_with_499_char_avg_line_length_checks_patterns(): void
    {
        // Just below threshold (499 chars) - should check patterns
        $line = str_repeat('x', 499);
        $content = $line; // Single compact line, no unminified patterns

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_file_with_exactly_15_percent_whitespace_ratio(): void
    {
        // Exactly MAX_WHITESPACE_RATIO_FOR_MINIFIED (0.15 = 15%)
        // Create content with exactly 15% spaces
        $nonSpaces = str_repeat('x', 850);
        $spaces = str_repeat(' ', 150); // 150/(850+150) = 0.15
        $content = $nonSpaces.$spaces;

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_file_with_16_percent_whitespace_ratio_is_unminified(): void
    {
        // Above MAX_WHITESPACE_RATIO_FOR_MINIFIED (0.16 = 16%)
        // Lines must be < 350 chars so max line length check doesn't classify as minified
        // Avg line length > 100 so we reach the whitespace ratio check
        $lines = [];
        for ($i = 0; $i < 20; $i++) {
            // Each line is 200 chars with ~40 spaces = 20% whitespace
            $lines[] = str_repeat('x', 80).str_repeat(' ', 20).str_repeat('y', 80).str_repeat(' ', 20);
        }
        $content = implode("\n", $lines);

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail: avg line length > 100 but excessive whitespace (20% > 15%)
        $this->assertWarning($result);
    }

    public function test_file_with_exactly_1024_bytes_uses_size_checks(): void
    {
        // Exactly MIN_FILE_SIZE_FOR_SIZE_CHECKS (1024 bytes)
        // Should use size-based checks, not pattern checks
        $content = str_repeat('x', 1024); // Single line, 1024 bytes

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_small_file_under_1024_bytes_with_minified_patterns(): void
    {
        // Small file (< 1024 bytes) that is minified (compact, no patterns)
        $content = str_repeat('function x(){return 1;}', 40); // ~960 bytes, compact

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_small_file_under_1024_bytes_with_unminified_patterns(): void
    {
        // Small file (< 1024 bytes) with unminified patterns (multiple blank lines)
        $content = "line1\n\n\nline2\n\n\nline3"; // Multiple consecutive newlines

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
    }

    public function test_empty_file_passes(): void
    {
        // Empty file - edge case for division by zero
        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => '',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Empty files should pass (nothing to minify)
        $this->assertPassed($result);
    }

    public function test_file_with_only_whitespace_passes(): void
    {
        // File with only whitespace (spaces, tabs, newlines)
        $content = "   \n\t\n   \t  ";

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Whitespace-only should pass (essentially empty)
        $this->assertPassed($result);
    }

    public function test_file_with_newline_function_call_pattern_is_unminified(): void
    {
        // Test with realistic unminified code showing function calls on newlines
        $content = <<<'JS'
// Initialize application
const app = {};

// Setup configuration
app.config = {
    debug: true,
    version: '1.0.0'
};

// Helper functions
app.init = function() {
    console.log('Initializing...');

    setupDatabase();

    loadPlugins();

    startServer();
};

// Export module
module.exports = app;
JS;

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail: comments + function calls on newlines
        $this->assertWarning($result);
    }

    // Category 2: Source Map Detection Tests

    public function test_file_with_source_url_reference_and_minified_code_passes(): void
    {
        // sourceURL reference with compact minified code should pass
        $content = <<<'JS'
function test(){console.log("x");}
function another(){return true;}
//# sourceURL=webpack:///src/app.js
JS;

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass - code is compact/minified (no spaces, no indentation)
        $this->assertPassed($result);
    }

    public function test_file_with_block_comment_source_map_but_unminified_code(): void
    {
        // /*# sourceMappingURL= */ doesn't make unminified code minified
        // JSDoc comments indicate unminified code
        $content = <<<'JS'
/**
 * Test functions module
 * @module testFunctions
 */
function test() {
    console.log("x");
}

function another() {
    return true;
}

function third() {
    var x = 1;
    var y = 2;
    return x + y;
}

function fourth() {
    console.log("more");
}
/*# sourceMappingURL=app.js.map */
JS;

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail because the code is unminified (formatted, indented, many lines)
        $this->assertWarning($result);
    }

    public function test_file_with_uppercase_sourcemappingurl_and_minified_code_passes(): void
    {
        // Source map with compact minified code should pass
        $content = <<<'JS'
function test(){console.log("x");}
//# SOURCEMAPPINGURL=app.js.map
JS;

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass - code is compact/minified
        $this->assertPassed($result);
    }

    public function test_file_with_source_map_and_unminified_patterns_is_detected_as_unminified(): void
    {
        // Source map reference does NOT override objective minification checks
        // Unminified patterns should be detected regardless of source map presence
        $unminifiedCss = <<<'CSS'
body {
    color: red;
    background: blue;
    margin: 0;
    padding: 0;
}

.container {
    width: 100%;
}
/*# sourceMappingURL=app.css.map */
CSS;

        $tempDir = $this->createTempDirectory([
            'public/css/app.css' => $unminifiedCss,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail because the CSS has clear unminified patterns
        $this->assertWarning($result);
    }

    public function test_file_with_malformed_source_map_comment_is_detected_as_unminified(): void
    {
        // Malformed source map marker doesn't make unminified code pass
        // JSDoc comments indicate unminified code
        $content = <<<'JS'
/**
 * Test module with malformed source map
 * @module test
 */
function test() {
    console.log("x");
}
function another() {
    return true;
}
//# sourceMappingURL=
JS;

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail because the code is unminified (formatted, indented)
        $this->assertWarning($result);
    }

    // Category 3: hasUnminifiedPatterns() Tests

    public function test_multiple_consecutive_newlines_pattern_is_unminified(): void
    {
        // Pattern: \n\s*\n\s*\n (3+ newlines with optional whitespace)
        $content = <<<'JS'
function test() {
    console.log("test");
}


function another() {
    return true;
}
JS;

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
    }

    public function test_jsdoc_formatted_comments_is_unminified(): void
    {
        // JSDoc-style formatted comments indicate unminified code
        // These have internal newlines and asterisk formatting
        $content = <<<'JS'
/**
 * This is a JSDoc comment
 * with multiple lines
 */
function test() {
    console.log("x");
}
JS;

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should warn - formatted JSDoc comments indicate unminified code
        $this->assertWarning($result);
    }

    public function test_css_indented_properties_pattern_is_unminified(): void
    {
        // Pattern: \n\s{2,}[\w\-]+\s*:\s*
        $content = <<<'CSS'
body {
  color: red;
  background: blue;
  margin: 0;
}
CSS;

        $tempDir = $this->createTempDirectory([
            'public/css/app.css' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
    }

    public function test_readable_variable_names_alone_passes(): void
    {
        // Readable variable names don't indicate unminified code
        // Modern minifiers often preserve names (debugging, no-mangle config)
        $content = <<<'JS'
var userName = "test";
var userEmail = "test@example.com";
var userAge = 25;
var userAddress = "123 Main St";
var userPhone = "555-1234";
var userCity = "Springfield";
var userState = "IL";
JS;

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass - readable names are not reliable indicators of minification
        $this->assertPassed($result);
    }

    public function test_comments_with_source_mapping_url_is_minified(): void
    {
        // Has comments AND sourceMappingURL - should be considered minified
        $content = <<<'JS'
/* Copyright 2024 */
function test(){console.log("x");}
//# sourceMappingURL=app.js.map
JS;

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_multiline_block_comments_is_unminified(): void
    {
        // Multi-line block comments with formatting indicate unminified code
        $content = <<<'JS'
/*
 * This is a formatted block comment
 * spanning multiple lines with asterisks
 */
function test() {
    console.log("x");
}
JS;

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should warn - formatted multi-line comments indicate unminified code
        $this->assertWarning($result);
    }

    public function test_single_line_comments_alone_passes(): void
    {
        // Single-line comments are common in production builds (license, annotations)
        // They alone don't indicate unminified code
        $content = <<<'JS'
// Initialize application
var app = {};
// Set configuration
app.config = {debug: true};
JS;

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass - single-line comments are preserved in many minified builds
        $this->assertPassed($result);
    }

    // Category 4: Mix Manifest Handling Tests

    public function test_mix_manifest_with_malformed_json_is_skipped(): void
    {
        // Malformed JSON - should return early
        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => '{invalid json',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass (no assets detected)
        $this->assertPassed($result);
    }

    public function test_mix_manifest_with_empty_object_is_skipped(): void
    {
        // Empty manifest
        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => '{}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_mix_manifest_with_non_string_values_are_skipped(): void
    {
        // Manifest with non-string values
        $mixManifest = json_encode([
            '/css/app.css' => '/css/app.css?id=abc123',
            '/js/app.js' => ['file' => '/js/app.js'], // Non-string
            '/other' => null, // Non-string
            '/number' => 123, // Non-string
        ]);

        $unminifiedCss = str_repeat("body {\n    color: red;\n}\n", 10);

        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => $mixManifest,
            'public/css/app.css' => $unminifiedCss,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should only report the CSS file
        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
    }

    public function test_mix_manifest_with_windows_backslash_paths(): void
    {
        // Paths with Windows backslashes
        $mixManifest = json_encode([
            '\\css\\app.css' => '\\css\\app.css?id=abc123',
        ]);

        $unminifiedCss = str_repeat("body {\n    color: red;\n}\n", 10);

        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => $mixManifest,
            'public/css/app.css' => $unminifiedCss,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
    }

    public function test_mix_manifest_with_nonexistent_file_is_skipped(): void
    {
        // Manifest references file that doesn't exist
        $mixManifest = json_encode([
            '/css/app.css' => '/css/app.css?id=abc123',
            '/js/missing.js' => '/js/missing.js?id=xyz789',
        ]);

        $unminifiedCss = str_repeat("body {\n    color: red;\n}\n", 10);

        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => $mixManifest,
            'public/css/app.css' => $unminifiedCss,
            // missing.js doesn't exist
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should only check app.css
        $this->assertWarning($result);
    }

    // Category 5: Vite Asset Handling Tests

    public function test_vite_build_directory_not_existing_is_skipped(): void
    {
        // Vite manifest exists but build directory doesn't
        $viteManifest = json_encode([
            'resources/js/app.js' => [
                'file' => 'assets/app.abc123.js',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'public/build/manifest.json' => $viteManifest,
            // No build/assets directory
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass (no assets to check)
        $this->assertPassed($result);
    }

    public function test_vite_handles_glob_returning_false(): void
    {
        // Create a scenario where glob might return false
        // (This is hard to test directly, but we ensure it doesn't crash)
        $viteManifest = json_encode([
            'resources/js/app.js' => [
                'file' => 'assets/app.abc123.js',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'public/build/manifest.json' => $viteManifest,
            'public/build/assets/.gitkeep' => '',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass (no matching JS/CSS files)
        $this->assertPassed($result);
    }

    public function test_vite_with_mixed_minified_and_unminified_files(): void
    {
        // Some minified, some unminified
        $minifiedJs = str_repeat('function x(){return 1;}', 100);
        // Realistic unminified code with JSDoc comments
        $unminifiedJs = <<<'JS'
/**
 * Module code for testing
 * @module test
 */
function test() {
    console.log('x');
}

function helper() {
    return 1;
}

module.exports = { test, helper };
JS;

        $viteManifest = json_encode([
            'resources/js/app.js' => [
                'file' => 'assets/app.abc123.js',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'public/build/manifest.json' => $viteManifest,
            'public/build/assets/app.abc123.js' => $unminifiedJs,
            'public/build/assets/vendor.xyz789.js' => $minifiedJs,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should report only unminified
        $this->assertWarning($result);
        $this->assertHasIssueContaining('Vite', $result);
    }

    // Category 6: Environment & Configuration Tests

    public function test_environment_filtering_with_set_relevant_environments(): void
    {
        // Test environment filtering via setRelevantEnvironments()
        /** @var MinificationAnalyzer $analyzer */
        $analyzer = new MinificationAnalyzer;
        $analyzer->setRelevantEnvironments(['production', 'staging']);

        $unminifiedCss = str_repeat("body {\n    color: red;\n}\n", 10);

        $tempDir = $this->createTempDirectory([
            'public/css/app.css' => $unminifiedCss,
        ]);

        $analyzer->setBasePath($tempDir);

        // With testing environment (default in PHPUnit), should skip
        $this->assertFalse($analyzer->shouldRun());
        $this->assertStringContainsString('testing', $analyzer->getSkipReason());
    }

    public function test_custom_build_path_with_absolute_path(): void
    {
        // Absolute path configuration
        $unminifiedCss = str_repeat("body {\n    color: red;\n}\n", 10);

        $tempDir = $this->createTempDirectory([
            'custom/css/app.css' => $unminifiedCss,
        ]);

        $absolutePath = $tempDir.DIRECTORY_SEPARATOR.'custom';
        config(['shieldci.analyzers.performance.asset-minification.build_path' => $absolutePath]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());

        $result = $analyzer->analyze();

        $this->assertWarning($result);
    }

    public function test_config_with_build_path_outside_base_path_uses_default(): void
    {
        // Config path outside base path should be rejected
        $tempDir = $this->createTempDirectory([
            'public/css/app.css' => str_repeat("body {\n    color: red;\n}\n", 10),
        ]);

        config(['shieldci.analyzers.performance.asset-minification.build_path' => '/completely/different/path']);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        // Should fall back to default (public)
        $this->assertTrue($analyzer->shouldRun());
    }

    // Additional Edge Cases

    public function test_metadata_includes_exactly_10_unminified_files_when_more_exist(): void
    {
        // Create 15 unminified files, verify only 10 are in metadata
        $files = [];
        for ($i = 1; $i <= 15; $i++) {
            $files["public/css/file{$i}.css"] = "body {\n    color: red;\n}\n";
        }

        $tempDir = $this->createTempDirectory($files);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $metadata = $issues[0]->metadata;
        $this->assertArrayHasKey('unminified_files', $metadata);
        $this->assertArrayHasKey('total_count', $metadata);
        $this->assertIsArray($metadata['unminified_files']);
        $this->assertCount(10, $metadata['unminified_files']);
        $this->assertEquals(15, $metadata['total_count']);
    }

    public function test_vite_metadata_includes_exactly_5_suspicious_files(): void
    {
        // Create 8 unminified files, verify only 5 are in metadata
        // Realistic unminified code with JSDoc comments
        $unminifiedJs = <<<'JS'
/**
 * File module for testing
 * @module file
 */
function test() {
    console.log('x');
}

function helper() {
    return 1;
}

module.exports = { test, helper };
JS;

        $files = [
            'public/build/manifest.json' => '{}',
        ];

        for ($i = 1; $i <= 8; $i++) {
            $files["public/build/assets/file{$i}.js"] = $unminifiedJs;
        }

        $tempDir = $this->createTempDirectory($files);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();

        $metadata = $issues[0]->metadata;
        $this->assertArrayHasKey('suspicious_files', $metadata);
        $this->assertArrayHasKey('total_count', $metadata);
        $this->assertIsArray($metadata['suspicious_files']);
        $this->assertCount(5, $metadata['suspicious_files']);
        $this->assertEquals(8, $metadata['total_count']);
    }

    public function test_mix_metadata_limits_to_10_assets(): void
    {
        // Create 12 unminified assets in Mix
        $manifest = [];
        $files = ['public/mix-manifest.json' => ''];

        for ($i = 1; $i <= 12; $i++) {
            $manifest["/css/file{$i}.css"] = "/css/file{$i}.css?id=abc{$i}";
            $files["public/css/file{$i}.css"] = "body {\n    color: red;\n}\n";
        }

        $files['public/mix-manifest.json'] = json_encode($manifest);

        $tempDir = $this->createTempDirectory($files);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();

        $metadata = $issues[0]->metadata;
        $this->assertArrayHasKey('unminified_assets', $metadata);
        $this->assertIsArray($metadata['unminified_assets']);
        $this->assertCount(10, $metadata['unminified_assets']);
        $this->assertEquals(12, $metadata['total_count']);
    }

    // New tests for line count fix (handling >15 lines with high avg line length)

    public function test_minified_file_with_license_banner_passes(): void
    {
        // Minified file with 30-line license banner at top
        // Should PASS because avg line length is very high (minified code)
        $banner = "/*!\n * Copyright (c) 2024 Example Corp.\n * Licensed under MIT\n */\n";
        $minifiedCode = str_repeat('function x(){return 1;}', 200); // Very long single line (4600+ chars)
        $content = $banner.$minifiedCode;

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass: high avg line length (900+ chars/line) indicates minified
        $this->assertPassed($result);
    }

    public function test_minified_with_webpack_chunks_passes(): void
    {
        // Webpack output with runtime chunks (40+ lines)
        // Each line is very long, minified content
        $lines = [];
        for ($i = 1; $i <= 40; $i++) {
            // Each line is 1000+ chars of minified code
            $lines[] = str_repeat('function chunk'.$i.'(){return '.$i.';}', 50);
        }
        $content = implode("\n", $lines);

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass: many lines but each line is very long (minified chunks)
        $this->assertPassed($result);
    }

    public function test_truly_unminified_20_lines_fails(): void
    {
        // 20 lines but each line is short, formatted, indented
        // Should FAIL because JSDoc comments indicate unminified code
        $content = <<<'JS'
/**
 * Calculate total price of items
 * @param {Array} items - Items to calculate
 * @returns {number} Total price
 */
function calculateTotal(items) {
    let total = 0;

    for (let i = 0; i < items.length; i++) {
        total += items[i].price;
    }

    return total;
}

function formatCurrency(amount) {
    return '$' + amount.toFixed(2);
}

function displayTotal(items) {
    const total = calculateTotal(items);
    const formatted = formatCurrency(total);
    console.log(formatted);
}
JS;

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail: JSDoc comments indicate unminified code
        $this->assertWarning($result);
    }

    public function test_pretty_minified_css_with_strategic_line_breaks(): void
    {
        // PostCSS output with strategic line breaks for debugging
        // Still minified (no spaces, compact) but has line breaks
        $lines = [];
        for ($i = 1; $i <= 25; $i++) {
            // Each line is 800+ chars of minified CSS
            $lines[] = '.class'.$i.'{color:red;background:blue;margin:0;padding:0;}'.str_repeat('.another{width:100%;}', 30);
        }
        $content = implode("\n", $lines);

        $tempDir = $this->createTempDirectory([
            'public/css/app.css' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass: high avg line length indicates minification despite line breaks
        $this->assertPassed($result);
    }
}
