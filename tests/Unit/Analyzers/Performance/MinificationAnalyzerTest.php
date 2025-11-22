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

    public function test_detects_minified_files_by_source_map(): void
    {
        // File with source map reference is considered minified even if multi-line
        $jsWithSourceMap = <<<'JS'
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

        $this->assertPassed($result);
    }

    public function test_detects_css_with_source_map(): void
    {
        // CSS file with source map reference
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

        $this->assertPassed($result);
    }

    public function test_line_count_threshold_15_lines(): void
    {
        // File with exactly 16 lines should fail (threshold is 15)
        $lines = [];
        for ($i = 1; $i <= 16; $i++) {
            $lines[] = "line{$i}";
        }
        $content = implode("\n", $lines);

        $tempDir = $this->createTempDirectory([
            'public/js/app.js' => $content,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

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
        $unminifiedJs = str_repeat("function example() {\n    console.log('nested');\n}\n", 10);

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

        config(['shieldci.build_path' => 'custom_build']);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('unminified assets', $result);
    }

    public function test_detects_vite_manifest_assets(): void
    {
        $unminifiedJs = str_repeat("function test() {\n    console.log('x');\n}\n", 10);

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
        config(['shieldci.build_path' => $tempDir.'/public']);

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
        $this->assertEquals('Asset Minification', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Performance, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $metadata->severity);
        $this->assertContains('minification', $metadata->tags);
    }

    public function test_run_in_ci_property_is_false(): void
    {
        $this->assertFalse(MinificationAnalyzer::$runInCI);
    }
}
