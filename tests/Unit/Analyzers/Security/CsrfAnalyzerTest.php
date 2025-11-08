<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\CsrfAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CsrfAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CsrfAnalyzer;
    }

    public function test_passes_with_csrf_token_in_form(): void
    {
        $blade = <<<'BLADE'
<form method="POST">
    @csrf
    <input type="text" name="name">
    <button type="submit">Submit</button>
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/form.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_form_without_csrf(): void
    {
        $blade = <<<'BLADE'
<form method="POST">
    <input type="text" name="name">
    <button type="submit">Submit</button>
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/form.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('CSRF', $result);
    }

    public function test_ignores_get_forms(): void
    {
        $blade = <<<'BLADE'
<form method="GET">
    <input type="text" name="search">
    <button type="submit">Search</button>
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/search.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
