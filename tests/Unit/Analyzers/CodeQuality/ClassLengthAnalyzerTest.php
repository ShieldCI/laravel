<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\ClassLengthAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class ClassLengthAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new ClassLengthAnalyzer($this->parser);
    }

    public function test_detects_oversized_classes(): void
    {
        $methods = '';
        for ($i = 1; $i <= 25; $i++) {
            $methods .= "    public function method{$i}() { return true; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Services;

class GodObject
{
{$methods}}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/GodObject.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('too large', $result);
    }

    public function test_passes_with_reasonable_class_size(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getUser($id) { return User::find($id); }
    public function createUser($data) { return User::create($data); }
    public function updateUser($id, $data) { return User::update($id, $data); }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
