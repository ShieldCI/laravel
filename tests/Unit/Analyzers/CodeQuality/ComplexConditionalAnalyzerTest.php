<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\ComplexConditionalAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class ComplexConditionalAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new ComplexConditionalAnalyzer($this->parser);
    }

    public function test_detects_complex_conditionals(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class AccessControl
{
    public function canAccess($user, $resource)
    {
        if ($user->isActive() && !$user->isBanned() && ($user->hasRole('admin') || $user->hasRole('moderator')) && $user->emailVerified && $resource->isPublic()) {
            return true;
        }

        return false;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/AccessControl.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('logical operators', $result);
    }

    public function test_passes_with_extracted_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class AccessControl
{
    public function canAccess($user, $resource)
    {
        if (!$this->isEligibleUser($user)) {
            return false;
        }

        return $this->canAccessResource($user, $resource);
    }

    private function isEligibleUser($user)
    {
        return $user->isActive() && !$user->isBanned();
    }

    private function canAccessResource($user, $resource)
    {
        return $user->hasModeratorAccess() && $resource->isPublic();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/AccessControl.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
