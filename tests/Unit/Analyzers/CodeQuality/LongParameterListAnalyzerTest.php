<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\LongParameterListAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class LongParameterListAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new LongParameterListAnalyzer($this->parser);
    }

    public function test_detects_multiple_same_type_parameters(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function createUser(
        string $name,
        string $email,
        string $phone,
        string $address,
        string $city,
        string $country
    ) {
        return User::create(compact('name', 'email', 'phone', 'address', 'city', 'country'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('parameters of type', $result);
    }

    public function test_passes_with_dto(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function createUser(CreateUserDTO $userData)
    {
        return User::create($userData->toArray());
    }
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
