<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\AppKeyAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class AppKeyAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new AppKeyAnalyzer;
    }

    public function test_passes_with_valid_app_key_in_env(): void
    {
        $envContent = <<<'ENV'
APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH=
APP_DEBUG=false
ENV;

        $configContent = <<<'PHP'
<?php

return [
    'name' => env('APP_NAME', 'Laravel'),
    'env' => env('APP_ENV', 'production'),
    'key' => env('APP_KEY'),
    'cipher' => 'AES-256-CBC',
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'config/app.php' => $configContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_app_key_is_empty(): void
    {
        $envContent = <<<'ENV'
APP_NAME=Laravel
APP_KEY=
APP_DEBUG=false
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('APP_KEY is not set or is empty', $result);
    }

    public function test_fails_when_app_key_is_placeholder(): void
    {
        $envContent = <<<'ENV'
APP_NAME=Laravel
APP_KEY=SomeRandomString
APP_DEBUG=false
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('placeholder/example value', $result);
    }

    public function test_fails_when_app_key_is_too_short(): void
    {
        $envContent = <<<'ENV'
APP_NAME=Laravel
APP_KEY=short
APP_DEBUG=false
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('does not follow the expected format or is too short', $result);
    }

    public function test_fails_when_app_key_is_missing_in_env(): void
    {
        $envContent = <<<'ENV'
APP_NAME=Laravel
APP_DEBUG=false
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('APP_KEY is not defined', $result);
    }

    public function test_fails_when_app_key_is_hardcoded_in_config(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH=
ENV;

        $configContent = <<<'PHP'
<?php

return [
    'key' => 'base64:hardcoded-key-12345678901234567890123456789012',
    'cipher' => 'AES-256-CBC',
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'config/app.php' => $configContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('hardcoded in config/app.php', $result);
    }

    public function test_fails_when_cipher_is_insecure(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH=
ENV;

        $configContent = <<<'PHP'
<?php

return [
    'key' => env('APP_KEY'),
    'cipher' => 'DES',
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'config/app.php' => $configContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Unsupported or weak cipher', $result);
    }

    public function test_passes_with_aes_128_cbc_cipher(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH=
ENV;

        $configContent = <<<'PHP'
<?php

return [
    'key' => env('APP_KEY'),
    'cipher' => 'AES-128-CBC',
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'config/app.php' => $configContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_missing_app_key_in_env_example(): void
    {
        $envExampleContent = <<<'ENV'
APP_NAME=Laravel
APP_DEBUG=false
ENV;

        $envContent = <<<'ENV'
APP_NAME=Laravel
APP_KEY=base64:abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH=
APP_DEBUG=false
ENV;

        $tempDir = $this->createTempDirectory([
            '.env.example' => $envExampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_no_env_or_config_exists(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
