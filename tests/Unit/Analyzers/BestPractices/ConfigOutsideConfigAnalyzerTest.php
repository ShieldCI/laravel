<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\ConfigOutsideConfigAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class ConfigOutsideConfigAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new ConfigOutsideConfigAnalyzer($this->parser);
    }

    public function test_passes_with_config_helper(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PaymentService
{
    public function getApiKey()
    {
        return config('services.stripe.key');
    }

    public function getTimeout()
    {
        return config('payment.timeout', 30);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/PaymentService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_hardcoded_api_keys(): void
    {
        // API key must be > 30 characters and only alphanumeric
        $code = <<<'PHP'
<?php

namespace App\Services;

class StripeService
{
    private $apiKey = 'sk1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

    public function charge()
    {
        // Use API key
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/StripeService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('API key', $result);
    }

    public function test_detects_hardcoded_urls(): void
    {
        // URL must not contain example.com, laravel.com, github.com, or stackoverflow.com
        $code = <<<'PHP'
<?php

namespace App\Services;

class WebhookService
{
    public function getUrl()
    {
        return 'https://api.production-server.com/webhook';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/WebhookService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('URL', $result);
    }

    public function test_skips_config_directory(): void
    {
        $code = <<<'PHP'
<?php

return [
    'stripe' => [
        'key' => 'sk_test_4eC39HqLyjWDarjtT1zdp7dc',
        'secret' => 'whsec_test_secret',
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/services.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_provides_config_recommendation(): void
    {
        // Use a long alphanumeric string > 30 characters
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    private $apiKey = 'sklive51HqLyjWDarjtT1zdp7dcABCDEFGHIJKLMNOPQRSTUVWXYZ123456';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('config', $issues[0]->recommendation);
    }

    public function test_ignores_files_with_parse_errors(): void
    {
        $code = '<?php this is invalid PHP code {{{';

        $tempDir = $this->createTempDirectory(['Invalid.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_md5_hash_is_not_flagged_as_api_key(): void
    {
        // MD5 hash (32 hex characters)
        $code = <<<'PHP'
<?php

namespace App\Services;

class CacheService
{
    private $cacheKey = '5d41402abc4b2a76b9719d911017c592';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CacheService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_sha1_hash_is_not_flagged_as_api_key(): void
    {
        // SHA1 hash (40 hex characters)
        $code = <<<'PHP'
<?php

namespace App\Services;

class HashService
{
    private $hash = '356a192b7913b04c54574d18c28d46e6395428ab';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/HashService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_sha256_hash_is_not_flagged_as_api_key(): void
    {
        // SHA256 hash (64 hex characters)
        $code = <<<'PHP'
<?php

namespace App\Services;

class SecurityService
{
    private $token = '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/SecurityService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_localhost_urls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    private $url = 'http://localhost:8000/api';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('localhost', $result);
    }

    public function test_detects_127_0_0_1_urls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    private $url = 'http://127.0.0.1:3000/webhook';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('URL', $result);
    }

    public function test_detects_private_ip_addresses(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class RedisService
{
    private $host = 'http://192.168.1.100:6379';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/RedisService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('URL', $result);
    }

    public function test_excludes_example_com_urls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DemoService
{
    private $url = 'https://api.example.com/webhook';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DemoService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_laravel_com_urls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DocsService
{
    private $docsUrl = 'https://laravel.com/docs/eloquent';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DocsService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_github_com_urls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class RepoService
{
    private $repoUrl = 'https://github.com/laravel/laravel';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/RepoService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_stackoverflow_urls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class HelpService
{
    private $helpUrl = 'https://stackoverflow.com/questions/tagged/laravel';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/HelpService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_multiple_issues_in_one_file(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PaymentService
{
    private $apiUrl = 'https://api.production.com/charge';
    private $apiKey = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc1234567890ABCDEFGH';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/PaymentService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
        $this->assertStringContainsString('URL', $issues[0]->message);
        $this->assertStringContainsString('API key', $issues[1]->message);
    }

    public function test_api_key_boundary_exactly_31_characters(): void
    {
        // Exactly 31 alphanumeric characters (just over 30 threshold)
        $code = <<<'PHP'
<?php

namespace App\Services;

class KeyService
{
    private $key = '1234567890abcdefghijklmnopqrstu';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/KeyService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('API key', $result);
    }

    public function test_api_key_boundary_exactly_30_characters(): void
    {
        // Exactly 30 alphanumeric characters (at threshold, should pass)
        $code = <<<'PHP'
<?php

namespace App\Services;

class KeyService
{
    private $key = '1234567890abcdefghijklmnopqrs';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/KeyService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_nested_config_directory(): void
    {
        $code = <<<'PHP'
<?php

return [
    'api_key' => 'sk_test_hardcoded_but_in_config_so_OK_1234567890abcdef',
    'url' => 'https://api.production.com',
];
PHP;

        $tempDir = $this->createTempDirectory(['config/services/stripe.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
