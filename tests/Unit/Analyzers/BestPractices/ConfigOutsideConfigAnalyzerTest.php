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
}
