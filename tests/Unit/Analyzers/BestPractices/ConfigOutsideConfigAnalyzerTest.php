<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\BestPractices\ConfigOutsideConfigAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class ConfigOutsideConfigAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        $configRepo = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => [
                        'config-outside-config' => $config,
                    ],
                ],
            ],
        ]);

        return new ConfigOutsideConfigAnalyzer($this->parser, $configRepo);
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

    public function test_detects_hardcoded_urls_with_env_markers(): void
    {
        // URL with environment marker in domain (dev.) - should be flagged in default mode
        $code = <<<'PHP'
<?php

namespace App\Services;

class WebhookService
{
    public function getUrl()
    {
        return 'https://dev.api.myapp.com/webhook';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/WebhookService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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
        // URL with non-standard port (environment marker) and API key
        $code = <<<'PHP'
<?php

namespace App\Services;

class PaymentService
{
    private $apiUrl = 'https://api.myapp.com:8080/charge';
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

    public function test_skips_tests_directory(): void
    {
        $code = <<<'PHP'
<?php

namespace Tests\Feature;

class ApiTest
{
    private $testUrl = 'http://localhost:8000/api';
    private $testKey = 'sk_test_4eC39HqLyjWDarjtT1zdp7dc1234567890abcdef';
}
PHP;

        $tempDir = $this->createTempDirectory(['tests/Feature/ApiTest.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_database_seeders_directory(): void
    {
        $code = <<<'PHP'
<?php

namespace Database\Seeders;

class UserSeeder
{
    private $webhookUrl = 'https://api.production.com/webhook';
}
PHP;

        $tempDir = $this->createTempDirectory(['database/seeders/UserSeeder.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_database_factories_directory(): void
    {
        $code = <<<'PHP'
<?php

namespace Database\Factories;

class UserFactory
{
    private $apiUrl = 'http://localhost:3000/api';
}
PHP;

        $tempDir = $this->createTempDirectory(['database/factories/UserFactory.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_cdn_urls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class AssetService
{
    private $cdnUrl = 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css';
    private $fontUrl = 'https://fonts.googleapis.com/css2?family=Roboto';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/AssetService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_schema_urls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class SchemaService
{
    private $jsonSchema = 'https://json-schema.org/draft/2020-12/schema';
    private $w3Namespace = 'https://www.w3.org/2001/XMLSchema';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/SchemaService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_snake_case_identifiers(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class MethodService
{
    private $method = 'handle_user_registration_with_email_verification_and_profile';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/MethodService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_screaming_snake_case_constants(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ConfigService
{
    private $constant = 'SOME_VERY_LONG_CONFIGURATION_CONSTANT_NAME_HERE';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ConfigService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_camel_case_identifiers(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class MethodService
{
    private $method = 'handleUserRegistrationWithEmailVerificationProcess';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/MethodService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_array_access_key_identifiers(): void
    {
        // Long descriptive camelCase key used as an array-access key is an identifier,
        // not a hardcoded secret. Reproduces the reported false positive.
        $code = <<<'PHP'
<?php

namespace App\Services;

class MetricsService
{
    public function value(array $metrics)
    {
        return $metrics['monthlyActiveUsersWith2FactorAuthByQACount'];
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/MetricsService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_compact_argument_identifiers(): void
    {
        // A long descriptive token passed to compact() is a variable name, not a secret.
        $code = <<<'PHP'
<?php

namespace App\Services;

class ReportService
{
    public function build()
    {
        $monthlyActiveUsersWith2FactorAuthByQACount = 0;

        return compact('monthlyActiveUsersWith2FactorAuthByQACount');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ReportService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_array_literal_key_identifiers(): void
    {
        // The key of an array literal is an identifier; only the value could be a secret.
        $code = <<<'PHP'
<?php

namespace App\Services;

class MetricsService
{
    public function defaults()
    {
        return [
            'monthlyActiveUsersWith2FactorAuthByQACount' => 0,
        ];
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/MetricsService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_detects_secret_as_array_value(): void
    {
        // Regression guard: a secret in the VALUE position of an array literal is still flagged,
        // even though the surrounding key is treated as an identifier.
        $code = <<<'PHP'
<?php

namespace App\Services;

class PaymentService
{
    public function config()
    {
        return [
            'api_key' => 'secret_aBcDeF0123456789aBcDeF0123456789xyz',
        ];
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/PaymentService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('API key', $result);
    }

    public function test_excludes_css_class_combinations(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class StyleService
{
    private $classes = 'container-fluid-responsive-layout-content-wrapper-main';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/StyleService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_detects_api_keys_with_prefixes(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PaymentService
{
    private $stripeKey = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc1234567890ABCDEFGH';
    private $testKey = 'test_key_abc123def456ghi789jkl012mno345pqr678';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/PaymentService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('API key', $result);
    }

    public function test_excludes_placeholder_image_urls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ImageService
{
    private $placeholder = 'https://via.placeholder.com/150';
    private $gravatar = 'https://gravatar.com/avatar/example';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ImageService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_sha512_hashes(): void
    {
        // SHA512 hash (128 hex characters)
        $code = <<<'PHP'
<?php

namespace App\Services;

class HashService
{
    private $hash = 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/HashService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_requires_mixed_letters_and_digits_for_api_key_detection(): void
    {
        // Pure letter string should not be flagged (even if >30 chars)
        $code = <<<'PHP'
<?php

namespace App\Services;

class TextService
{
    private $text = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/TextService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_custom_excluded_domains_are_respected(): void
    {
        // This URL would normally be flagged
        $code = <<<'PHP'
<?php

namespace App\Services;

class StripeService
{
    private $url = 'https://api.stripe.com/v1/charges';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/StripeService.php' => $code]);

        // Configure custom excluded domain
        $analyzer = $this->createAnalyzer([
            'excluded_domains' => ['stripe.com'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_custom_excluded_domains_merge_with_defaults(): void
    {
        // Test that default domains still work when custom ones are added
        $code = <<<'PHP'
<?php

namespace App\Services;

class MultiService
{
    // Default exclusion (laravel.com)
    private $docs = 'https://laravel.com/docs';
    // Custom exclusion
    private $api = 'https://api.custom-service.com/endpoint';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/MultiService.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'excluded_domains' => ['custom-service.com'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_non_excluded_domains_still_flagged_in_strict_mode(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    // Not in exclusions - flagged in strict mode even without env markers
    private $url = 'https://api.another-service.com/endpoint';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        // Enable strict mode to flag all non-excluded URLs
        $analyzer = $this->createAnalyzer([
            'excluded_domains' => ['stripe.com'],
            'strict_url_detection' => true,
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('URL', $result);
    }

    public function test_empty_custom_config_uses_defaults(): void
    {
        // Test that default excluded domains work with empty config
        $code = <<<'PHP'
<?php

namespace App\Services;

class DefaultsService
{
    private $docs = 'https://laravel.com/docs';
    private $github = 'https://github.com/laravel/laravel';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DefaultsService.php' => $code]);

        $analyzer = $this->createAnalyzer([]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // === Heuristics-based URL Detection Tests ===

    public function test_third_party_api_urls_not_flagged_in_default_mode(): void
    {
        // Third-party APIs without environment markers should NOT be flagged in default mode
        $code = <<<'PHP'
<?php

namespace App\Services;

class ThirdPartyService
{
    private $stripeUrl = 'https://api.stripe.com/v1/charges';
    private $slackUrl = 'https://slack.com/api/chat.postMessage';
    private $twilioUrl = 'https://api.twilio.com/2010-04-01/Accounts';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ThirdPartyService.php' => $code]);

        // Default mode (strict_url_detection = false)
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_urls_with_dev_domain_marker_are_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    private $url = 'https://dev.myapp.com/api/users';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('URL', $result);
    }

    public function test_urls_with_staging_domain_marker_are_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    private $url = 'https://api-staging.myapp.com/webhook';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('URL', $result);
    }

    public function test_urls_with_test_path_marker_are_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    private $url = 'https://api.myapp.com/test/v1/users';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('URL', $result);
    }

    public function test_urls_with_non_standard_port_are_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    private $url = 'https://api.myapp.com:8080/users';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('URL', $result);
    }

    public function test_urls_with_port_3000_are_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    private $url = 'https://myapi.com:3000/endpoint';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('URL', $result);
    }

    public function test_standard_port_443_not_flagged_without_env_markers(): void
    {
        // URL with explicit port 443 (standard HTTPS) should NOT be flagged
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    private $url = 'https://api.someservice.com:443/endpoint';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_strict_mode_flags_all_urls(): void
    {
        // In strict mode, even clean third-party URLs should be flagged
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    private $url = 'https://api.cleanservice.com/v1/endpoint';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'strict_url_detection' => true,
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('URL', $result);
    }

    public function test_strict_mode_still_excludes_configured_domains(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    private $url = 'https://api.stripe.com/v1/charges';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'strict_url_detection' => true,
            'excluded_domains' => ['stripe.com'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_urls_with_sandbox_path_marker_are_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PaymentService
{
    private $url = 'https://api.paypal.com/sandbox/v1/payments';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/PaymentService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('URL', $result);
    }

    public function test_urls_with_local_domain_marker_are_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    private $url = 'https://local.myapp.com/api';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('URL', $result);
    }

    public function test_marker_named_registrable_domains_are_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class LinkService
{
    private $articles = 'https://dev.to/someone/an-article';
    private $api = 'https://api.dev.to/articles';
    private $blog = 'https://my-dev.to/posts';
    private $tool = 'https://test.io/pricing';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/LinkService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_marker_in_middle_subdomain_label_is_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    private $url = 'https://api.dev.myapp.com/users';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_marker_before_two_label_domain_is_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    private $url = 'https://staging.myapp.co/webhook';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('URL', $result);
    }

    public function test_hyphen_suffixed_subdomain_marker_is_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    private $url = 'https://api-dev.myapp.com/users';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('URL', $result);
    }

    public function test_marker_prefixed_words_are_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    private $shop = 'https://devon.myapp.com/shop';
    private $ops = 'https://devops.myapp.com/runbooks';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_urls_on_reserved_dev_tlds_are_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    private $valet = 'http://myapp.test/api';
    private $loopback = 'http://app.localhost/api';
    private $mdns = 'http://printer.local/status';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(3, $result);
    }

    public function test_trailing_dot_hosts_are_read_like_their_dotless_form(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class LinkService
{
    private $articles = 'https://dev.to./someone/an-article';
    private $valet = 'http://myapp.test./api';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/LinkService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('myapp.test', $result);
    }

    public function test_public_dev_tld_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class LinkService
{
    private $url = 'https://web.dev/articles/vitals';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/LinkService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_snake_case_identifiers_with_key_like_prefixes(): void
    {
        // A cache key or message key that happens to start with api_, auth_, token_ or
        // test_ is still an identifier, not a secret.
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;

class ReportService
{
    public function flush(): void
    {
        Cache::forget('api_widget_totals_for_reporting_page');
        Cache::forget('token_rotation_queue_name_for_workers');
    }

    public function lockoutMessage(): string
    {
        return 'auth_lockout_after_repeated_failures_notice';
    }

    public function scenario(): string
    {
        return 'test_guest_can_request_a_new_invitation_link';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Services/ReportService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_detects_prefixed_keys_with_mixed_case_and_digits(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class BillingService
{
    private $first = 'sk_test_4eC39HqLyjWDarjtT1zdp7dc';
    private $second = 'pk_live_62Kd9xQWzyMNO481rstUVW735abc';
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Services/BillingService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(2, $result);
        $this->assertHasIssueContaining('API key', $result);
    }

    /**
     * @dataProvider prefixedKeyProvider
     */
    #[DataProvider('prefixedKeyProvider')]
    public function test_prefixed_snake_case_with_a_digit_heavy_segment_is_a_key(string $value): void
    {
        // Three or more digits in one segment reads as key material rather than a word,
        // so the prefix decides even when the whole string is lowercase snake_case.
        $code = <<<PHP
<?php

namespace App\\Services;

class KeyService
{
    private \$key = '{$value}';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/KeyService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('API key', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function prefixedKeyProvider(): array
    {
        return [
            'digit rule, digits spread across a segment' => ['test_key_abc123def456ghi789jkl012mno345pqr678'],
            'digit rule, two segments of lowercase hex' => ['api_f3a9e17c4b2d8e6a0c5f1b7d9e3a'],
            'digit rule, three segments of lowercase hex' => ['api_live_f3a9e17c4b2d8e6a0c5f1b7d'],
            'digit rule, digit-led segment' => ['api_live_4ec39hq8x2mzp7wq1rt5vk8n'],
            'not snake_case, mixed case' => ['sk_test_4eC39HqLyjWDarjtT1zdp7dc'],
            'digit rule, trailing underscore' => ['api_live_f3a9e17c4b2d8e6a0c5f1b7d_'],
            'digit rule, five-digit number segment' => ['api_response_cache_for_dashboard_58317'],
            'digit rule, exactly three digits in a mixed segment' => ['api_response_cache_for_dashboard_k3x7p1'],
        ];
    }

    /**
     * @dataProvider snakeCaseIdentifierProvider
     */
    #[DataProvider('snakeCaseIdentifierProvider')]
    public function test_snake_case_identifiers_with_few_digits_per_segment_are_not_keys(string $value): void
    {
        // A prefixed string reads as an identifier when its words hold few digits, including
        // a word that leads with one (2fa) and a two-word name. The digit rule applies to
        // prefixed strings only, so an unprefixed identifier with a digit-heavy segment
        // stays excused.
        $code = <<<PHP
<?php

namespace App\\Services;

class CacheService
{
    private \$name = '{$value}';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CacheService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function snakeCaseIdentifierProvider(): array
    {
        return [
            'prefixed, no digits' => ['api_response_cache_for_dashboard'],
            'prefixed, one digit in a segment' => ['api_v2_widget_cache_for_dashboard'],
            'unprefixed, digit-heavy segment' => ['report_q2024_summary_for_finance_team'],
            'prefixed, digit-led segment' => ['auth_2fa_challenge_required_for_session'],
            'prefixed, two-digit segment' => ['api_rate_limit_60_per_minute_cache_key'],
            'prefixed, trailing number segment' => ['token_refresh_queue_for_workers_10'],
            'prefixed, two segments' => ['secret_rotationschedulerforworkers'],
            'prefixed, two segments with test_' => ['test_userscanresetpasswordviaemailx'],
            'prefixed, trailing underscore of a concatenated key' => ['api_widget_totals_for_reporting_page_'],
            'prefixed, double underscore' => ['api__response_cache_for_dashboard'],
            'unprefixed, trailing underscore' => ['report_widget_totals_for_reporting_'],
            'prefixed, thousands of segments' => ['api'.str_repeat('_ab', 5000)],
            'prefixed, three-digit number segment' => ['api_response_cache_for_dashboard_123'],
            'prefixed, four-digit year segment' => ['api_invoice_widgets_cache_for_2023'],
            'unprefixed, year segment' => ['annual_invoice_totals_cache_for_2026'],
            'unprefixed, long number segment' => ['annual_invoice_totals_cache_for_58317'],
        ];
    }

    /**
     * @dataProvider excludedSegmentAboveBasePathProvider
     */
    #[DataProvider('excludedSegmentAboveBasePathProvider')]
    public function test_excluded_directory_names_above_the_base_path_do_not_skip_the_project(string $segment): void
    {
        // Only the path inside the project decides what is excluded, so a checkout that
        // sits under a directory named tests/ or config/ is still analyzed, while its own
        // tests/ and config/ are still skipped.
        $key = <<<'PHP'
<?php

namespace App\Http;

class Keys
{
    public const TOKEN = 'sk_test_4eC39HqLyjWDarjtT1zdp7dc';
}
PHP;

        $tempDir = $this->createTempDirectory([
            "workspace/{$segment}/acme/app/Http/Keys.php" => $key,
            "workspace/{$segment}/acme/tests/Feature/KeysTest.php" => $key,
            "workspace/{$segment}/acme/config/keys.php" => $key,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath("{$tempDir}/workspace/{$segment}/acme");
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $location = $result->getIssues()[0]->location;
        $this->assertNotNull($location);
        $this->assertStringEndsWith('app/Http/Keys.php', $location->file);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function excludedSegmentAboveBasePathProvider(): array
    {
        return [
            'tests' => ['tests'],
            'config' => ['config'],
            'vendor' => ['vendor'],
            'database/seeders' => ['database/seeders'],
            'mixed case' => ['Tests'],
        ];
    }

    /**
     * @dataProvider loopbackLookalikeHostProvider
     */
    #[DataProvider('loopbackLookalikeHostProvider')]
    public function test_hosts_that_only_start_with_a_loopback_name_are_graded_as_public(string $url): void
    {
        $tempDir = $this->createTempDirectory(['app/Services/CacheService.php' => $this->urlPropertyFixture($url)]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function loopbackLookalikeHostProvider(): array
    {
        return [
            'localhost-prefixed registrable domain' => ['https://localhost.run/docs'],
            'localhost-prefixed word' => ['https://localhostify.com/api/v1'],
            'loopback-prefixed octet' => ['https://127.0.0.10.acme.io/status'],
        ];
    }

    /**
     * @dataProvider loopbackUrlProvider
     */
    #[DataProvider('loopbackUrlProvider')]
    public function test_loopback_hosts_are_flagged_whatever_follows_the_host(string $url): void
    {
        $tempDir = $this->createTempDirectory(['app/Services/CacheService.php' => $this->urlPropertyFixture($url)]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('Hardcoded URL', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function loopbackUrlProvider(): array
    {
        return [
            'bare localhost' => ['http://localhost'],
            'localhost with port and path' => ['http://localhost:8000/api'],
            'localhost with path' => ['http://localhost/path'],
            'localhost with query' => ['http://localhost?x=1'],
            'localhost with fragment' => ['http://localhost#f'],
            'localhost with userinfo' => ['http://user:pass@localhost/api'],
            'localhost with trailing dot' => ['http://localhost./api'],
            'loopback ip with port' => ['http://127.0.0.1:8080'],
            'loopback ip with path' => ['http://127.0.0.1/api'],
            'loopback ip with trailing dot' => ['http://127.0.0.1./api'],
            'loopback ip with userinfo' => ['http://user@127.0.0.1/api'],
        ];
    }

    /**
     * @dataProvider privateIpLookalikeHostProvider
     */
    #[DataProvider('privateIpLookalikeHostProvider')]
    public function test_hosts_that_are_not_exactly_a_private_ip_are_graded_as_public(string $url): void
    {
        $tempDir = $this->createTempDirectory(['app/Services/CacheService.php' => $this->urlPropertyFixture($url)]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function privateIpLookalikeHostProvider(): array
    {
        return [
            'private-ip-prefixed hostname' => ['https://10.20.30.40.cdn.acme.io/assets'],
            'private ip as userinfo' => ['http://192.168.1.1@acme.io/'],
            'out-of-range octet' => ['http://10.0.0.1234/'],
            'below the 172.16/12 range' => ['http://172.15.0.1/'],
            'above the 172.16/12 range' => ['http://172.32.0.1/'],
        ];
    }

    /**
     * @dataProvider privateIpUrlProvider
     */
    #[DataProvider('privateIpUrlProvider')]
    public function test_private_ip_hosts_are_flagged_whatever_follows_the_host(string $url): void
    {
        $tempDir = $this->createTempDirectory(['app/Services/CacheService.php' => $this->urlPropertyFixture($url)]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('Hardcoded URL', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function privateIpUrlProvider(): array
    {
        return [
            '192.168/16 with path' => ['http://192.168.1.10/api'],
            '10/8 with port' => ['http://10.0.0.5:8080'],
            'bottom of 172.16/12' => ['http://172.16.0.1'],
            'top of 172.16/12' => ['http://172.31.255.255/x'],
            'trailing dot' => ['http://192.168.1.10./api'],
            'with userinfo' => ['http://user:pass@192.168.1.10/api'],
        ];
    }

    public function test_canonical_uuids_are_not_flagged_as_api_keys(): void
    {
        // A UUID is an identifier format, like a hash, wherever it appears
        $code = <<<'PHP'
<?php

namespace App\Support;

class Identifiers
{
    public const TENANT_NAMESPACE = '3f2c9a71-5b8e-4d06-a1c4-7e9b2d58f013';

    private $tenantId = '9d41e6b2-07ac-4f3e-b85d-2c6a1f7e904b';

    public function upper(): string
    {
        return 'C80B3E5A-41F7-4D29-9E06-B7A2D4C1F358';
    }

    public function lookup(): mixed
    {
        return $this->find('e57a0c93-6d2b-48f1-a3e9-0b4c7d26f851');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Support/Identifiers.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_uuid_lookalikes_and_prefixed_keys_are_still_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class BillingService
{
    private $misgrouped = '3f2c9a715b8e-4d06-a1c4-7e9b-2d58f013';
    private $notHex = 'q7x2k9m4-p3w8-z5n1-r6t0-y4v7b2c9d8e1';
    private $secret = 'sk_test_4eC39HqLyjWDarjtT1zdp7dc';
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Services/BillingService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(3, $result);
        $this->assertHasIssueContaining('API key', $result);
    }

    /**
     * @dataProvider caseStyleIdentifierProvider
     */
    #[DataProvider('caseStyleIdentifierProvider')]
    public function test_case_style_identifiers_are_not_keys_at_any_length(string $value): void
    {
        $tempDir = $this->createTempDirectory(['app/Services/CacheService.php' => $this->urlPropertyFixture($value)]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function caseStyleIdentifierProvider(): array
    {
        return [
            'snake_case' => ['report_q2_widget_totals_for_page_view'],
            'SCREAMING_SNAKE_CASE' => ['REPORT_Q2_WIDGET_TOTALS_FOR_PAGE_VIEW'],
            'camelCase' => ['reportQ2WidgetTotalsForDashboardPage'],
            'snake_case, thousands of segments' => ['summary'.str_repeat('_b2', 6000)],
            'SCREAMING_SNAKE_CASE, thousands of segments' => ['SUMMARY'.str_repeat('_B2', 6000)],
            'camelCase, thousands of humps' => ['summary'.str_repeat('B2', 6000)],
            'SCREAMING_SNAKE_CASE, year segment' => ['ANNUAL_INVOICE_TOTALS_CACHE_FOR_2026'],
            'kebab-case, year segment' => ['annual-billing-summary-2026-archive'],
            'kebab-case, version and year segments' => ['release-digest-for-v2-published-2027'],
            'kebab-case, short letter-led mixed segment' => ['export-h264-video-archive-for-2026'],
            'kebab-case, thousands of segments' => ['summary'.str_repeat('-b2', 6000)],
            'kebab-case, thousands of number segments' => ['archive'.str_repeat('-2026', 3000)],
            'snake_case, number first segment' => ['2026_annual_billing_summary_archive'],
            'snake_case, migration name' => ['2023_08_30_104512_create_invoice_archive_records_table'],
            'SCREAMING_SNAKE_CASE, number first segment' => ['2026_ANNUAL_BILLING_SUMMARY_ARCHIVE'],
            'kebab-case, number first segment' => ['2026-annual-billing-summary-archive'],
            'kebab-case, date-led slug' => ['2026-07-annual-billing-summary-archive'],
        ];
    }

    /**
     * @dataProvider caseStyleNearMissProvider
     */
    #[DataProvider('caseStyleNearMissProvider')]
    public function test_case_style_near_misses_are_still_keys(string $value): void
    {
        $tempDir = $this->createTempDirectory(['app/Services/CacheService.php' => $this->urlPropertyFixture($value)]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('API key', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function caseStyleNearMissProvider(): array
    {
        return [
            'snake, double underscore' => ['report__widget_totals_for_q2_page'],
            'snake, trailing underscore' => ['report_widget_totals_for_q2_reporting_'],
            'snake, leading underscore' => ['_report_widget_totals_for_q2_reporting'],
            'snake, digit-led segment' => ['report_2fa_challenge_for_session_page'],
            'snake, digit-led first segment' => ['2report_widget_totals_for_reporting_page'],
            'screaming, digit-led first segment' => ['2REPORT_WIDGET_TOTALS_FOR_REPORTING_PAGE'],
            'kebab, digit-led first segment' => ['2annual-billing-summary-q2-archive'],
            'snake, two segments' => ['reportwidget_totalsforq2reportingpage'],
            'screaming, double underscore' => ['REPORT__WIDGET_TOTALS_FOR_Q2_PAGE'],
            'screaming, trailing underscore' => ['REPORT_WIDGET_TOTALS_FOR_Q2_REPORTING_'],
            'screaming, digit-led segment' => ['REPORT_2FA_CHALLENGE_FOR_SESSION_PAGE'],
            'screaming, two segments' => ['REPORTWIDGET_TOTALSFORQ2REPORTINGPAGE'],
            'camel, consecutive capitals' => ['reportWidgetTotalsForQ2HTMLDashboardPage'],
            'camel, one hump' => ['reportwidgettotalsforq2reportingPage'],
            'camel, trailing capital' => ['reportWidgetTotalsForQ2DashboardPageX'],
            'camel, leading capital' => ['ReportWidgetTotalsForQ2DashboardPage'],
            'camel, digit-led' => ['2reportWidgetTotalsForDashboardPage'],
            'snake, thousands of segments then a digit-led tail' => ['summary'.str_repeat('_b2', 6000).'_7k3q9z'],
            'kebab, double dash' => ['annual--billing-summary-q2-archive'],
            'kebab, trailing dash' => ['annual-billing-summary-q2-archive-'],
            'kebab, leading dash' => ['-annual-billing-summary-q2-archive'],
            'kebab, digit-led segment' => ['annual-2fa-challenge-for-session-page'],
            'kebab, two segments' => ['annualbillingsummaryq2-archivefor2026'],
            'kebab, uppercase' => ['ANNUAL-BILLING-SUMMARY-Q2-ARCHIVE'],
            'kebab, mixed separators' => ['annual_billing-summary_q2-archive'],
            'kebab, mixed case random key' => ['a8Kd02-mXq7Lp3-Zr9Tn5V-b1Wc6Yh4'],
            'kebab, lowercase random key with digit-led segments' => ['x7k2-9fq3m-8zp1w-4tr6v-2nb5c-3hj8k'],
            'kebab, lowercase random key with long letter-led mixed segments' => ['k3j9x7q2-m8p4w1z6-r5t0y4v7-b2c9d8e1'],
            'kebab, one long letter-led mixed segment' => ['q7x2k9m4zz-plan-for-quarterly-reporting'],
            'kebab, thousands of segments then a digit-led tail' => ['summary'.str_repeat('-b2', 6000).'-7k3q9z'],
        ];
    }

    /**
     * @dataProvider newlineTerminatedLiteralProvider
     */
    #[DataProvider('newlineTerminatedLiteralProvider')]
    public function test_identifier_checks_ignore_one_trailing_newline(string $literal, bool $reported): void
    {
        // $literal is double-quoted PHP source, so \n is an escape in the analyzed string
        $code = <<<PHP
<?php

namespace App\\Services;

class CacheService
{
    private \$name = "{$literal}";
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Services/CacheService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        if ($reported) {
            $this->assertFailed($result);
            $this->assertIssueCount(1, $result);
            $this->assertHasIssueContaining('API key', $result);
        } else {
            $this->assertPassed($result);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function newlineTerminatedLiteralProvider(): array
    {
        return [
            'snake_case, one newline' => ['report_q2_widget_totals_for_page_view\n', false],
            'SCREAMING_SNAKE_CASE, one newline' => ['REPORT_Q2_WIDGET_TOTALS_FOR_PAGE_VIEW\n', false],
            'camelCase, one newline' => ['reportQ2WidgetTotalsForDashboardPage\n', false],
            'snake_case, two newlines' => ['report_q2_widget_totals_for_page_view\n\n', false],
            'SCREAMING_SNAKE_CASE, two newlines' => ['REPORT_Q2_WIDGET_TOTALS_FOR_PAGE_VIEW\n\n', false],
            'camelCase, two newlines' => ['reportQ2WidgetTotalsForDashboardPage\n\n', false],
            'snake near-miss, one newline' => ['report__widget_totals_for_q2_page\n', true],
            'SCREAMING near-miss, one newline' => ['REPORT_2FA_CHALLENGE_FOR_SESSION_PAGE\n', true],
            'camel near-miss, one newline' => ['reportWidgetTotalsForQ2HTMLDashboardPage\n', true],
            'prefixed lowercase words, one newline' => ['api_response_cache_for_dashboard\n', false],
            'prefixed digit-heavy, 29 characters with the newline, under the length gate' => ['api_key_7f3k9q2m8x4w1z6v5b0n\n', false],
            'prefixed digit-heavy, longer, one newline' => ['api_key_7f3k9q2m8x4w1z6v5b0n4r8t\n', true],
            'prefixed mixed case, one newline' => ['sk_test_4eC39HqLyjWDarjtT1zdp7dc\n', true],
            'SHA-256 digest, one newline' => [hash('sha256', 'invoice-archive').'\n', false],
            'SHA-384 digest, one newline' => [hash('sha384', 'invoice-archive').'\n', false],
            'hex of no digest length, one newline' => [substr(hash('sha256', 'invoice-archive'), 0, 60).'\n', true],
        ];
    }

    /**
     * @dataProvider hashDigestProvider
     */
    #[DataProvider('hashDigestProvider')]
    public function test_hash_digests_are_not_keys(string $value): void
    {
        $tempDir = $this->createTempDirectory(['app/Services/CacheService.php' => $this->urlPropertyFixture($value)]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function hashDigestProvider(): array
    {
        return [
            'SHA-224, 56 hex characters' => [hash('sha224', 'invoice-archive')],
            'SHA-384, 96 hex characters' => [hash('sha384', 'invoice-archive')],
            'Subresource Integrity, sha384' => ['sha384-'.self::sriSha384Digest()],
        ];
    }

    /**
     * @dataProvider digestLookalikeProvider
     */
    #[DataProvider('digestLookalikeProvider')]
    public function test_digest_lookalikes_are_still_keys(string $value): void
    {
        $tempDir = $this->createTempDirectory(['app/Services/CacheService.php' => $this->urlPropertyFixture($value)]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('API key', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function digestLookalikeProvider(): array
    {
        return [
            '57 hex characters' => [hash('sha224', 'invoice-archive').'e'],
            '95 hex characters' => [substr(hash('sha384', 'invoice-archive'), 0, 95)],
            'Subresource Integrity, sha384 one character short' => ['sha384-'.substr(self::sriSha384Digest(), 0, 63)],
            'Subresource Integrity, unknown algorithm' => ['sha999-'.self::sriSha384Digest()],
            'Subresource Integrity, sha256 without its padding' => ['sha256-'.substr(str_repeat('Xq73mB2nLk9pRw4TzV0cHs6Jd8Fy5G1a', 2), 0, 44)],
        ];
    }

    /**
     * A base64 sha384 digest with no + or /, so the whole integrity value passes the
     * analyzer's character gate. About one digest in eight qualifies; the loop finds one.
     */
    private static function sriSha384Digest(): string
    {
        for ($i = 0; ; $i++) {
            $digest = base64_encode(hash('sha384', "invoice-archive-{$i}", true));

            if (strpbrk($digest, '+/') === false) {
                return $digest;
            }
        }
    }

    public function test_null_excluded_domain_entry_does_not_error(): void
    {
        // An unset env() inside excluded_domains yields null; the string entries still apply
        $tempDir = $this->createTempDirectory(['app/Services/CacheService.php' => $this->urlPropertyFixture('http://192.168.1.11/x')]);

        $analyzer = $this->createAnalyzer(['excluded_domains' => [null, '192.168.1.11']]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_non_string_excluded_domain_entries_do_not_exclude_other_hosts(): void
    {
        $tempDir = $this->createTempDirectory(['app/Services/CacheService.php' => $this->urlPropertyFixture('http://192.168.1.11/x')]);

        $analyzer = $this->createAnalyzer(['excluded_domains' => [null, 42, ['192.168.1.11'], '192.168.1.10']]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('192.168.1.11', $result);
    }

    public function test_stringable_excluded_domain_entries_are_read(): void
    {
        $tempDir = $this->createTempDirectory(['app/Services/Probe.php' => $this->urlPropertyFixture('https://api.acme.io/x')]);

        $analyzer = $this->createAnalyzer([
            'strict_url_detection' => true,
            'excluded_domains' => [Str::of('acme.io')],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_excluded_domain_does_not_match_a_host_with_two_trailing_dots(): void
    {
        $tempDir = $this->createTempDirectory(['app/Services/Probe.php' => $this->urlPropertyFixture('http://192.168.1.10../api')]);

        $analyzer = $this->createAnalyzer(['excluded_domains' => ['192.168.1.10']]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('192.168.1.10..', $result);
    }

    /**
     * @dataProvider leadingDotExcludedDomainProvider
     */
    #[DataProvider('leadingDotExcludedDomainProvider')]
    public function test_leading_dot_excluded_domain_entries_cover_the_domain_and_its_subdomains(string $entry): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Probe
{
    private $covered = 'https://api.acme.io/x';
    private $collision = 'https://notacme.io/x';
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Services/Probe.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'strict_url_detection' => true,
            'excluded_domains' => [$entry],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('notacme.io', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function leadingDotExcludedDomainProvider(): array
    {
        return [
            'leading dot' => ['.acme.io'],
            'leading wildcard' => ['*.acme.io'],
        ];
    }

    public function test_excluded_domains_match_a_host_written_with_a_trailing_dot(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CacheService
{
    private $excluded = 'http://192.168.1.10./api';
    private $neighbour = 'http://192.168.1.11./api';
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Services/CacheService.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'excluded_domains' => ['192.168.1.10'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('192.168.1.11', $result);
    }

    public function test_strict_mode_excluded_domains_match_a_host_written_with_a_trailing_dot(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class LinkService
{
    private $configured = 'https://github.com./acme/widgets';
    private $configuredWithDot = 'https://api.acme.io/v1';
    private $builtIn = 'https://laravel.com./docs';
    private $other = 'https://gitlab.com./acme/widgets';
    private $collision = 'https://notgithub.com./acme/widgets';
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Services/LinkService.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'strict_url_detection' => true,
            'excluded_domains' => ['github.com', 'acme.io.'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(2, $result);
        $this->assertHasIssueContaining('gitlab.com.', $result);
        $this->assertHasIssueContaining('notgithub.com.', $result);
    }

    private function urlPropertyFixture(string $url): string
    {
        return <<<PHP
<?php

namespace App\\Services;

class CacheService
{
    private \$name = '{$url}';
}
PHP;
    }
}
