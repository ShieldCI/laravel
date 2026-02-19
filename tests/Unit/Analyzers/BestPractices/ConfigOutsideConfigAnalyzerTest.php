<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
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
    private $stripeKey = 'sk_live_51HqLyjWDarjtT1zdp7dc';
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
}
