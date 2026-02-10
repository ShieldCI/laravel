<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Support\ConfigSuggester;
use ShieldCI\Tests\TestCase;

class ConfigSuggesterTest extends TestCase
{
    #[Test]
    public function it_suggests_app_config_for_app_prefixed_vars(): void
    {
        $result = ConfigSuggester::suggest('APP_NAME');

        $this->assertEquals(['app', 'app.name'], $result);
    }

    #[Test]
    public function it_suggests_database_config_for_db_prefixed_vars(): void
    {
        $result = ConfigSuggester::suggest('DB_HOST');

        $this->assertEquals(['database', 'database.host'], $result);
    }

    #[Test]
    public function it_suggests_database_config_for_database_prefixed_vars(): void
    {
        $result = ConfigSuggester::suggest('DATABASE_CONNECTION');

        $this->assertEquals(['database', 'database.connection'], $result);
    }

    #[Test]
    public function it_suggests_cache_config_for_cache_prefixed_vars(): void
    {
        $result = ConfigSuggester::suggest('CACHE_DRIVER');

        $this->assertEquals(['cache', 'cache.driver'], $result);
    }

    #[Test]
    public function it_suggests_mail_config_for_mail_prefixed_vars(): void
    {
        $result = ConfigSuggester::suggest('MAIL_HOST');

        $this->assertEquals(['mail', 'mail.host'], $result);
    }

    #[Test]
    public function it_suggests_queue_config_for_queue_prefixed_vars(): void
    {
        $result = ConfigSuggester::suggest('QUEUE_CONNECTION');

        $this->assertEquals(['queue', 'queue.connection'], $result);
    }

    #[Test]
    public function it_suggests_session_config_for_session_prefixed_vars(): void
    {
        $result = ConfigSuggester::suggest('SESSION_DRIVER');

        $this->assertEquals(['session', 'session.driver'], $result);
    }

    #[Test]
    public function it_suggests_logging_config_for_log_prefixed_vars(): void
    {
        $result = ConfigSuggester::suggest('LOG_CHANNEL');

        $this->assertEquals(['logging', 'logging.channel'], $result);
    }

    #[Test]
    public function it_suggests_broadcasting_config_for_broadcast_prefixed_vars(): void
    {
        $result = ConfigSuggester::suggest('BROADCAST_DRIVER');

        $this->assertEquals(['broadcasting', 'broadcasting.driver'], $result);
    }

    #[Test]
    public function it_suggests_filesystems_config_for_filesystem_prefixed_vars(): void
    {
        $result = ConfigSuggester::suggest('FILESYSTEM_DISK');

        $this->assertEquals(['filesystems', 'filesystems.disk'], $result);
    }

    #[Test]
    public function it_suggests_filesystems_config_for_aws_prefixed_vars(): void
    {
        $result = ConfigSuggester::suggest('AWS_BUCKET');

        $this->assertEquals(['filesystems', 'filesystems.bucket'], $result);
    }

    #[Test]
    public function it_suggests_custom_config_for_unknown_vars(): void
    {
        $result = ConfigSuggester::suggest('MY_CUSTOM_VAR');

        $this->assertEquals(['custom', 'custom.my_custom_var'], $result);
    }

    #[Test]
    public function it_handles_case_insensitive_prefixes(): void
    {
        $result = ConfigSuggester::suggest('app_debug');

        $this->assertEquals(['app', 'app.debug'], $result);
    }

    #[Test]
    public function it_generates_recommendation_with_var_name(): void
    {
        $recommendation = ConfigSuggester::getRecommendation('APP_DEBUG');

        $this->assertStringContainsString('Do not call env() outside of configuration files', $recommendation);
        $this->assertStringContainsString('APP_DEBUG', $recommendation);
        $this->assertStringContainsString('config/app.php', $recommendation);
        $this->assertStringContainsString("config('app.debug')", $recommendation);
    }

    #[Test]
    public function it_generates_generic_recommendation_without_var_name(): void
    {
        $recommendation = ConfigSuggester::getRecommendation(null);

        $this->assertStringContainsString('Do not call env() outside of configuration files', $recommendation);
        $this->assertStringContainsString('Move this env() call to a configuration file', $recommendation);
    }

    #[Test]
    #[DataProvider('envVarProvider')]
    public function it_suggests_correct_config_for_various_env_vars(string $envVar, string $expectedFile, string $expectedKey): void
    {
        $result = ConfigSuggester::suggest($envVar);

        $this->assertEquals([$expectedFile, $expectedKey], $result);
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: string}>
     */
    public static function envVarProvider(): array
    {
        return [
            'app_env' => ['APP_ENV', 'app', 'app.env'],
            'app_url' => ['APP_URL', 'app', 'app.url'],
            'db_port' => ['DB_PORT', 'database', 'database.port'],
            'db_password' => ['DB_PASSWORD', 'database', 'database.password'],
            'cache_prefix' => ['CACHE_PREFIX', 'cache', 'cache.prefix'],
            'mail_from_address' => ['MAIL_FROM_ADDRESS', 'mail', 'mail.from_address'],
            'queue_failed_driver' => ['QUEUE_FAILED_DRIVER', 'queue', 'queue.failed_driver'],
            'session_lifetime' => ['SESSION_LIFETIME', 'session', 'session.lifetime'],
            'log_level' => ['LOG_LEVEL', 'logging', 'logging.level'],
            'broadcast_connection' => ['BROADCAST_CONNECTION', 'broadcasting', 'broadcasting.connection'],
            'filesystem_cloud' => ['FILESYSTEM_CLOUD', 'filesystems', 'filesystems.cloud'],
            'aws_access_key_id' => ['AWS_ACCESS_KEY_ID', 'filesystems', 'filesystems.access_key_id'],
            'custom_var' => ['REDIS_HOST', 'custom', 'custom.redis_host'],
        ];
    }
}
