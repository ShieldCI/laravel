<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use ShieldCI\Support\MessageHelper;

class MessageHelperTest extends TestCase
{
    public function test_sanitize_error_message_returns_short_message_unchanged(): void
    {
        $message = 'This is a short error message';
        $result = MessageHelper::sanitizeErrorMessage($message);

        $this->assertSame($message, $result);
    }

    public function test_sanitize_error_message_truncates_long_message(): void
    {
        $longMessage = str_repeat('a', 250);
        $result = MessageHelper::sanitizeErrorMessage($longMessage);

        $this->assertSame(200, strlen($result) - 3); // -3 for the '...'
        $this->assertStringEndsWith('...', $result);
        $this->assertStringStartsWith(str_repeat('a', 100), $result);
    }

    public function test_sanitize_error_message_respects_custom_max_length(): void
    {
        $message = str_repeat('b', 150);
        $result = MessageHelper::sanitizeErrorMessage($message, 100);

        $this->assertSame(103, strlen($result)); // 100 + 3 for '...'
        $this->assertStringEndsWith('...', $result);
        $this->assertStringStartsWith(str_repeat('b', 50), $result);
    }

    public function test_sanitize_error_message_handles_exact_max_length(): void
    {
        $message = str_repeat('c', 200);
        $result = MessageHelper::sanitizeErrorMessage($message);

        $this->assertSame($message, $result);
        $this->assertStringEndsNotWith('...', $result);
    }

    public function test_sanitize_error_message_handles_empty_string(): void
    {
        $result = MessageHelper::sanitizeErrorMessage('');

        $this->assertSame('', $result);
    }

    public function test_sanitize_error_message_handles_special_characters(): void
    {
        $message = 'Error: Connection failed! @#$%^&*()';
        $result = MessageHelper::sanitizeErrorMessage($message);

        $this->assertSame($message, $result);
    }

    public function test_sanitize_error_message_truncates_at_boundary(): void
    {
        $message = str_repeat('x', 201);
        $result = MessageHelper::sanitizeErrorMessage($message);

        $this->assertSame(203, strlen($result));
        $this->assertSame(str_repeat('x', 200).'...', $result);
    }

    public function test_sanitize_error_message_redacts_redis_connection_string(): void
    {
        $message = 'Connection failed: redis://myuser:mypassword@localhost:6379';
        $result = MessageHelper::sanitizeErrorMessage($message);

        $this->assertStringContainsString('redis://***:***@localhost:6379', $result);
        $this->assertStringNotContainsString('myuser', $result);
        $this->assertStringNotContainsString('mypassword', $result);
    }

    public function test_sanitize_error_message_redacts_mysql_connection_string(): void
    {
        $message = 'SQLSTATE[HY000]: mysql://root:secret123@localhost/mydb';
        $result = MessageHelper::sanitizeErrorMessage($message);

        $this->assertStringContainsString('mysql://***:***@localhost/mydb', $result);
        $this->assertStringNotContainsString('root', $result);
        $this->assertStringNotContainsString('secret123', $result);
    }

    public function test_sanitize_error_message_redacts_password_parameters(): void
    {
        $cases = [
            'password=secret123' => 'password=***',
            'pwd=mypassword' => 'pwd=***',
            'pass=12345' => 'pass=***',
            'passwd=admin123' => 'passwd=***',
            'PASSWORD=CAPS' => 'PASSWORD=***',
        ];

        foreach ($cases as $input => $expected) {
            $result = MessageHelper::sanitizeErrorMessage("Error: $input");
            $this->assertStringContainsString($expected, $result);
            $this->assertStringNotContainsString(explode('=', $input)[1], $result);
        }
    }

    public function test_sanitize_error_message_redacts_api_keys(): void
    {
        $cases = [
            'api_key=sk_live_abc123xyz' => 'api_key=***',
            'apikey=1234567890' => 'apikey=***',
            'token=bearer_abc123' => 'token=***',
            'auth_token=xyz789' => 'auth_token=***',
            'bearer abc123xyz' => 'bearer ***',
        ];

        foreach ($cases as $input => $expected) {
            $result = MessageHelper::sanitizeErrorMessage("Auth failed: $input");
            $this->assertStringContainsString($expected, $result);
        }
    }

    public function test_sanitize_error_message_redacts_private_keys_and_secrets(): void
    {
        $cases = [
            'private_key=-----BEGIN' => 'private_key=***',
            'secret=supersecret123' => 'secret=***',
            'client_secret=oauth_secret' => 'client_secret=***',
        ];

        foreach ($cases as $input => $expected) {
            $result = MessageHelper::sanitizeErrorMessage("Error: $input");
            $this->assertStringContainsString($expected, $result);
        }
    }

    public function test_sanitize_error_message_redacts_aws_access_keys(): void
    {
        $message = 'AWS Error with key AKIAIOSFODNN7EXAMPLE';
        $result = MessageHelper::sanitizeErrorMessage($message);

        $this->assertStringContainsString('AKIA***', $result);
        $this->assertStringNotContainsString('AKIAIOSFODNN7EXAMPLE', $result);
    }

    public function test_sanitize_error_message_redacts_internal_ip_addresses(): void
    {
        $cases = [
            'Connection to 10.0.0.5 failed' => '***.*.*.*',
            'Server at 192.168.1.100 unreachable' => '***.*.*.*',
            'Host 172.16.0.1 timeout' => '***.*.*.*',
            'Network 172.31.255.255 error' => '***.*.*.*',
        ];

        foreach ($cases as $input => $expected) {
            $result = MessageHelper::sanitizeErrorMessage($input);
            $this->assertStringContainsString($expected, $result);
        }
    }

    public function test_sanitize_error_message_preserves_public_ips(): void
    {
        $message = 'Connection to 8.8.8.8 failed';
        $result = MessageHelper::sanitizeErrorMessage($message);

        // Public IPs should be preserved (not in private ranges)
        $this->assertStringContainsString('8.8.8.8', $result);
    }

    public function test_sanitize_error_message_handles_multiple_sensitive_patterns(): void
    {
        $message = 'Failed to connect redis://admin:pass123@10.0.0.5:6379 with token=secret_abc';
        $result = MessageHelper::sanitizeErrorMessage($message);

        $this->assertStringContainsString('redis://***:***@', $result);
        $this->assertStringContainsString('***.*.*.*', $result);
        $this->assertStringContainsString('token=***', $result);
        $this->assertStringNotContainsString('admin', $result);
        $this->assertStringNotContainsString('pass123', $result);
        $this->assertStringNotContainsString('10.0.0.5', $result);
        $this->assertStringNotContainsString('secret_abc', $result);
    }

    public function test_sanitize_error_message_redacts_then_truncates(): void
    {
        $longMessage = 'Error with redis://user:password@localhost '.str_repeat('x', 200);
        $result = MessageHelper::sanitizeErrorMessage($longMessage);

        // Should redact sensitive info first, then truncate
        $this->assertStringContainsString('redis://***:***@localhost', $result);
        $this->assertStringNotContainsString('password', $result);
        $this->assertStringEndsWith('...', $result);
        $this->assertLessThanOrEqual(203, strlen($result)); // 200 + '...'
    }
}
