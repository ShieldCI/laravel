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
}
