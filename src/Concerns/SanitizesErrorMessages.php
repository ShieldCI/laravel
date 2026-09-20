<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use ShieldCI\AnalyzersCore\Support\MessageHelper;

/**
 * Bounds and redacts an error message on its way into a result, an issue or a report.
 *
 * AbstractAnalyzer::analyze() already does this for any Throwable that escapes runAnalysis().
 * An analyzer that catches its own failure and builds the result itself never reaches that
 * catch, so without this its message goes out unbounded and unredacted. This exists so the two
 * routes agree rather than differing by which catch happened to run.
 *
 * Apply it where a message is *emitted* - a result message, an issue message, a recommendation,
 * metadata - and never where one is *matched*. Several analyzers classify a failure by
 * lowercasing the message and looking for 'access denied' and similar; redaction rewrites the
 * substrings that matching depends on, so those call sites must keep reading the raw text.
 * DatabaseStatusAnalyzer does both: isTransientError() and buildRecommendation() match on the
 * raw message off the connection result, while only the copy put in the issue goes through here.
 *
 * Two call sites deliberately stay on MessageHelper's 200 default rather than moving to this:
 * CacheStatusAnalyzer and DatabaseStatusAnalyzer each embed the error inside a longer
 * recommendation sentence. There the error is a clause in someone else's prose and the whole
 * recommendation is what needs to stay readable - CacheStatusAnalyzerTest pins that at 500 for
 * the finished string. Here the message *is* the error, so it gets the fuller allowance. The
 * cap differs because the role differs, not because the sweep missed them.
 */
trait SanitizesErrorMessages
{
    /**
     * Takes a string rather than a Throwable because two callers never hold the exception:
     * DatabaseStatusAnalyzer reads a message off a connection-result object, and
     * AnalyzeCommand::notifyFailure() receives one as a parameter.
     */
    protected function sanitizedErrorMessage(string $message): string
    {
        // 500 rather than MessageHelper's 200 default, matching the cap AbstractAnalyzer uses so
        // that an analyzer failure reads the same either way. Core's own constant is private, so
        // the number cannot be imported - it lives here instead of in every call site. It is a
        // literal rather than a trait constant because those are PHP 8.2+ and this package
        // supports 8.1.
        return MessageHelper::sanitizeErrorMessage($message, 500);
    }
}
