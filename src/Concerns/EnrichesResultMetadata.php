<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Results\AnalysisResult;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

/**
 * Attaches an analyzer's own metadata to the result it produced.
 *
 * An analyzer knows its id, name, category and severity, but a result does not carry them,
 * and both the console and JSON reporters read them. Every run path therefore rebuilt the
 * result with that metadata attached, in five copies that had already drifted: one of them
 * omitted timeToFix, so a full non-streaming run never reported it.
 */
trait EnrichesResultMetadata
{
    protected function enrichResult(ResultInterface $result, AnalyzerMetadata $metadata): AnalysisResult
    {
        return new AnalysisResult(
            analyzerId: $result->getAnalyzerId(),
            status: $result->getStatus(),
            message: $result->getMessage(),
            issues: $result->getIssues(),
            executionTime: $result->getExecutionTime(),
            // Merged rather than replaced. AbstractAnalyzer::analyze() records the exception
            // class and stack trace here when an analyzer throws, and that is the only
            // account of why it could not run: an errored result carries no issues, so
            // nothing else survives to explain it. Replacing the array discarded it before
            // it reached the JSON report, the saved file or the platform. Analyzer keys go
            // first so the fields below stay authoritative.
            metadata: array_merge($result->getMetadata(), [
                'id' => $metadata->id,
                'name' => $metadata->name,
                'description' => $metadata->description,
                'category' => $metadata->category,
                'severity' => $metadata->severity,
                'docsUrl' => $metadata->getDocsUrl(),
                'timeToFix' => $metadata->timeToFix,
            ]),
        );
    }
}
