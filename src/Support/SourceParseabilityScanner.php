<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use PhpParser\Error;
use PhpParser\Parser;
use PhpParser\ParserFactory;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ShieldCI\Enums\ParseFailureCause;
use SplFileInfo;

/**
 * Enumerates the source the analyzer suite reads and reports every file it cannot parse.
 *
 * Every AST-based analyzer skips a file it cannot parse, and every one of them skips it
 * silently: the run then reports no issues for that file, which is indistinguishable from
 * having checked it and found nothing. This scanner is the only place that difference is
 * recorded, so a report can state which files were never examined.
 */
class SourceParseabilityScanner
{
    /**
     * Directories whose PHP files the suite reads.
     *
     * @var list<string>
     */
    private const SOURCE_DIRECTORIES = ['app', 'config', 'routes', 'database', 'bootstrap'];

    /**
     * Where the Blade templates that get compiled live.
     */
    private const VIEW_DIRECTORY = 'resources/views';

    private const BLADE_SUFFIX = '.blade.php';

    /**
     * Relative path prefixes holding generated code rather than application source.
     *
     * @var list<string>
     */
    private const SKIPPED_PREFIXES = ['bootstrap/cache/'];

    /**
     * Directory names that are never application source, wherever they appear.
     *
     * @var list<string>
     */
    private const SKIPPED_SEGMENTS = ['vendor', 'node_modules'];

    private readonly Parser $parser;

    /**
     * The parser is injectable so a caller can share one, and so tests can pin a parser
     * older than the runtime — the arrangement that produces an UnsupportedSyntax result.
     */
    public function __construct(?Parser $parser = null)
    {
        $this->parser = $parser ?? (new ParserFactory)->createForNewestSupportedVersion();
    }

    /**
     * Every file the suite will read that the pinned parser cannot parse.
     *
     * @return list<UnparseableFile>
     */
    public function scan(string $basePath): array
    {
        $failures = [];

        foreach ($this->filesToScan($basePath) as $relativePath) {
            $failure = $this->inspect($basePath, $relativePath);

            if ($failure !== null) {
                $failures[] = $failure;
            }
        }

        return $failures;
    }

    /**
     * Every file the suite will read, relative to the application root and sorted.
     *
     * @return list<string>
     */
    public function filesToScan(string $basePath): array
    {
        $basePath = $this->normaliseBasePath($basePath);
        $files = [];

        foreach (self::SOURCE_DIRECTORIES as $directory) {
            foreach ($this->filesIn($basePath, $directory, '.php') as $file) {
                $files[] = $file;
            }
        }

        foreach ($this->filesIn($basePath, self::VIEW_DIRECTORY, self::BLADE_SUFFIX) as $file) {
            $files[] = $file;
        }

        sort($files);

        return $files;
    }

    /**
     * Parse one file the way the suite would read it, and describe the failure if it fails.
     */
    private function inspect(string $basePath, string $relativePath): ?UnparseableFile
    {
        $absolutePath = $this->normaliseBasePath($basePath).DIRECTORY_SEPARATOR
            .str_replace('/', DIRECTORY_SEPARATOR, $relativePath);

        $source = @file_get_contents($absolutePath);

        if ($source === false) {
            // Reported rather than skipped: the suite was going to read this file, and
            // silence here would be the same silence the helper exists to remove.
            return new UnparseableFile(
                path: $relativePath,
                line: 1,
                parserMessage: 'File could not be read',
                cause: ParseFailureCause::Unreadable,
            );
        }

        $lineMap = null;

        if (str_ends_with($relativePath, self::BLADE_SUFFIX)) {
            $compiled = BladeCompilerFactory::compile($source);

            if ($compiled === null) {
                return new UnparseableFile(
                    path: $relativePath,
                    line: 1,
                    parserMessage: 'Blade template could not be compiled to PHP',
                    cause: ParseFailureCause::SyntaxError,
                );
            }

            $source = $compiled['compiledPhp'];
            $lineMap = $compiled['lineMap'];
        }

        try {
            $this->parser->parse($source);

            return null;
        } catch (Error $error) {
            $line = max(1, $error->getStartLine());

            return new UnparseableFile(
                path: $relativePath,
                // A Blade template's failure is reported against the Blade source the
                // author can act on, not the compiled PHP the parser actually read.
                line: $lineMap === null ? $line : ($lineMap[$line] ?? 1),
                parserMessage: $error->getRawMessage(),
                cause: $this->classify($source),
            );
        }
    }

    /**
     * Separate broken code from code the pinned parser has not caught up with.
     *
     * The running PHP is the second opinion. token_get_all() with TOKEN_PARSE runs the real
     * compiler front end and throws on invalid syntax, so code it accepts while the pinned
     * parser rejects it is, by elimination, valid syntax the parser does not implement —
     * which is what a PHP runtime newer than the pinned parser looks like.
     */
    private function classify(string $code): ParseFailureCause
    {
        try {
            // A non-empty token list means the runtime read the whole file; TOKEN_PARSE
            // makes it throw rather than warn on anything it cannot read.
            $acceptedByRuntime = token_get_all($code, TOKEN_PARSE) !== [];
        } catch (\CompileError) {
            $acceptedByRuntime = false;
        }

        return $acceptedByRuntime
            ? ParseFailureCause::UnsupportedSyntax
            : ParseFailureCause::SyntaxError;
    }

    /**
     * Relative paths of every file under $directory whose name ends in $suffix.
     *
     * @return list<string>
     */
    private function filesIn(string $basePath, string $directory, string $suffix): array
    {
        $absoluteDirectory = $basePath.DIRECTORY_SEPARATOR
            .str_replace('/', DIRECTORY_SEPARATOR, $directory);

        if (! is_dir($absoluteDirectory)) {
            return [];
        }

        $files = [];

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($absoluteDirectory, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );

        /** @var SplFileInfo $file */
        foreach ($iterator as $file) {
            if (! $file->isFile() || ! str_ends_with($file->getFilename(), $suffix)) {
                continue;
            }

            // The iterator is rooted at $absoluteDirectory, so every pathname it yields
            // starts with it: the remainder is the path below $directory.
            $relativePath = $directory.'/'.str_replace(
                '\\',
                '/',
                substr($file->getPathname(), strlen($absoluteDirectory) + 1)
            );

            if (! $this->isSkipped($relativePath)) {
                $files[] = $relativePath;
            }
        }

        return $files;
    }

    private function isSkipped(string $relativePath): bool
    {
        foreach (self::SKIPPED_PREFIXES as $prefix) {
            if (str_starts_with($relativePath, $prefix)) {
                return true;
            }
        }

        $segments = explode('/', $relativePath);
        array_pop($segments);

        foreach ($segments as $segment) {
            if (in_array($segment, self::SKIPPED_SEGMENTS, true)) {
                return true;
            }
        }

        return false;
    }

    private function normaliseBasePath(string $basePath): string
    {
        return rtrim($basePath, '/'.DIRECTORY_SEPARATOR);
    }
}
