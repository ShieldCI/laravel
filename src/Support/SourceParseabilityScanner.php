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
 *
 * @internal No analyzer consumes this yet. It is published only so a consumer can be
 * built against it, and the failure channel may move to analyzers-core's AstParser,
 * which records what the suite actually parsed rather than predicting it. Do not
 * depend on it from outside this package.
 */
final class SourceParseabilityScanner
{
    private const BLADE_SUFFIX = '.blade.php';

    private const PHP_SUFFIX = '.php';

    private readonly Parser $parser;

    /**
     * The reading set comes in rather than being restated here.
     *
     * What the suite reads is paths.analyze filtered by excluded_paths, which the service
     * provider already resolves into a PathFilter and AnalyzerManager already pushes into
     * every file analyzer. A second copy of those two lists would make this class claim
     * files no analyzer was pointed at, and stay silent about paths an application added
     * -- which is the silence it exists to remove.
     *
     * The parser is injectable so a caller can share one, and so tests can pin a parser
     * older than the runtime, the arrangement that produces an UnsupportedSyntax result.
     */
    public function __construct(
        private readonly PathFilter $paths,
        ?Parser $parser = null,
    ) {
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

        foreach ($this->paths->getAnalyzePaths() as $path) {
            foreach ($this->filesIn($basePath, trim($path, '/')) as $file) {
                $files[] = $file;
            }
        }

        sort($files);

        // Configured paths may nest ('app' and 'app/Models'), which would otherwise
        // report the same file twice.
        return array_values(array_unique($files));
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
                // No PHP was produced, so nothing was parsed: this is not evidence that
                // the author's code is broken, the same reasoning as Unreadable.
                return new UnparseableFile(
                    path: $relativePath,
                    line: 1,
                    parserMessage: 'Blade template could not be compiled to PHP',
                    cause: ParseFailureCause::Uncompilable,
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
     * parser rejects it is, by elimination, valid syntax the parser does not implement,
     * which is what a PHP runtime newer than the pinned parser looks like.
     */
    private function classify(string $code): ParseFailureCause
    {
        try {
            // Only the throw matters here, not the tokens. The result is still compared
            // rather than discarded because PHPStan's function.resultUnused rejects a
            // bare call, and a suppression would be worse than a comparison.
            $acceptedByRuntime = token_get_all($code, TOKEN_PARSE) !== [];
        } catch (\CompileError) {
            $acceptedByRuntime = false;
        }

        return $acceptedByRuntime
            ? ParseFailureCause::UnsupportedSyntax
            : ParseFailureCause::SyntaxError;
    }

    /**
     * Relative paths of every PHP file the suite would read under $path.
     *
     * @return list<string>
     */
    private function filesIn(string $basePath, string $path): array
    {
        $absolutePath = $basePath.DIRECTORY_SEPARATOR
            .str_replace('/', DIRECTORY_SEPARATOR, $path);

        // A configured path may name one file rather than a directory, which is what
        // the suite's own walk does with it.
        if (is_file($absolutePath)) {
            return str_ends_with($path, self::PHP_SUFFIX) && $this->paths->shouldAnalyze($path)
                ? [$path]
                : [];
        }

        if (! is_dir($absolutePath)) {
            return [];
        }

        $files = [];

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($absolutePath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY,
            // Without this a directory the process cannot read throws out of the walk and
            // costs us every finding, including the ones already collected.
            RecursiveIteratorIterator::CATCH_GET_CHILD
        );

        /** @var SplFileInfo $file */
        foreach ($iterator as $file) {
            if (! $file->isFile() || ! str_ends_with($file->getFilename(), self::PHP_SUFFIX)) {
                continue;
            }

            $relativePath = $path.'/'.$this->subPathOf($file, $absolutePath);

            if ($this->paths->shouldAnalyze($relativePath)) {
                $files[] = $relativePath;
            }
        }

        return $files;
    }

    /**
     * The part of $file's pathname below $root, forward-slashed.
     *
     * Only a real separator is rewritten. A blanket backslash-to-slash replacement would
     * corrupt a filename that legally contains one on Linux, turning it into a path that
     * does not exist and then reporting that path as unreadable.
     */
    private function subPathOf(SplFileInfo $file, string $root): string
    {
        // The iterator is rooted at $root, so every pathname it yields starts with it.
        $subPath = substr($file->getPathname(), strlen($root) + 1);

        return DIRECTORY_SEPARATOR === '/'
            ? $subPath
            : str_replace(DIRECTORY_SEPARATOR, '/', $subPath);
    }

    private function normaliseBasePath(string $basePath): string
    {
        return rtrim($basePath, '/'.DIRECTORY_SEPARATOR);
    }
}
