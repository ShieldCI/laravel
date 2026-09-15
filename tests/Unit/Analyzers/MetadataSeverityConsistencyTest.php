<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\AstParser;

/**
 * An analyzer's metadata severity must equal the highest severity it can emit.
 *
 * That value is what the documentation tables, the category cards and the generated
 * catalog display, and no code reads it back, so an analyzer that gains a higher-severity
 * finding would otherwise keep advertising the old, lower one indefinitely (issue #336).
 *
 * The check is static: every severity reaches an Issue as a literal, so the ceiling can be
 * read off the source without instantiating analyzers, which would require their
 * constructor dependencies.
 */
class MetadataSeverityConsistencyTest extends TestCase
{
    /**
     * @test
     *
     * @dataProvider analyzerFileProvider
     */
    #[Test]
    #[DataProvider('analyzerFileProvider')]
    public function analyzer_metadata_severity_equals_its_highest_emitted_severity(string $file): void
    {
        $ast = (new AstParser)->parseFile($file);

        // parseFile() swallows parse errors and returns [], which would otherwise show up
        // here as a silent skip rather than a failure.
        $this->assertNotSame([], $ast, sprintf('%s could not be parsed.', self::relative($file)));

        $finder = new NodeFinder;
        $metadata = self::readMetadata($ast, $finder);

        $this->assertNotNull(
            $metadata['severity'],
            sprintf('%s has no severity in its metadata() method.', self::relative($file))
        );

        $id = $metadata['id'] ?? self::relative($file);

        $literals = self::severityLiterals($ast, $file, $finder, $metadata['excludedIds']);

        if ($literals === []) {
            // The analyzer passes $this->metadata()->severity to every issue, so it cannot
            // drift. Assert that rather than skipping blindly, otherwise an analyzer that
            // sourced its severities from somewhere unreadable would pass unnoticed.
            $this->assertTrue(
                self::derivesSeverityFromMetadata($ast, $finder),
                sprintf(
                    'Analyzer [%s] emits no Severity literal and never reads $this->metadata()->severity, '
                    .'so its highest emitted severity cannot be determined.',
                    $id
                )
            );

            $this->markTestSkipped(sprintf(
                'Analyzer [%s] derives every issue severity from metadata(), so it is consistent by construction.',
                $id
            ));
        }

        $highest = $literals[0];
        foreach ($literals as $literal) {
            if ($literal['severity']->level() > $highest['severity']->level()) {
                $highest = $literal;
            }
        }

        $this->assertSame(
            $highest['severity']->value,
            $metadata['severity']->value,
            sprintf(
                "Analyzer [%s] declares metadata severity '%s' but the highest severity it can emit is '%s', "
                ."at %s:%d.\nEither raise the metadata severity to Severity::%s, or lower that emission.",
                $id,
                $metadata['severity']->value,
                $highest['severity']->value,
                self::relative($highest['file']),
                $highest['line'],
                $highest['severity']->name
            )
        );
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function analyzerFileProvider(): array
    {
        $cases = [];

        foreach (self::analyzerFiles() as $file) {
            $cases[self::relative($file)] = [$file];
        }

        return $cases;
    }

    /**
     * The per-analyzer check above reads one file, which only works while severities are
     * assigned in the analyzer itself (or a visitor declared beside it). A shared trait
     * that assigned one would be invisible to it.
     *
     * @test
     */
    #[Test]
    public function no_shared_concern_assigns_a_severity(): void
    {
        $finder = new NodeFinder;

        $concerns = new \DirectoryIterator(self::packageRoot().'/src/Concerns');

        foreach ($concerns as $fileInfo) {
            if ($fileInfo->getExtension() !== 'php') {
                continue;
            }

            $path = $fileInfo->getPathname();
            $literals = self::severityLiterals((new AstParser)->parseFile($path), $path, $finder, []);

            $this->assertSame(
                [],
                $literals,
                sprintf(
                    '%s assigns a Severity, so an analyzer using it can emit a severity that '
                    .'%s cannot see. Extend that check to follow trait imports.',
                    self::relative($path),
                    self::class
                )
            );
        }
    }

    /**
     * @return list<string>
     */
    private static function analyzerFiles(): array
    {
        /** @var iterable<string, \SplFileInfo> $iterator */
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator(self::packageRoot().'/src/Analyzers', \FilesystemIterator::SKIP_DOTS)
        );

        $files = [];
        foreach ($iterator as $fileInfo) {
            if ($fileInfo->getExtension() === 'php') {
                $files[] = $fileInfo->getPathname();
            }
        }

        sort($files);

        return $files;
    }

    /**
     * Read the analyzer's declared id and severity, and the ids of every Severity node
     * inside metadata() so they are not mistaken for emissions.
     *
     * @param  array<Node>  $ast
     * @return array{id: string|null, severity: Severity|null, excludedIds: array<int, true>}
     */
    private static function readMetadata(array $ast, NodeFinder $finder): array
    {
        $id = null;
        $severity = null;
        $excludedIds = [];

        foreach ($finder->findInstanceOf($ast, Node\Stmt\ClassMethod::class) as $method) {
            if ($method->name->toString() !== 'metadata') {
                continue;
            }

            foreach ($finder->findInstanceOf([$method], Node\Expr\ClassConstFetch::class) as $node) {
                $excludedIds[spl_object_id($node)] = true;
            }

            foreach ($finder->findInstanceOf([$method], Node\Expr\New_::class) as $new) {
                if (! $new->class instanceof Node\Name || $new->class->getLast() !== 'AnalyzerMetadata') {
                    continue;
                }

                foreach ($new->args as $arg) {
                    // Guarded positively: php-parser 5.9 can place an ArgPlaceholder here,
                    // which has no ->value (see PR #338).
                    if (! $arg instanceof Node\Arg || $arg->name === null) {
                        continue;
                    }

                    if ($arg->name->toString() === 'id' && $arg->value instanceof Node\Scalar\String_) {
                        $id = $arg->value->value;
                    }

                    if ($arg->name->toString() === 'severity') {
                        $severity = self::severityOf($arg->value);
                    }
                }
            }
        }

        return ['id' => $id, 'severity' => $severity, 'excludedIds' => $excludedIds];
    }

    /**
     * Every Severity literal that can reach an Issue, i.e. excluding metadata() and any
     * literal used to derive a scalar (Severity::High->level()) or as a comparison operand.
     *
     * @param  array<Node>  $ast
     * @param  array<int, true>  $excludedIds
     * @return list<array{severity: Severity, file: string, line: int}>
     */
    private static function severityLiterals(array $ast, string $file, NodeFinder $finder, array $excludedIds): array
    {
        $excluded = $excludedIds;

        foreach ($finder->findInstanceOf($ast, Node\Expr\MethodCall::class) as $call) {
            $excluded[spl_object_id($call->var)] = true;
        }

        foreach ($finder->findInstanceOf($ast, Node\Expr\NullsafeMethodCall::class) as $call) {
            $excluded[spl_object_id($call->var)] = true;
        }

        foreach ($finder->findInstanceOf($ast, Node\Expr\PropertyFetch::class) as $fetch) {
            $excluded[spl_object_id($fetch->var)] = true;
        }

        $comparisons = [
            Node\Expr\BinaryOp\Identical::class,
            Node\Expr\BinaryOp\NotIdentical::class,
            Node\Expr\BinaryOp\Equal::class,
            Node\Expr\BinaryOp\NotEqual::class,
        ];

        foreach ($comparisons as $comparison) {
            foreach ($finder->findInstanceOf($ast, $comparison) as $operation) {
                $excluded[spl_object_id($operation->left)] = true;
                $excluded[spl_object_id($operation->right)] = true;
            }
        }

        $literals = [];

        foreach ($finder->findInstanceOf($ast, Node\Expr\ClassConstFetch::class) as $node) {
            if (isset($excluded[spl_object_id($node)])) {
                continue;
            }

            $severity = self::severityOf($node);

            if ($severity !== null) {
                $literals[] = ['severity' => $severity, 'file' => $file, 'line' => $node->getStartLine()];
            }
        }

        return $literals;
    }

    /**
     * @param  array<Node>  $ast
     */
    private static function derivesSeverityFromMetadata(array $ast, NodeFinder $finder): bool
    {
        foreach ($finder->findInstanceOf($ast, Node\Expr\PropertyFetch::class) as $fetch) {
            if (! $fetch->name instanceof Node\Identifier || $fetch->name->toString() !== 'severity') {
                continue;
            }

            $call = $fetch->var;

            if ($call instanceof Node\Expr\MethodCall
                && $call->name instanceof Node\Identifier
                && $call->name->toString() === 'metadata') {
                return true;
            }
        }

        return false;
    }

    private static function severityOf(Node $node): ?Severity
    {
        if (! $node instanceof Node\Expr\ClassConstFetch) {
            return null;
        }

        if (! $node->class instanceof Node\Name || $node->class->getLast() !== 'Severity') {
            return null;
        }

        if (! $node->name instanceof Node\Identifier) {
            return null;
        }

        foreach (Severity::cases() as $case) {
            if ($case->name === $node->name->toString()) {
                return $case;
            }
        }

        return null;
    }

    private static function packageRoot(): string
    {
        return dirname(__DIR__, 3);
    }

    private static function relative(string $path): string
    {
        return str_replace(self::packageRoot().'/', '', $path);
    }
}
